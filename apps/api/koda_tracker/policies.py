from __future__ import annotations

import copy
import re
from collections import Counter
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .cel_executor import CelPolicyError, execute_cel, validate_expression
from .models import AnalysisRevision, JobState, SbomPolicyRevision, SbomRun
from .oracle_evidence import oracle_listener_identity
from .sbom import iter_components
from .vulnerability import cvss_score, project_cve_findings
from .vulnerability_intelligence import enrich_findings, enqueue_findings
from .offline_intelligence_store import active_reference_document
from .project_catalog import catalog_context_for_run, project_scope_matches
from .legacy_policy import validate_legacy_conditions, prepare_legacy_contexts, validate_java_conditions


class ProjectScope(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    sourceId: str = Field(min_length=1, max_length=128)
    projectIds: list[str] = Field(default_factory=list, max_length=10000)
    tags: list[str] = Field(default_factory=list, max_length=100)
    includeChildren: bool = False
    onlyLatest: bool = False

    @field_validator("projectIds", "tags")
    @classmethod
    def validate_values(cls, values):
        if any(not isinstance(value, str) or not value.strip() or len(value) > 255 for value in values):
            raise ValueError("프로젝트 범위 식별자·태그는 1~255자여야 합니다")
        return sorted(set(value.strip() for value in values))


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    name: str = Field(min_length=1, max_length=255)
    kind: Literal["severity", "kev", "license_denied", "license_unknown", "component_denied", "cel"]
    enabled: bool = True
    action: Literal["fail", "warn", "info"] = "fail"
    values: list[str] = Field(default_factory=list, max_length=200)

    expression: str = Field(default="", max_length=8192)
    target: Literal["component", "vulnerability", "project"] = "vulnerability"
    serviceIds: list[str] = Field(default_factory=list, max_length=200)
    environmentIds: list[str] = Field(default_factory=list, max_length=200)
    releaseVersions: list[str] = Field(default_factory=list, max_length=200)
    runIds: list[str] = Field(default_factory=list, max_length=10000)
    projectScope: ProjectScope | None = None
    legacyConditions: list[dict] = Field(default_factory=list, max_length=100)

    @field_validator("legacyConditions")
    @classmethod
    def validate_conditions(cls, values):
        return validate_legacy_conditions(values)

    @field_validator("serviceIds", "environmentIds", "releaseVersions", "runIds")
    @classmethod
    def validate_scope(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value or len(value) > 255 for value in cleaned) or len(set(cleaned)) != len(cleaned):
            raise ValueError("정책 적용 범위는 중복 없이 1~255자 값을 지정해야 합니다")
        return cleaned

    @field_validator("values")
    @classmethod
    def validate_values(cls, values: list[str]) -> list[str]:
        cleaned = [value.strip() for value in values]
        if any(not value or len(value) > 2048 for value in cleaned):
            raise ValueError("정책 값은 1~2048자여야 합니다")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("정책 값이 중복되었습니다")
        return cleaned

    @model_validator(mode="after")
    def validate_kind(self) -> PolicyRule:
        if self.legacyConditions and (self.kind != "cel" or self.target != "component"):
            raise ValueError("이관 조건은 구성요소 대상 CEL 정책에만 지정할 수 있습니다")
        if self.kind == "cel":
            if not self.expression or len(self.expression.encode()) > 8192 or self.values:
                raise ValueError("CEL 정책에는 1~8192바이트 표현식이 필요하며 values는 지정하지 않습니다")
        elif self.expression:
            raise ValueError("CEL 유형에만 expression을 지정할 수 있습니다")
        if self.kind in {"severity", "license_denied", "component_denied"} and not self.values:
            raise ValueError("이 정책 유형에는 조건 값이 필요합니다")
        if self.kind == "severity":
            self.values = [value.lower() for value in self.values]
            if any(value not in {"critical", "high", "medium", "low", "info", "unknown"} for value in self.values):
                raise ValueError("알 수 없는 취약점 심각도입니다")
            if len(set(self.values)) != len(self.values):
                raise ValueError("정책 값이 중복되었습니다")
        elif self.kind in {"kev", "license_unknown"} and self.values:
            raise ValueError("이 정책 유형에는 조건 값을 지정하지 않습니다")
        elif self.kind == "license_denied":
            if any(not _LICENSE_ATOM.fullmatch(value) or value.upper() in {"AND", "OR", "WITH"} for value in self.values):
                raise ValueError("금지 라이선스에는 개별 식별자를 지정해야 합니다")
        return self


class PolicyException(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    ruleId: str = Field(min_length=1, max_length=128)
    component: str = Field(min_length=1, max_length=2048)
    runId: str | None = Field(default=None, max_length=36)
    vulnerabilityId: str | None = Field(default=None, max_length=255)
    reason: str = Field(min_length=1, max_length=2000)
    expiresAt: datetime | None = None

    @field_validator("expiresAt")
    @classmethod
    def timezone_required(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("예외 만료일에는 시간대가 필요합니다")
        return value.astimezone(UTC)

    @field_validator("vulnerabilityId")
    @classmethod
    def vulnerability_id(cls, value: str | None) -> str | None:
        if value is not None and not value:
            raise ValueError("취약점 식별자는 비워둘 수 없습니다")
        return value.upper() if value else None


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[PolicyRule] = Field(default_factory=list, max_length=200)
    exceptions: list[PolicyException] = Field(default_factory=list, max_length=200)

    @model_validator(mode="after")
    def unique_and_referenced(self) -> PolicyDocument:
        ids = [rule.id for rule in self.rules]
        if len(set(ids)) != len(ids):
            raise ValueError("정책 ID가 중복되었습니다")
        exception_ids = [exception.id for exception in self.exceptions]
        if len(set(exception_ids)) != len(exception_ids):
            raise ValueError("예외 ID가 중복되었습니다")
        if any(exception.ruleId not in ids for exception in self.exceptions):
            raise ValueError("예외가 존재하지 않는 정책을 참조합니다")
        return self


DEFAULT_DOCUMENT = {
    "rules": [
        {"id": "severity-high", "name": "High 이상 취약점", "kind": "severity", "enabled": True, "action": "fail", "values": ["critical", "high"]},
        {"id": "kev", "name": "알려진 악용 취약점(KEV)", "kind": "kev", "enabled": True, "action": "fail", "values": []},
        {"id": "license-unknown", "name": "라이선스 확인 필요", "kind": "license_unknown", "enabled": True, "action": "warn", "values": []},
    ],
    "exceptions": [],
}

MAX_POLICY_RESULTS = 100_000


def get_policy_document(db: Session) -> SbomPolicyRevision:
    current = db.scalar(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).limit(1))
    if current:
        return current
    initial = SbomPolicyRevision(version=1, document=copy.deepcopy(DEFAULT_DOCUMENT), created_by="system")
    # API and worker startup can race while seeding a fresh database.
    try:
        with db.begin_nested():
            db.add(initial)
            db.flush()
    except IntegrityError:
        current = db.scalar(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).limit(1))
        if current is None:
            raise
        return current
    return initial


_LICENSE_ATOM = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:-]*")
_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9][A-Za-z0-9.+:-]*)")
_UNKNOWN_LICENSES = {"unknown", "noassertion", "none", "unlicensed", "unspecified"}


def _license_expression(expression: str, denied: set[str]) -> tuple[bool, bool]:
    """Return (every legal choice denied, requires review).

    OR permits choosing a safe alternative; AND requires both terms. WITH is
    never treated as a blanket waiver: an exact base denial still applies and
    an unknown exception requires review. This is a screening rule, not a legal
    compatibility decision. A bounded parser avoids executing policy strings.
    """
    if not expression or len(expression) > 4096:
        return False, True
    tokens = []
    offset = 0
    while offset < len(expression):
        match = _TOKEN.match(expression, offset)
        if not match:
            if not expression[offset:].strip():
                break
            return False, True
        tokens.append(match.group(1))
        offset = match.end()
        if len(tokens) > 256:
            return False, True
    position = 0

    def atom(depth: int) -> tuple[bool, bool]:
        nonlocal position
        if depth > 32 or position >= len(tokens):
            raise ValueError("invalid license expression")
        token = tokens[position]
        position += 1
        if token == "(":
            value = disjunction(depth + 1)
            if position >= len(tokens) or tokens[position] != ")":
                raise ValueError("unclosed license expression")
            position += 1
            return value
        if token in {"AND", "OR", "WITH", ")"}:
            raise ValueError("invalid license atom")
        lowered = token.lower()
        result = (lowered in denied, lowered in _UNKNOWN_LICENSES or lowered.startswith("licenseref-") or lowered.startswith("documentref-"))
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            if position >= len(tokens) or tokens[position] in {"AND", "OR", "WITH", "(", ")"}:
                raise ValueError("invalid license exception")
            position += 1
            result = (result[0], True)
        return result

    def conjunction(depth: int) -> tuple[bool, bool]:
        nonlocal position
        blocked, unknown = atom(depth)
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right_blocked, right_unknown = atom(depth)
            blocked, unknown = blocked or right_blocked, unknown or right_unknown
        return blocked, unknown

    def disjunction(depth: int) -> tuple[bool, bool]:
        nonlocal position
        blocked, unknown = conjunction(depth)
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            right_blocked, right_unknown = conjunction(depth)
            blocked, unknown = blocked and right_blocked, unknown or right_unknown
        return blocked, unknown

    try:
        result = disjunction(0)
        return result if position == len(tokens) else (False, True)
    except ValueError:
        return False, True


def _licenses(component: dict, denied: set[str]) -> tuple[bool, bool]:
    # IDs are treated as declared identifiers. This bounded evaluator does not
    # ship the SPDX registry or certify the validity/compatibility of licenses.
    # License names, LicenseRefs, missing IDs, and unsupported expressions are
    # explicitly sent for review instead of guessed from free text.
    licenses = component.get("licenses") or []
    if not isinstance(licenses, list) or not licenses:
        return False, True
    results = []
    for license_value in licenses:
        if isinstance(license_value, str):
            results.append(_license_expression(license_value, denied))
        elif isinstance(license_value, dict) and isinstance(license_value.get("expression"), str):
            results.append(_license_expression(license_value["expression"], denied))
        elif isinstance(license_value, dict) and isinstance(license_value.get("license"), dict):
            identifier = license_value["license"].get("id")
            results.append(_license_expression(identifier, denied) if isinstance(identifier, str) else (False, True))
        else:
            results.append((False, True))
    # Separate CycloneDX license entries have no explicit OR operator. Treat
    # each declared obligation as applicable; alternatives must use expression.
    return any(value[0] for value in results), any(value[1] for value in results)


def component_identity(component: dict) -> str:
    listener = oracle_listener_identity(component)
    name = listener or str(component.get("name") or component.get("bom-ref") or "unknown")
    version = str(component.get("version") or "")
    return str((component.get("purl") if listener is None else None) or (f"{name}@{version}" if version else name))


def validate_policy_expressions(document: PolicyDocument) -> None:
    rules = [rule.model_dump(mode="json") for rule in document.rules if rule.kind == "cel"]
    if rules:
        validate_java_conditions(rules)
        execute_cel({"expressions": rules, "compileOnly": True})


def policy_context_for_run(run: SbomRun, db: Session | None = None) -> dict:
    release = getattr(run, "release", None)
    service = getattr(release, "service", None)
    environment = getattr(release, "environment", None)
    def named(value) -> dict:
        return {key: getattr(value, key) for key in ("id", "slug", "name") if getattr(value, key, None) is not None}
    context = {"project": named(service), "environment": named(environment),
            "release": {"version": release.version} if release is not None else {},
            "run": {key: value for key, value in {"id": getattr(run, "id", None), "source": getattr(run, "source", None), "roundNumber": getattr(run, "round_number", None)}.items() if value is not None}}
    if db is not None and isinstance(run, SbomRun):
        from .quality import latest_quality
        quality = latest_quality(db, run.id)
        context["sbomQuality"] = ({**quality["summary"], "state": quality["state"], "revisionId": quality["id"]}
                                  if quality else {"state": "not_evaluated"})
        catalog = catalog_context_for_run(db, run.id)
        context["sourceProject"] = catalog
        if catalog:
            context["project"].update({"sourceId": catalog["sourceId"], "sourceProjectId": catalog["projectId"],
                                      "ancestorIds": catalog.get("ancestorIds", []), "tags": catalog.get("tags", []),
                                      "isLatest": catalog.get("isLatest", False), "active": catalog.get("active", True)})
    return context


def _rule_applies(rule: PolicyRule, context: dict) -> bool:
    if rule.projectScope and not project_scope_matches(rule.projectScope.model_dump(), context.get("sourceProject") or {}):
        return False
    return all(not allowed or (context.get(section) or {}).get(key) in allowed for allowed, section, key in (
        (rule.serviceIds, "project", "id"), (rule.environmentIds, "environment", "id"), (rule.releaseVersions, "release", "version"), (rule.runIds, "run", "id")))


def _cel_component(component: dict, at: datetime) -> dict:
    result = {key: component[key] for key in ("type", "name", "group", "version", "purl", "legacyLicense", "isDirectDependency") if component.get(key) is not None}
    result["legacyRegexFields"] = {key: component.get(key) for key in ("purl","cpe","group","name","version")}
    result["legacyRegexFields"]["swidTagId"] = (component.get("swid") or {}).get("tagId")
    result["legacyLiteralFields"] = component.get("legacyLiteralFields") or dict(result["legacyRegexFields"])
    result["metadataStatus"] = component.get("metadataStatus", "missing")
    cached_metadata = component.get("packageMetadata") or {}
    result["packageMetadata"] = cached_metadata if component.get("metadataStatus") == "fresh" else {key: cached_metadata[key] for key in ("status", "ecosystem", "sourceUrls", "fetchedAt", "expiresAt", "error", "fieldStatus") if key in cached_metadata}
    result.update(cpe=str(component.get("cpe") or ""), swidTagId=str((component.get("swid") or {}).get("tagId") or ""), hashes=component.get("hashes") or [], isInternal=bool(component.get("isInternal", False)))
    result["licenses"] = [value if isinstance(value, str) else value.get("expression") or (value.get("license") or {}).get("id") or (value.get("license") or {}).get("name") for value in (component.get("licenses") or []) if isinstance(value, (str, dict))]
    result["licenses"] = [value for value in result["licenses"] if isinstance(value, str)]
    properties = component.get("properties") or []
    result["properties"] = {value["name"]: value.get("value", "") for value in properties if isinstance(value, dict) and isinstance(value.get("name"), str)} if isinstance(properties, list) else dict(properties)
    props = result["properties"]
    # Optional metadata is never inferred from version text or fetched remotely.
    # It exists only when explicitly supplied in SBOM koda:* properties.
    if isinstance(props.get("koda:latestVersion"), str):
        result["latestVersion"] = props["koda:latestVersion"]
    for field in ("ageDays", "versionDistance"):
        value = props.get(f"koda:{field}")
        if value is not None:
            try:
                number = int(value)
                if number >= 0:
                    result[field] = number
            except (ValueError, TypeError, OverflowError):
                pass
    if "ageDays" not in result and isinstance(props.get("koda:publishedAt"), str):
        try:
            published = datetime.fromisoformat(props["koda:publishedAt"].replace("Z", "+00:00"))
            if published.tzinfo is not None:
                result["ageDays"] = max(0, (at - published).days)
        except (ValueError, OverflowError):
            pass
    return result


def _cel_quality(evidence: dict) -> dict:
    # Inheritance chains and scoring check rows are immutable evidence, stored
    # once with the analysis. Repeating them per component can exceed CEL's
    # bounded input even for an otherwise small SBOM.
    result = {key: value for key, value in evidence.items() if not isinstance(value, (dict, list))}
    if 'fieldStatus' in evidence:
        result['fieldStatus'] = evidence['fieldStatus']
    if 'profileSnapshot' in evidence:
        result['profileSnapshot'] = {key: value for key, value in evidence['profileSnapshot'].items() if key != 'resolution'}
    details = (evidence.get('scoreDetails') or {}).get('domains') or {}
    if details:
        result['domainScores'] = {key: value.get('score') for key, value in details.items()}
    return result


def build_cel_contexts(components: list[dict], findings: list[dict], project_context: dict | None = None, *, evaluated_at: datetime | None = None, targets: set[str] | None = None, include_peer_vulnerabilities: bool = True) -> dict[str, list[dict]]:
    at = evaluated_at or datetime.now(UTC)
    context = project_context or {}
    base = {key: context.get(key, {}) for key in ("project", "environment", "release", "run")}
    base["sbomQuality"] = _cel_quality(context.get("sbomQuality") or {"state": "not_evaluated"})
    base["now"] = at.isoformat()
    targets = targets or {"component", "vulnerability", "project"}
    result = {target: [] for target in targets}
    indexed = {}
    scoped_components = {}
    for component in components:
        value = _cel_component(component, at)
        value["vulnerabilities"] = []
        indexed[component_identity(component)] = value
        name, version = str(component.get("name") or ""), str(component.get("version") or "")
        if ref := component.get("bom-ref"):
            scoped_components[str(ref)] = value
        indexed[f"{name}@{version}"] = value
        if not version:
            indexed[name] = value
        if "component" in targets:
            result["component"].append({**base, "component": value})
    if "project" in targets:
        result["project"] = [dict(base)]
    for finding in findings:
        name, version = str(finding.get("component") or ""), str(finding.get("version") or "")
        component = scoped_components.get(finding["bomRef"]) if finding.get("oracleHomeEvidence") and isinstance(finding.get("bomRef"), str) else None
        component = component or indexed.get(name) or indexed.get(f"{name}@{version}")
        if component is None:
            component = {"name": name, "version": version, "purl": name} if name.startswith("pkg:") else {"name": name, "version": version}
        vulnerability = {key: finding[key] for key in ("id", "severity", "kev", "fixedIn", "cwes", "cweStatus", "epssScore", "epssPercentile", "epssDate", "epssStatus", "legacyCwesNull") if finding.get(key) is not None}
        vulnerability["canonicalId"] = finding.get("canonicalId") or finding.get("id") or "unknown"
        vulnerability["suppressed"] = (finding.get("vex") or {}).get("suppressed") is True
        score = cvss_score(finding)
        if score is not None:
            try:
                vulnerability["cvssScore"] = float(score)
            except (ValueError, TypeError, OverflowError):
                pass
        if not (finding.get("vex") or {}).get("suppressed"):
            component.setdefault("vulnerabilities", []).append(vulnerability)
        if "vulnerability" in targets:
            activation_component = component if include_peer_vulnerabilities else {key: value for key, value in component.items() if key != "vulnerabilities"}
            result["vulnerability"].append({**base, "component": activation_component, "vulnerability": vulnerability})
    return result


def components_with_dependency_graph(bom: dict) -> list[dict]:
    components = [copy.deepcopy({key: value for key, value in component.items() if key != "components"})
                  for component in iter_components(bom.get("components") or [])]
    root_ref = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    direct = None
    if root_ref:
        root = next((item for item in (bom.get("dependencies") or []) if item.get("ref") == root_ref), None)
        if root is not None:
            direct = set(root.get("dependsOn") or [])
    for component in components:
        if direct is not None:
            component["isDirectDependency"] = component.get("bom-ref") in direct
    return components


def preview_expression(expression: str, target: str, components: list[dict], findings: list[dict], project_context: dict | None = None) -> dict:
    validate_expression(expression, target)
    contexts = build_cel_contexts(components, findings, project_context, targets={target}, include_peer_vulnerabilities="vulnerabilities" in expression)
    result = execute_cel({"expressions": [{"id": "preview", "expression": expression, "target": target}], "contexts": contexts})
    indexes = result["matches"]["preview"]
    return {"valid": True, "target": target, "evaluatedCount": len(contexts[target]), "matchCount": len(indexes), "matchedIndexes": indexes[:100], "truncated": len(indexes) > 100}


def evaluate_document(document: PolicyDocument, components: list[dict], findings: list[dict], *, evaluated_at: datetime | None = None, available_sources: set[str] | None = None, project_context: dict | None = None) -> tuple[list[dict], dict]:
    evaluated_at = evaluated_at or datetime.now(UTC)
    rows: dict[tuple[str, str, str, str, str], dict] = {}
    data_warnings: list[dict] = []
    context = project_context or {}
    applicable_rules = [rule for rule in document.rules if rule.enabled and _rule_applies(rule, context)]
    cel_rules = [rule for rule in applicable_rules if rule.kind == "cel"]
    cel_matches = {}
    legacy_warnings = []
    if cel_rules:
        contexts = build_cel_contexts(components, findings, context, evaluated_at=evaluated_at, targets={rule.target for rule in cel_rules}, include_peer_vulnerabilities=any(rule.target == "vulnerability" and "vulnerabilities" in rule.expression for rule in cel_rules))
        legacy_warnings = prepare_legacy_contexts([rule.model_dump(mode="json") for rule in cel_rules], contexts, evaluated_at=evaluated_at)
        cel_matches = execute_cel({"expressions": [rule.model_dump(mode="json") for rule in cel_rules], "contexts": contexts})["matches"]

    def add(rule: PolicyRule, component: str, vulnerability: str, reason: str, aliases: set[str] | None = None, *, version: str = "", unavailable: bool = False) -> None:
        key = (rule.id, component, version, vulnerability, "data_unavailable" if unavailable else rule.kind)
        if key not in rows and len(rows) >= MAX_POLICY_RESULTS:
            raise ValueError(f"정책 결과가 {MAX_POLICY_RESULTS:,}건 한도를 초과하여 평가를 중단했습니다")
        row = {"policyId": rule.id, "policyName": rule.name, "component": component, "componentVersion": version, "vulnerabilityId": vulnerability, "type": "data_unavailable" if unavailable else rule.kind, "action": "warn" if unavailable else rule.action, "reason": reason, "suppressed": False}
        if rule.kind == "cel":
            row["target"] = rule.target
            row["expression"] = rule.expression
            row["scope"] = {"serviceIds": list(rule.serviceIds), "environmentIds": list(rule.environmentIds), "releaseVersions": list(rule.releaseVersions), "runIds": list(rule.runIds)}
            if rule.projectScope:
                row["scope"]["projectScope"] = rule.projectScope.model_dump(mode="json")
        for exception in document.exceptions:
            if unavailable:
                break
            if exception.runId and exception.runId != ((project_context or {}).get("run") or {}).get("id"):
                continue
            if exception.ruleId != rule.id or exception.component != component or (exception.expiresAt is not None and exception.expiresAt <= evaluated_at):
                continue
            if exception.vulnerabilityId and exception.vulnerabilityId not in (aliases or {vulnerability.upper()}):
                continue
            row["suppressed"] = True
            row["exception"] = exception.model_dump(mode="json")
            break
        rows[key] = row

    for rule in applicable_rules:
        if rule.kind == "cel":
            for warning in legacy_warnings:
                if warning["ruleId"] == rule.id:
                    add(rule, warning["component"], "", warning["reason"], unavailable=True)
                    data_warnings.append({"policyId": rule.id, "source": "legacyCondition", **warning})
            tokens = re.findall(r""" "(?:\\.|[^"\\])*" | '(?:\\.|[^'\\])*' | [A-Za-z_][A-Za-z_0-9]* | [^\s] """, rule.expression, re.VERBOSE)
            referenced = {tokens[index + 1] for index, token in enumerate(tokens[:-1]) if token == "."}
            referenced.update(tokens[index + 1][1:-1] for index, token in enumerate(tokens[:-2]) if token == "[" and tokens[index + 2] == "]" and tokens[index + 1].startswith(("\"", "'")))
            metadata_fields = referenced.intersection({"ageDays", "latestVersion", "versionDistance", "versionDistanceParts", "currentVersionPublishedAt", "latestPublishedAt"})
            for activation in contexts.get(rule.target, []) if metadata_fields else []:
                component_value = activation.get("component") or {}
                missing = sorted(field for field in metadata_fields if component_value.get(field) is None and (component_value.get("packageMetadata") or {}).get(field) is None)
                if missing:
                    component_key = str(component_value.get("purl") or component_value.get("name") or "project")
                    reason = "정책에 필요한 패키지 데이터가 없거나 만료되었습니다: " + ", ".join(missing)
                    add(rule, component_key, "", reason, version=str(component_value.get("version") or ""), unavailable=True)
                    data_warnings.append({"policyId": rule.id, "source": "packageMetadata", "component": component_key, "fields": missing, "reason": reason})
            intelligence_fields = referenced.intersection({"cwes", "epssScore", "epssPercentile"})
            for activation in contexts.get(rule.target, []) if intelligence_fields else []:
                component_value = activation.get("component") or {}
                vulnerabilities = [activation["vulnerability"]] if rule.target == "vulnerability" else component_value.get("vulnerabilities", [])
                for vulnerability_value in vulnerabilities:
                    if vulnerability_value.get("suppressed") is True:
                        continue
                    missing = sorted(field for field in intelligence_fields if vulnerability_value.get(field) is None or field == "cwes" and not vulnerability_value.get("cwes") and vulnerability_value.get("cweStatus") != "available")
                    if missing:
                        component_key = str(component_value.get("purl") or component_value.get("name") or "project")
                        reason = "정책에 필요한 취약점 데이터가 없거나 만료되었습니다: " + ", ".join(missing)
                        vuln_id = str(vulnerability_value.get("canonicalId") or vulnerability_value.get("id") or "")
                        add(rule, component_key, vuln_id, reason, version=str(component_value.get("version") or ""), unavailable=True)
                        data_warnings.append({"policyId": rule.id, "source": "vulnerabilityIntelligence", "component": component_key, "vulnerabilityId": vuln_id, "fields": missing, "reason": reason})
            for index in cel_matches[rule.id]:
                if rule.target == "project":
                    add(rule, str((context.get("project") or {}).get("id") or "project"), "", "CEL 프로젝트 조건에 해당")
                elif rule.target == "component":
                    component = components[index]
                    add(rule, component_identity(component), "", "CEL 구성요소 조건에 해당", version=str(component.get("version") or ""))
                else:
                    finding = findings[index]
                    vulnerability = str(finding.get("canonicalId") or finding.get("id") or "unknown")
                    aliases = {vulnerability.upper(), str(finding.get("id") or "").upper()}
                    aliases.update(str(value).upper() for value in (finding.get("aliases") or []) if isinstance(value, str))
                    component, version = str(finding.get("component") or "unknown"), str(finding.get("version") or "")
                    if version and not component.startswith("pkg:") and not component.endswith(f"@{version}"):
                        component = f"{component}@{version}"
                    add(rule, component, vulnerability, "CEL 취약점 조건에 해당", aliases, version=version)
            continue
        if rule.kind == "kev" and available_sources is not None and "kev" not in available_sources:
            reason = "KEV 데이터 공급원이 없어 알려진 악용 취약점 해당 여부를 확인할 수 없습니다"
            add(rule, "", "", reason, unavailable=True)
            data_warnings.append({"policyId": rule.id, "source": "cisaKev", "reason": reason})
            continue
        if rule.kind in {"severity", "kev"}:
            for finding in findings:
                severity = str(finding.get("severity") or "unknown").lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "unknown"
                matches = severity in rule.values if rule.kind == "severity" else finding.get("kev") is True
                if matches:
                    vulnerability = str(finding.get("canonicalId") or finding.get("id") or "unknown")
                    aliases = {vulnerability.upper(), str(finding.get("id") or "").upper()}
                    aliases.update(str(value).upper() for value in (finding.get("aliases") or []) if isinstance(value, str))
                    component = str(finding.get("component") or "unknown")
                    version = str(finding.get("version") or "")
                    if version and not component.startswith("pkg:") and not component.endswith(f"@{version}"):
                        component = f"{component}@{version}"
                    add(rule, component, vulnerability, f"취약점 심각도: {severity}" if rule.kind == "severity" else "알려진 악용 취약점(KEV) 목록에 포함", aliases, version=version)
        else:
            for component in components:
                identity = component_identity(component)
                if rule.kind == "component_denied":
                    name = str(component.get("name") or "")
                    version = str(component.get("version") or "")
                    exact = {identity, name, f"{name}@{version}" if version else name}
                    matches, reason = bool(exact.intersection(rule.values)), "금지된 구성요소 또는 버전"
                else:
                    denied, unknown = _licenses(component, {value.lower() for value in rule.values})
                    matches = denied if rule.kind == "license_denied" else unknown
                    reason = "금지 라이선스 조건에 해당" if rule.kind == "license_denied" else "라이선스 누락·불명확 또는 표현식 검토 필요"
                if matches:
                    add(rule, identity, "", reason, version=str(component.get("version") or ""))

    policies = [rows[key] for key in sorted(rows)]
    active = [row for row in policies if not row["suppressed"]]
    projected = project_cve_findings(findings)
    severity_counts: Counter[str] = Counter()
    for finding in projected:
        severity = str(finding.get("severity") or "unknown").lower()
        severity_counts[severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown"] += 1
    vulnerable_components = {(str(finding.get("component")), str(finding.get("version") or "")) for finding in projected if finding.get("component")}
    metrics = {
        "componentCount": len(components),
        "componentTypeCounts": dict(Counter(str(component.get("type") or "library") for component in components)),
        "vulnerabilityCount": len(projected),
        "vulnerableComponentCount": len(vulnerable_components),
        "severityCounts": dict(severity_counts),
        "kevCount": sum(finding.get("kev") is True for finding in projected),
        "policyViolationCount": len(active),
        "policyFailCount": sum(row["action"] == "fail" for row in active),
        "policyWarnCount": sum(row["action"] == "warn" for row in active),
        "policyInfoCount": sum(row["action"] == "info" for row in active),
        "policySuppressedCount": len(policies) - len(active),
        "policyDataComplete": not data_warnings,
        "policyDataWarnings": data_warnings,
        "policyStatus": "fail" if any(row["action"] == "fail" for row in active) else "warn" if any(row["action"] == "warn" for row in active) else "info" if active else "pass",
        "evaluatedAt": evaluated_at.isoformat(),
    }
    if any(spec.get("subject") == "JAVA_REGEX" for rule in cel_rules for spec in rule.legacyConditions):
        metrics["policyCompatibilityRuntimes"] = [{"runtime":"java.util.regex.Pattern", "javaMajor":21,
            "adapterProtocol":"KODA_REGEX_V1", "dialect":"java21-legacy4", "isolated":True}]
    literal_minors = {spec["sourceMinor"] for rule in cel_rules for spec in rule.legacyConditions if spec["subject"] in {"LEGACY_LITERAL","LEGACY_PRE48"}}
    if literal_minors:
        metrics.setdefault("policyCompatibilityRuntimes",[]).append({"runtime":"koda.pre48-literal", "sourceMinors":sorted(literal_minors), "allGate":"rawConditionViolationCount", "source40":"firstMatchPerSubject"})
    return policies, metrics


def evaluate_revision(db: Session, run: SbomRun, revision: AnalysisRevision) -> None:
    if revision.state != JobState.COMPLETED:
        revision.policy_state = "not_evaluated"
        revision.policy_error = "Grype 분석이 완료되지 않아 정책을 평가하지 않았습니다"
        return
    try:
        policy = get_policy_document(db)
        snapshot = copy.deepcopy(policy.document)
        revision.policy_version = policy.version
        revision.policy_snapshot = snapshot
        document = PolicyDocument.model_validate(snapshot)
        components = components_with_dependency_graph(getattr(run, "normalized_bom", None) or {})
        from .package_metadata import enrich_components, metadata_summary
        if isinstance(run, SbomRun):
            components = enrich_components(db, components)
            enqueue_findings(db, revision.findings or [])
            revision.findings = enrich_findings(db, revision.findings or [])
        if isinstance(run, SbomRun):
            from .offline_intelligence_store import active_reference_document, sync_reference_bundle
            from .offline_reference_enrichment import enrich_reference_context
            from .vulnerability import active_bundle
            from .config import get_settings
            bundle = active_bundle(get_settings())
            if bundle:
                sync_reference_bundle(db, bundle.path, request_reanalysis=False)
            components, revision.findings, reference_summary = enrich_reference_context(components, revision.findings or [], active_reference_document(db))
            revision.data_sources = {**(revision.data_sources or {}), "offlineIntelligence": reference_summary}
        metadata_evidence = [value.get("packageMetadata") for value in components if value.get("packageMetadata")]
        sources = revision.data_sources or {}
        kev_source = sources.get("cisaKev") or {}
        available_sources = {"kev"} if isinstance(kev_source, dict) and kev_source.get("available") is True else set()
        project_context = policy_context_for_run(run, db)
        # An analysis uses the exact immutable quality evidence it evaluated;
        # a later manual quality rerun must not change this policy snapshot.
        quality_source = (revision.data_sources or {}).get("sbomQuality")
        if quality_source:
            project_context["sbomQuality"] = quality_source
        revision.policies, revision.metrics = evaluate_document(document, components, revision.findings or [], available_sources=available_sources, project_context=project_context)
        revision.policy_snapshot = {**snapshot, "projectScopeSnapshot": project_context.get("sourceProject"), "sbomQualitySnapshot": project_context.get("sbomQuality"),
                                    "vulnerabilityIntelligenceSnapshot": [{"id": value.get("canonicalId") or value.get("id"), "cwes": value.get("cwes"), "epssEvidence": value.get("epssEvidence")} for value in revision.findings or []]}
        revision.metrics["packageMetadataSummary"] = metadata_summary(components)
        if any(rule.kind == "cel" and (any(field in rule.expression for field in ("ageDays", "latestVersion", "versionDistance", "packageMetadata")) or any(spec.get("subject") in {"AGE", "VERSION_DISTANCE"} for spec in rule.legacyConditions)) for rule in document.rules):
            revision.policy_snapshot = {**revision.policy_snapshot, "packageMetadataSnapshot": metadata_evidence}
        revision.metrics = {**revision.metrics, "policyVersion": policy.version, "dataAsOf": revision.data_as_of, "toolVersion": revision.tool_version}
        revision.policy_state = "completed"
        revision.policy_error = None
    except Exception as exc:
        revision.policy_state = "failed"
        revision.policy_error = str(exc)[-2000:]
        revision.metrics = {"policyStatus": "error"}
