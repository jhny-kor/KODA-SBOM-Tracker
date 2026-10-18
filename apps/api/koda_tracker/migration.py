"""Read-only legacy API export, strict conversion, and transactional native import.

The retained bundle is the audit source of truth. Import never treats incomplete
exports, unknown operators, or unrepresentable policies as a passing policy.
"""
from __future__ import annotations

import copy
from datetime import UTC, datetime
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import time
import uuid
from urllib.parse import quote, urlsplit

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .migration_models import LegacyMigration, LegacyObjectMap
from .models import AnalysisRevision, AuditEvent, Environment, Job, JobState, ProcessingState, Release, RunComponent, SbomPolicyRevision, SbomRun, Service, now
from .policies import PolicyDocument, get_policy_document, evaluate_revision, validate_policy_expressions
from .sbom import parse_sbom, normalized_identity
from .workflow_models import FindingReview, ReviewEvent

FORMAT = "koda-legacy-export"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_PROJECTS = 10_000
MAX_FINDINGS = 100_000
_NAMESPACE = uuid.UUID("115e6e14-8ee7-4d74-b36b-a99df197f3e9")


class MigrationError(ValueError):
    pass


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _id(source: str, kind: str, key: str) -> str:
    return str(uuid.uuid5(_NAMESPACE, f"{source}:{kind}:{key}"))


def _uuid(value) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise MigrationError("원본 객체 식별자는 UUID여야 합니다") from exc


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise MigrationError("원본 URL은 사용자정보·쿼리 없는 HTTP(S) origin이어야 합니다")
    if parsed.path not in {"", "/"}:
        raise MigrationError("원본 URL에는 경로를 포함하지 않습니다")
    port = parsed.port
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    return f"{parsed.scheme}://{host}" + (f":{port}" if port and port != (443 if parsed.scheme == "https" else 80) else "")


def validate_source_url(base_url: str, allowed_origins: list[str]) -> str:
    origin = _origin(base_url)
    if origin not in {_origin(value) for value in allowed_origins}:
        raise MigrationError("원본 origin이 명시적 허용 목록에 없습니다")
    host = urlsplit(origin).hostname
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, urlsplit(origin).port or 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise MigrationError("원본 서버 주소를 확인할 수 없습니다") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise MigrationError("메타데이터·링크 로컬·예약 주소는 허용하지 않습니다")
    return origin


class _SourceStream(httpx.SyncByteStream):
    def __init__(self, response, connection):
        self.response, self.connection = response, connection

    def __iter__(self):
        try:
            while chunk := self.response.read(65536):
                yield chunk
        finally:
            self.close()

    def close(self):
        self.response.close()
        self.connection.close()


class _PinnedTransport(httpx.BaseTransport):
    """Connect only to prevalidated IPs; TLS still verifies the original host.

    This stdlib transport avoids a second resolver lookup between the SSRF
    check and connect, while leaving HTTP parsing/stream limits to http.client
    and the exporter. Environment proxy configuration is never consulted.
    """
    def __init__(self, origin: str):
        self.origin = origin
        parsed = urlsplit(origin)
        self.hostname, self.scheme = parsed.hostname, parsed.scheme
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = socket.getaddrinfo(self.hostname, self.port, type=socket.SOCK_STREAM)
        self.addresses = []
        for family, kind, protocol, _, address in addresses:
            ip = ipaddress.ip_address(address[0].split("%", 1)[0])
            if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                raise MigrationError("원본 서버가 금지된 주소로 변경되었습니다")
            self.addresses.append((family, kind, protocol, address))
        if not self.addresses:
            raise MigrationError("원본 서버 주소가 없습니다")

    def handle_request(self, request):
        if _origin(str(request.url.copy_with(path="/", query=None, fragment=None))) != self.origin:
            raise MigrationError("허용한 원본 origin 외부 요청은 차단합니다")
        connection = http.client.HTTPConnection(self.hostname, self.port, timeout=30)
        def connect():
            last_error = None
            for family, kind, protocol, address in self.addresses:
                candidate = socket.socket(family, kind, protocol)
                candidate.settimeout(5)
                try:
                    candidate.connect(address)
                    if self.scheme == "https":
                        candidate = ssl.create_default_context().wrap_socket(candidate, server_hostname=self.hostname)
                    candidate.settimeout(30)
                    connection.sock = candidate
                    return
                except OSError as exc:
                    last_error = exc
                    candidate.close()
            raise last_error or OSError("source unavailable")
        connection.connect = connect
        try:
            connection.request(request.method, request.url.raw_path.decode("ascii"), headers=dict(request.headers))
            response = connection.getresponse()
            return httpx.Response(response.status, headers=list(response.getheaders()), stream=_SourceStream(response, connection), request=request)
        except (OSError, http.client.HTTPException) as exc:
            connection.close()
            raise httpx.ConnectError("source connection failed", request=request) from exc


class LegacyExporter:
    def __init__(self, base_url: str, api_key: str, allowed_origins: list[str], *, source_timezone: str | None = None, transport=None):
        self.source_timezone = source_timezone
        self.origin = validate_source_url(base_url, allowed_origins)
        if not api_key or len(api_key) > 4096 or "\n" in api_key or "\r" in api_key:
            raise MigrationError("원본 API 키가 올바르지 않습니다")
        self.client = httpx.Client(base_url=self.origin + "/api/v1/", headers={"X-Api-Key": api_key, "Accept": "application/json"}, follow_redirects=False, trust_env=False, timeout=httpx.Timeout(30, connect=5), limits=httpx.Limits(max_connections=2), transport=transport or _PinnedTransport(self.origin))
        self.bytes_read = 0
        self.started_at = time.monotonic()

    def close(self):
        self.client.close()

    def get(self, path: str, params: dict | None = None, *, missing_ok=False, accept: str | None = None, _retried=False):
        if time.monotonic() - self.started_at > 300:
            raise MigrationError("원본 전체 내보내기 제한시간(5분)을 초과했습니다")
        try:
            with self.client.stream("GET", path, params=params, headers={"Accept": accept} if accept else None) as response:
                if response.status_code == 406 and accept and not _retried:
                    return self.get(path, params, missing_ok=missing_ok, accept="*/*", _retried=True)
                if missing_ok and response.status_code == 404:
                    return None, response.headers
                if response.status_code != 200:
                    # Never include response bodies, headers, request URL, or keys.
                    raise MigrationError(f"원본 API {path.split('?')[0]} 읽기 실패 (HTTP {response.status_code})")
                raw = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() - self.started_at > 300:
                        raise MigrationError("원본 전체 내보내기 제한시간(5분)을 초과했습니다")
                    raw.extend(chunk)
                    self.bytes_read += len(chunk)
                    if len(raw) > MAX_RESPONSE_BYTES or self.bytes_read > MAX_BUNDLE_BYTES:
                        raise MigrationError("원본 API 응답 용량 제한을 초과했습니다")
                if not raw and missing_ok:
                    return None, response.headers
                return json.loads(raw), response.headers
        except (httpx.HTTPError, OSError, http.client.HTTPException, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MigrationError("원본 API 통신 또는 JSON 응답이 올바르지 않습니다") from exc

    def pages(self, path: str, params: dict | None = None) -> list:
        rows = []
        for page in range(1, 1001):
            data, headers = self.get(path, {**(params or {}), "pageNumber": page, "pageSize": 100})
            if not isinstance(data, list):
                raise MigrationError(f"원본 API {path} 목록 형식이 올바르지 않습니다")
            rows.extend(data)
            total = headers.get("x-total-count")
            if len(rows) > MAX_FINDINGS:
                raise MigrationError("원본 목록 개수 제한을 초과했습니다")
            if total is not None:
                try:
                    expected_total = int(total)
                except ValueError as exc:
                    raise MigrationError("원본 페이지 전체 개수 형식이 올바르지 않습니다") from exc
                if len(rows) >= expected_total:
                    return rows
            elif len(data) < 100:
                return rows
            if not data:
                raise MigrationError("원본 페이지가 선언한 전체 개수보다 일찍 끝났습니다")
        raise MigrationError("원본 페이지 수 제한을 초과했습니다")

    def export(self, project_uuids: list[str] | None = None) -> dict:
        projects = self.pages("project", {"excludeInactive": "false"})
        if len(projects) > MAX_PROJECTS:
            raise MigrationError("프로젝트 수 제한을 초과했습니다")
        if project_uuids:
            selected = {_uuid(value) for value in project_uuids}
            projects = [value for value in projects if value.get("uuid") in selected]
            if selected != {value.get("uuid") for value in projects}:
                raise MigrationError("요청한 원본 프로젝트 일부를 읽을 수 없습니다")
        policies = self.pages("policy")
        policies = [self.get(f"policy/{_uuid(policy['uuid'])}")[0] for policy in policies]
        licenses = self.pages("license")
        groups = self.pages("licenseGroup")
        groups = [self.get(f"licenseGroup/{_uuid(group['uuid'])}")[0] for group in groups]
        exported = []
        for summary in projects:
            project_id = _uuid(summary["uuid"])
            project = self.get(f"project/{project_id}")[0]
            bom = self.get(f"bom/cyclonedx/project/{project_id}", {"format": "json", "variant": "inventory"}, accept="application/vnd.cyclonedx+json, application/octet-stream;q=0.9")[0]
            fpf = self.get(f"finding/project/{project_id}/export")[0]
            # Explicit suppressed=true prevents loss on API versions whose FPF
            # export defaults to active findings only. Merge by source UUID pair.
            findings = self.pages(f"finding/project/{project_id}", {"suppressed": "true"})
            merged = {}
            for finding in [*(fpf.get("findings") or []), *findings]:
                key = ((finding.get("component") or {}).get("uuid"), (finding.get("vulnerability") or {}).get("uuid"))
                if not all(key):
                    raise MigrationError("원본 finding UUID 쌍이 누락되었습니다")
                merged[key] = finding
            fpf["findings"] = list(merged.values())
            analyses = []
            for finding in fpf["findings"]:
                component_id = _uuid(finding["component"]["uuid"])
                vulnerability_id = _uuid(finding["vulnerability"]["uuid"])
                analysis = self.get("analysis", {"project": project_id, "component": component_id, "vulnerability": vulnerability_id}, missing_ok=True)[0]
                if analysis is not None:
                    analyses.append({"componentUuid": component_id, "vulnerabilityUuid": vulnerability_id, "analysis": analysis})
            violations = self.pages(f"violation/project/{project_id}", {"suppressed": "true"})
            violation_analyses = []
            for violation in violations:
                component_id = _uuid((violation.get("component") or {}).get("uuid"))
                analysis = self.get("violation/analysis", {"component": component_id, "policyViolation": _uuid(violation["uuid"])}, missing_ok=True)[0]
                if analysis is not None:
                    violation_analyses.append({"violationUuid": violation["uuid"], "componentUuid": component_id, "analysis": analysis})
            source_components = self.pages(f"component/project/{project_id}")
            exported.append({"project": project, "bom": bom, "components": source_components, "findings": fpf, "analyses": analyses, "violations": violations, "violationAnalyses": violation_analyses})
        version_info = self.get("../version", missing_ok=True)[0]
        bundle = {"format": FORMAT, "version": 1, "source": {"id": hashlib.sha256(self.origin.encode()).hexdigest(), "origin": self.origin, "exportedAt": now().isoformat(), "version": version_info.get("version") if isinstance(version_info, dict) else version_info, **({"timeZone": self.source_timezone} if self.source_timezone else {})}, "projects": exported, "policies": policies, "licenses": licenses, "licenseGroups": groups}
        if len(_json(bundle)) > MAX_BUNDLE_BYTES:
            raise MigrationError("이관 번들이 64 MiB 한도를 초과했습니다")
        return bundle


def _literal(value) -> str:
    return json.dumps(value, ensure_ascii=False)


def _matcher(field: str, value, operator: str) -> str:
    if operator not in {"MATCHES", "NO_MATCH"} or not isinstance(value, str):
        raise MigrationError("문자열 조건의 연산자 또는 값이 지원되지 않습니다")
    # Source Matcher.java treats * as regex wildcard and uses Java full-match.
    # Restrict Java-only constructs instead of silently changing regex dialect.
    if "(?" in value or "&&" in value or re.search(r"\[[^\]]*\[|\\[A-Za-z0-9]", value) or len(value) > 2048:
        raise MigrationError("Java 전용 정규식/이스케이프는 CEL RE2로 동등 변환할 수 없습니다")
    pattern = value.replace("*", ".*").replace("..*", ".*")
    if not pattern.startswith(("^", ".*")):
        pattern = ".*" + pattern
    if not pattern.endswith(("$", ".*")):
        pattern += ".*"
    expression = f"(has({field}) && {field}.matches({_literal('^(?:' + pattern + ')$')}))"
    return f"!{expression}" if operator == "NO_MATCH" else expression


def _condition(condition: dict, *, source_timezone: str | None = None) -> str:
    subject, operator, value = condition.get("subject"), condition.get("operator"), condition.get("value")
    if subject == "SEVERITY" and operator in {"IS", "IS_NOT"}:
        if value not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"}:
            raise MigrationError("알 수 없는 심각도 값입니다")
        values = [value, value.title(), value.lower()]
        if value == "UNASSIGNED":
            values += ["unknown", "Unknown", "UNKNOWN"]
        comparator = f"v.severity in {_literal(values)}"
        if operator == "IS_NOT":
            comparator = f"!({comparator})"
        return f"component.vulnerabilities.exists(v, has(v.severity) && ({comparator}))"
    if subject == "AGE":
        operators = {"NUMERIC_GREATER_THAN": ">", "NUMERIC_GREATER_THAN_OR_EQUAL": ">=", "NUMERIC_EQUAL": "==", "NUMERIC_NOT_EQUAL": "!=", "NUMERIC_LESSER_THAN_OR_EQUAL": "<=", "NUMERIC_LESS_THAN": "<"}
        period = re.fullmatch(r"P([0-9]+)D", str(value))
        if source_timezone != "UTC" or period is None or operator not in operators or not (0 < int(period[1]) <= 2147483647):
            raise MigrationError("AGE는 원본 timeZone=UTC 명시 및 양수 PnD 기간만 동등 변환합니다. 다른 시간대·개월·년은 자동 변환하지 않습니다")
        # Source reads RepositoryMetaComponent.published (latest publication),
        # not the currently installed version's publication timestamp.
        timestamp_value = "int(timestamp(component.packageMetadata.latestPublishedAt))"
        published_day = f"(({timestamp_value} >= 0) ? ({timestamp_value} / 86400) : (({timestamp_value} - 86399) / 86400))"
        return f"(has(component.packageMetadata.latestPublishedAt) && ((int(now) / 86400 - {published_day}) {operators[operator]} {int(period[1])}))"
    if subject == "VULNERABILITY_ID" and operator in {"IS", "IS_NOT"} and isinstance(value, str) and value:
        comparison = f"v.id {'==' if operator == 'IS' else '!='} {_literal(value)}"
        return f"component.vulnerabilities.exists(v, has(v.id) && ({comparison}))"
    if subject in {"PACKAGE_URL", "CPE", "SWID_TAGID"}:
        field = {"PACKAGE_URL": "component.purl", "CPE": "component.cpe", "SWID_TAGID": "component.swidTagId"}[subject]
        return _matcher(field, value, operator)
    if subject == "COORDINATES":
        try:
            coordinates = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise MigrationError("좌표 조건 JSON이 올바르지 않습니다") from exc
        if not isinstance(coordinates, dict) or set(coordinates) - {"group", "name", "version"}:
            raise MigrationError("지원하지 않는 좌표 조건입니다")
        parts = []
        for key in ("group", "name", "version"):
            expected = coordinates.get(key)
            if expected is None:
                parts.append(f"(!has(component.{key}) || component.{key}.matches('^[\\\\x00-\\\\x20]*$'))" if key != "version" else f"!has(component.{key})")
            else:
                if key == "version" and re.match(r"^[<>=!]", expected):
                    raise MigrationError("패키지별 Java ComponentVersion 비교는 자동 변환하지 않습니다")
                part = _matcher(f"component.{key}", expected, "MATCHES")
                # Source group/name matcher treats present blank text as match.
                parts.append(f"({part} || (has(component.{key}) && component.{key}.matches('^[\\x00-\\x20]*$')))" if key != "version" else part)
        if operator not in {"MATCHES", "NO_MATCH"}:
            raise MigrationError("좌표 연산자를 지원하지 않습니다")
        expression = "(" + " && ".join(parts) + ")"
        return "!" + expression if operator == "NO_MATCH" else expression
    if subject == "IS_INTERNAL" and operator in {"IS", "IS_NOT"} and str(value).lower() in {"true", "false"}:
        expected = str(value).lower() == "true"
        if operator == "IS_NOT":
            expected = not expected
        return f"((has(component.isInternal) && component.isInternal) == {_literal(expected)})"
    if subject == "COMPONENT_HASH" and operator in {"IS", "IS_NOT"}:
        try:
            hash_value = json.loads(value)
            algorithm, expected = hash_value["algorithm"].upper(), hash_value["value"].strip().lower()
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            raise MigrationError("해시 조건이 올바르지 않습니다") from exc
        if not expected or not re.fullmatch(r"[a-f0-9]+", expected):
            raise MigrationError("해시 값이 올바르지 않습니다")
        expression = f"(has(component.hashes) && component.hashes.exists(h, h.alg == {_literal(algorithm)} && h.content.matches({_literal("(?i)^" + expected + "$")})))"
        return "!" + expression if operator == "IS_NOT" else expression
    raise MigrationError(f"조건 {subject}/{operator}는 동등성 검증이 필요하여 적용을 차단합니다")


def _source_scope(policy: dict, projects: list[dict]) -> list[str] | None:
    assigned = {_uuid(value.get("uuid") if isinstance(value, dict) else value) for value in policy.get("projects") or []}
    tags = {value.get("name") if isinstance(value, dict) else value for value in policy.get("tags") or []}
    only_latest = policy.get("onlyLatestProjectVersion") is True
    if not assigned and not tags and not only_latest:
        return None
    by_id = {item["project"]["uuid"]: item["project"] for item in projects}
    missing = assigned - by_id.keys()
    if missing:
        raise MigrationError("정책 범위 프로젝트가 번들에 누락되어 있습니다")
    result = set()
    for project_id, project in by_id.items():
        project_tags = {value.get("name") if isinstance(value, dict) else value for value in project.get("tags") or []}
        applies = not assigned and not tags or project_id in assigned or bool(tags & project_tags)
        visited, current = set(), project
        while policy.get("includeChildren") and current.get("parent"):
            parent = current["parent"]
            parent_id = parent.get("uuid") if isinstance(parent, dict) else parent
            if parent_id in visited:
                raise MigrationError("프로젝트 부모 계층에 순환이 있습니다")
            visited.add(parent_id)
            if parent_id in assigned:
                applies = True
            current = by_id.get(parent_id, {})
        if applies and not (only_latest and project.get("isLatest") is False):
            result.add(project_id)
    return sorted(result)


def _license_values(policy: dict, bundle: dict) -> list[str] | None:
    conditions = policy.get("policyConditions") or []
    if not any(value.get("subject") in {"LICENSE", "LICENSE_GROUP"} for value in conditions):
        return None
    if len(conditions) != 1:
        raise MigrationError("SPDX 라이선스와 다른 조건을 조합한 정책은 동등 변환 검증이 필요합니다")
    condition = conditions[0]
    if condition.get("operator") != "IS":
        raise MigrationError("허용 라이선스(IS_NOT) 및 unresolved 조건은 자동 변환하지 않습니다")
    licenses = {str(item.get("uuid")): item.get("licenseId") for item in bundle.get("licenses") or []}
    if condition["subject"] == "LICENSE":
        identifier = licenses.get(str(condition.get("value")))
        if not identifier:
            raise MigrationError("정책의 SPDX 라이선스 UUID를 해석할 수 없습니다")
        return [identifier]
    group = next((value for value in bundle.get("licenseGroups") or [] if str(value.get("uuid")) == str(condition.get("value"))), None)
    if group is None:
        raise MigrationError("라이선스 그룹이 번들에 없습니다")
    values = []
    for item in group.get("licenses") or []:
        identifier = item.get("licenseId") if isinstance(item, dict) else licenses.get(str(item))
        if not identifier:
            raise MigrationError("그룹의 SPDX 라이선스를 해석할 수 없습니다")
        values.append(identifier)
    if not values:
        raise MigrationError("빈 라이선스 그룹은 자동 변환하지 않습니다")
    return sorted(set(values))


def _plan_runs(db: Session, bundle: dict) -> dict:
    source_id = bundle["source"]["id"]
    plan = {}
    for item in bundle["projects"]:
        project_id = _uuid(item["project"]["uuid"])
        previous = db.get(LegacyObjectMap, (source_id, "project", project_id))
        existing = db.get(SbomRun, previous.target_id) if previous else db.scalar(select(SbomRun).where(SbomRun.dtrack_project_uuid == project_id).limit(1))
        bom_hash = digest({"bom": item.get("bom"), "components": item.get("components", [])})
        # The same exported source BOM reuses its run. Changed source BOMs get
        # another immutable round rather than overwriting original evidence.
        if existing and (not previous or previous.provenance.get("bomHash") == bom_hash):
            run_id = existing.id
        else:
            run_id = _id(source_id, "run", project_id + ":" + bom_hash)
        plan[project_id] = {"runId": run_id, "serviceId": existing.release.service_id if existing else _id(source_id, "service", project_id), "environmentId": existing.release.environment_id if existing else _id(source_id, "environment", "legacy"), "bomHash": bom_hash}
    return plan


def _source_exceptions(bundle: dict, report: dict) -> tuple[list[dict], list[dict]]:
    converted, blockers = [], []
    policies = {value["sourcePolicyUuid"]: value for value in report["convertedPolicies"]}
    for item in bundle["projects"]:
        analyses = {value.get("violationUuid"): value.get("analysis") or {} for value in item.get("violationAnalyses") or []}
        project_id = item["project"]["uuid"]
        for violation in item.get("violations") or []:
            analysis = analyses.get(violation.get("uuid"), {})
            suppressed = analysis.get("isSuppressed", analysis.get("suppressed", violation.get("suppressed"))) is True
            if not suppressed:
                continue
            condition = violation.get("policyCondition") or {}
            policy_id = (condition.get("policy") or {}).get("uuid") or (violation.get("policy") or {}).get("uuid")
            policy = policies.get(policy_id)
            if policy is None or len(policy["original"].get("policyConditions") or []) != 1:
                blockers.append({"projectUuid": project_id, "violationUuid": violation.get("uuid"), "reason": "복합 조건별 원본 억제를 단일 정책 예외로 합치면 과잉 면제가 발생하므로 신뢰 승인을 차단합니다"})
                continue
            component = violation.get("component") or {}
            identity = component.get("purl") or component.get("name")
            if not identity:
                blockers.append({"violationUuid": violation.get("uuid"), "reason": "원본 정책 억제의 구성요소 식별자가 없습니다"})
                continue
            if not identity.startswith("pkg:") and component.get("version"):
                identity += "@" + str(component["version"])
            converted.append({"sourceViolationUuid": _uuid(violation.get("uuid")), "exception": {
                "id": "legacy-exception-" + _id(bundle["source"]["id"], "exception", violation["uuid"]),
                "ruleId": policy["rule"]["id"], "runId": report["projectPlan"][project_id]["runId"],
                "component": identity, "expiresAt": None,
                "reason": str(analysis.get("analysisDetails") or analysis.get("detail") or "관리자가 신뢰한 원본 정책 억제 결정")[:2000],
            }, "original": {"violation": violation, "analysis": analysis}})
    return converted, blockers


def make_report(db: Session, bundle: dict) -> dict:
    blockers, warnings, converted = [], [], []
    if not isinstance(bundle, dict) or bundle.get("format") != FORMAT or bundle.get("version") != 1:
        raise MigrationError("지원하는 이관 번들 형식 또는 버전이 아닙니다")
    if len(_json(bundle)) > MAX_BUNDLE_BYTES:
        raise MigrationError("이관 번들이 64 MiB 한도를 초과했습니다")
    source_id = (bundle.get("source") or {}).get("id")
    if not isinstance(source_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", source_id):
        raise MigrationError("안정적인 원본 시스템 ID가 필요합니다")
    for key in ("projects", "policies", "licenses", "licenseGroups"):
        if not isinstance(bundle.get(key), list):
            raise MigrationError(f"번들 {key} 전체 목록이 필요합니다")
    if len(bundle["projects"]) > MAX_PROJECTS:
        raise MigrationError("프로젝트 수 제한을 초과했습니다")
    for key in ("projects", "policies", "licenses", "licenseGroups"):
        if any(not isinstance(value, dict) for value in bundle[key]):
            raise MigrationError(f"번들 {key} 항목은 JSON 객체여야 합니다")
    policy_ids = [_uuid(value.get("uuid")) for value in bundle["policies"]]
    if len(policy_ids) != len(set(policy_ids)):
        raise MigrationError("원본 정책 UUID가 중복되었습니다")
    source_ids = []
    for item in bundle["projects"]:
        project = item.get("project") or {}
        if not isinstance(project, dict):
            raise MigrationError("프로젝트 형식이 올바르지 않습니다")
        source_ids.append(_uuid(project.get("uuid")))
        for key in ("bom", "findings", "analyses", "violations", "violationAnalyses"):
            if key not in item:
                blockers.append({"projectUuid": project.get("uuid"), "reason": f"원본 {key} 수집이 누락되었습니다"})
        try:
            parse_sbom(_json(item.get("bom")))
        except ValueError as exc:
            blockers.append({"projectUuid": project.get("uuid"), "reason": str(exc)})
        findings = item.get("findings")
        if not isinstance(findings, dict) or not isinstance(findings.get("findings"), list):
            raise MigrationError("원본 findings FPF 목록이 필요합니다")
        if len(findings["findings"]) > MAX_FINDINGS:
            raise MigrationError("프로젝트 finding 개수 제한을 초과했습니다")
        for field in ("analyses", "violations", "violationAnalyses"):
            if field in item and (not isinstance(item[field], list) or any(not isinstance(value, dict) for value in item[field])):
                raise MigrationError(f"원본 {field} 목록 형식이 올바르지 않습니다")
        bom_components = (item.get("bom") or {}).get("components") or []
        for finding in findings["findings"]:
            if not isinstance(finding, dict) or not isinstance(finding.get("component"), dict) or not isinstance(finding.get("vulnerability"), dict):
                raise MigrationError("원본 finding 구성요소·취약점 형식이 올바르지 않습니다")
            source_component = finding["component"]
            _finding(finding)
            matched = any(
                (source_component.get("uuid") and str(component.get("bom-ref", "")).removeprefix("urn:uuid:") == source_component["uuid"])
                or (source_component.get("purl") and component.get("purl") == source_component["purl"])
                or (component.get("name") == source_component.get("name") and str(component.get("version") or "") == str(source_component.get("version") or ""))
                for component in bom_components if isinstance(component, dict))
            if not matched:
                blockers.append({"projectUuid": project.get("uuid"), "reason": "원본 finding이 내보낸 SBOM의 구성요소와 일치하지 않습니다. 변경 중인 원본을 다시 내보내세요"})
    if len(source_ids) != len(set(source_ids)):
        raise MigrationError("원본 프로젝트 UUID가 중복되었습니다")
    plan = _plan_runs(db, bundle)
    for policy in bundle["policies"]:
        policy_id = _uuid(policy.get("uuid"))
        try:
            action = str(policy.get("violationState") or "").lower()
            if action not in {"fail", "warn", "info"}:
                raise MigrationError("정책 위반 동작을 지원하지 않습니다")
            operator = policy.get("operator")
            if operator not in {"ALL", "ANY"}:
                raise MigrationError("정책 조합은 ALL 또는 ANY여야 합니다")
            conditions = policy.get("policyConditions")
            if not isinstance(conditions, list) or not conditions:
                raise MigrationError("빈 정책 조건은 자동 변환하지 않습니다")
            scoped = _source_scope(policy, bundle["projects"])
            if scoped == []:
                warnings.append({"policyUuid": policy_id, "reason": "선택한 원본 범위에 적용 대상이 없어 비활성 정책으로 보존합니다"})
            rule = {"id": "legacy-" + _id(source_id, "policy", policy_id), "name": str(policy.get("name") or policy_id)[:255], "action": action, "enabled": scoped != []}
            if scoped is not None:
                rule["runIds"] = [plan[value]["runId"] for value in scoped]
            license_values = _license_values(policy, bundle)
            if license_values is not None:
                for source_project in bundle["projects"]:
                    if scoped is not None and source_project["project"]["uuid"] not in scoped:
                        continue
                    for component in (source_project.get("bom") or {}).get("components") or []:
                        for license_value in component.get("licenses") or []:
                            expression = license_value if isinstance(license_value, str) else str(license_value.get("expression") or (license_value.get("license") or {}).get("id") or "")
                            if re.search(r"\bWITH\b|\+", expression):
                                raise MigrationError("원본 SPDX WITH·PLUS 선택 의미는 기본 라이선스 규칙과 달라 동등 변환을 차단합니다")
                rule.update({"kind": "license_denied", "values": license_values})
            else:
                pieces = [_condition(value, source_timezone=(bundle.get("source") or {}).get("timeZone")) for value in conditions]
                rule.update({"kind": "cel", "target": "component", "expression": "(" + (" && " if operator == "ALL" else " || ").join(f"({part})" for part in pieces) + ")"})
            validated = PolicyDocument(rules=[rule])
            validate_policy_expressions(validated)
            if any(value.get("subject") == "AGE" for value in conditions):
                warnings.append({"policyUuid": policy_id, "reason": "AGE는 원본 UTC 달력 날짜와 repository 최신 버전 공개일 기준으로 변환했습니다. 사용 중인 버전 나이 또는 경과 24시간으로 대체하지 않습니다"})
            converted.append({"sourcePolicyUuid": policy_id, "rule": validated.rules[0].model_dump(mode="json"), "original": copy.deepcopy(policy)})
            if policy.get("tags") or policy.get("includeChildren") or policy.get("onlyLatestProjectVersion"):
                warnings.append({"policyUuid": policy_id, "reason": "태그·부모 범위를 번들 시점의 회차 ID 집합으로 확장했습니다. 향후 새 원본 프로젝트는 새 이관이 필요합니다"})
        except (ValueError, KeyError, TypeError) as exc:
            blockers.append({"policyUuid": policy_id, "reason": str(exc)[:2000], "original": copy.deepcopy(policy)})
    current_policy = get_policy_document(db)
    warnings.append({"reason": "외부 분석·검토 결과는 원본 증거로 보존합니다. 기본값은 미승인 검토이며 신뢰 승인은 관리자 명시 선택이 필요합니다"})
    report = {"currentPolicyVersion": current_policy.version, "canApply": not blockers, "blockers": blockers, "warnings": warnings, "counts": {"projects": len(bundle["projects"]), "policies": len(bundle["policies"]), "convertedPolicies": len(converted), "findings": sum(len((item.get("findings") or {}).get("findings") or []) for item in bundle["projects"]), "analyses": sum(len(item.get("analyses") or []) for item in bundle["projects"])}, "convertedPolicies": converted, "projectPlan": plan}
    previous_rule_ids = set(db.scalars(select(LegacyObjectMap.target_id).where(LegacyObjectMap.source_id == source_id, LegacyObjectMap.object_type == "policy")))
    combined = [value for value in current_policy.document.get("rules", []) if value["id"] not in previous_rule_ids] + [value["rule"] for value in converted]
    try:
        PolicyDocument(rules=combined)
    except ValueError as exc:
        report["blockers"].append({"reason": "기존 정책과 합친 문서가 KODA 제한을 초과하거나 충돌합니다: " + str(exc)[:500]})
        report["canApply"] = False
    exceptions, trust_blockers = _source_exceptions(bundle, report)
    report["convertedExceptions"], report["trustReviewBlockers"] = exceptions, trust_blockers
    report["counts"]["policyExceptions"] = len(exceptions)
    return report


def stage_bundle(db: Session, bundle: dict, actor: str) -> LegacyMigration:
    report = make_report(db, bundle)
    checksum = digest(bundle)
    existing = db.scalar(select(LegacyMigration).where(LegacyMigration.digest == checksum))
    if existing:
        if existing.state != "applied":
            existing.report = report
            existing.state = "staged" if report["canApply"] else "blocked"
        return existing
    staged = LegacyMigration(digest=checksum, source_id=bundle["source"]["id"], bundle=copy.deepcopy(bundle), report=report, actor=actor, state="staged" if report["canApply"] else "blocked")
    db.add(staged)
    db.flush()
    return staged


def migration_payload(item: LegacyMigration) -> dict:
    return {"id": item.id, "digest": item.digest, "sourceId": item.source_id, "state": item.state, "report": item.report, "result": item.result, "createdAt": item.created_at.isoformat(), "appliedAt": item.applied_at.isoformat() if item.applied_at else None}


def _map(db: Session, source_id: str, kind: str, object_id: str, target: str, content, provenance: dict):
    item = db.get(LegacyObjectMap, (source_id, kind, object_id))
    if item is None:
        item = LegacyObjectMap(source_id=source_id, object_type=kind, object_id=object_id, target_id=target, content_hash=digest(content), provenance=provenance)
        db.add(item)
    else:
        item.target_id, item.content_hash, item.provenance = target, digest(content), provenance
    return item


def _finding(raw: dict) -> dict:
    component, vulnerability = raw.get("component") or {}, raw.get("vulnerability") or {}
    identifier = str(vulnerability.get("vulnId") or vulnerability.get("id") or "")
    if not identifier:
        raise MigrationError("원본 취약점 식별자가 누락되었습니다")
    aliases = []
    for alias in vulnerability.get("aliases") or []:
        if isinstance(alias, dict):
            aliases.extend(str(value) for key, value in alias.items() if key.lower().endswith("id") and isinstance(value, str))
        elif isinstance(alias, str):
            aliases.append(alias)
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", " ".join([identifier, *aliases]), re.I)))
    finding = {"id": identifier, "canonicalId": identifier.upper() if identifier.upper().startswith("CVE-") else cves[0].upper() if cves else identifier, "aliases": aliases, "component": component.get("purl") or component.get("name") or "unknown", "version": str(component.get("version") or ""), "severity": vulnerability.get("severity") or "Unknown", "source": vulnerability.get("source"), "legacy": copy.deepcopy(raw)}
    score = next((vulnerability[key] for key in ("cvssV4BaseScore", "cvssV3BaseScore", "cvssV2Score") if isinstance(vulnerability.get(key), (int, float))), None)
    if score is not None:
        finding["cvssScore"] = score
    return finding


def _analysis_content(source_item: dict) -> dict:
    # FPF meta includes the export timestamp; it is audit provenance rather than
    # a new analysis. Stable content makes repeat exports idempotent.
    return {"findings": sorted((source_item["findings"].get("findings") or []), key=digest),
            **{key: sorted(source_item[key], key=digest) for key in ("analyses", "violations", "violationAnalyses")}}


def _reviews(db: Session, batch: LegacyMigration, source_item: dict, run: SbomRun, actor: str, actor_id: str, trusted: bool) -> int:
    source_findings = (source_item.get("findings") or {}).get("findings") or []
    by_pair = {((value.get("component") or {}).get("uuid"), (value.get("vulnerability") or {}).get("uuid")): value for value in source_findings}
    count = 0
    for entry in source_item.get("analyses") or []:
        analysis = entry.get("analysis") or {}
        key = (entry.get("componentUuid"), entry.get("vulnerabilityUuid"))
        raw = by_pair.get(key)
        if raw is None:
            raise MigrationError("원본 검토가 번들 finding을 참조하지 않습니다")
        state = str(analysis.get("analysisState") or "NOT_SET")
        suppressed = analysis.get("isSuppressed") is True or analysis.get("suppressed") is True
        states = {"NOT_AFFECTED": "not_affected", "FALSE_POSITIVE": "false_positive", "EXPLOITABLE": "exploitable", "IN_TRIAGE": "in_triage", "RESOLVED": "resolved"}
        native_state = states.get(state, "in_triage")
        if trusted and suppressed and native_state not in {"not_affected", "false_positive"}:
            raise MigrationError("의미가 불명확한 원본 임의 억제는 신뢰 승인으로 가져올 수 없습니다. 원본 검토를 명확히 하거나 기본 미승인 이관을 사용하세요")
        # A source false-positive classification without source suppression must
        # never become a newly effective native suppression.
        approve = trusted and (not suppressed and native_state not in {"not_affected", "false_positive"} or suppressed)
        raw_hash = digest(entry)
        object_id = _id(batch.source_id, "analysis", ":".join(str(value) for value in key) + ":" + raw_hash)
        previous = db.get(LegacyObjectMap, (batch.source_id, "review", object_id))
        if previous:
            if approve and previous.provenance.get("trusted") is not True:
                raise MigrationError("이미 미승인으로 이관한 검토는 KODA 검토 승인 절차로 승인해야 합니다")
            continue
        finding = _finding(raw)
        component = finding["component"]
        if not component.startswith("pkg:") and finding["version"] and not component.endswith("@" + finding["version"]):
            component += "@" + finding["version"]
        detail = str(analysis.get("analysisDetails") or analysis.get("detail") or "원본 시스템 검토 이관")
        from .workflows import JUSTIFICATIONS, RESPONSES
        justification = str(analysis.get("analysisJustification") or "").lower()
        response = str(analysis.get("analysisResponse") or "").lower()
        review = FindingReview(id=_id(batch.source_id, "review", object_id), run_id=run.id, service_id=run.release.service_id, environment_id=run.release.environment_id, component=component, component_version=finding["version"], vulnerability_id=finding["canonicalId"], state=native_state, justification=justification if justification in JUSTIFICATIONS else "", detail=detail, response=[response] if response in RESPONSES else [], author_id=_id(batch.source_id, "review-author", "source"), author="migration:" + batch.source_id[:100], status="approved" if approve else "submitted", reviewer=actor if approve else None, decision_reason="관리자가 원본 검토 결정을 신뢰하여 이관" if approve else None, decided_at=now() if approve else None)
        db.add(review)
        db.flush()
        db.add(ReviewEvent(review_id=review.id, kind="legacy_import", actor=actor, comment=_json({"migrationId": batch.id, "sourceId": batch.source_id, "trusted": approve, "original": entry}).decode()))
        _map(db, batch.source_id, "review", object_id, review.id, entry, {"migrationId": batch.id, "trusted": approve})
        count += 1
    return count


def apply_migration(db: Session, migration_id: str, *, expected_digest: str, expected_policy_version: int, actor: str, actor_id: str, trust_source_reviews: bool = False, artifact_dir: Path | None = None) -> LegacyMigration:
    batch = db.scalar(select(LegacyMigration).where(LegacyMigration.id == migration_id).with_for_update())
    if batch is None:
        raise MigrationError("이관 작업이 없습니다")
    if batch.digest != expected_digest or digest(batch.bundle) != expected_digest:
        raise MigrationError("이관 번들 해시가 일치하지 않습니다")
    if batch.state == "applied":
        return batch
    report = make_report(db, batch.bundle)
    if trust_source_reviews and report.get("trustReviewBlockers"):
        raise MigrationError("원본 개별 정책 억제를 안전하게 이관할 수 없어 신뢰 승인을 차단합니다")
    if not report["canApply"]:
        raise MigrationError("동등 변환하지 못한 정책 또는 누락 데이터가 있어 적용할 수 없습니다")
    current = db.scalar(select(SbomPolicyRevision).order_by(SbomPolicyRevision.version.desc()).limit(1).with_for_update())
    if current is None or current.version != expected_policy_version:
        raise MigrationError("정책 버전이 변경되었습니다. 이관을 다시 검토하세요")
    bundle = batch.bundle
    source_id = batch.source_id
    old_policy_ids = set(db.scalars(select(LegacyObjectMap.target_id).where(LegacyObjectMap.source_id == source_id, LegacyObjectMap.object_type == "policy")))
    document = copy.deepcopy(current.document)
    document["rules"] = [rule for rule in document.get("rules") or [] if rule["id"] not in old_policy_ids]
    document["rules"].extend(value["rule"] for value in report["convertedPolicies"])
    remaining_ids = {rule["id"] for rule in document["rules"]}
    old_exception_ids = set(db.scalars(select(LegacyObjectMap.target_id).where(LegacyObjectMap.source_id == source_id, LegacyObjectMap.object_type == "exception")))
    document["exceptions"] = [value for value in document.get("exceptions") or [] if value.get("ruleId") in remaining_ids and value.get("id") not in old_exception_ids]
    if trust_source_reviews:
        document["exceptions"].extend(value["exception"] for value in report["convertedExceptions"])
    validated = PolicyDocument.model_validate(document)
    validate_policy_expressions(validated)
    root = Path(artifact_dir or get_settings().artifact_dir).resolve() / "legacy-imports"
    root.mkdir(parents=True, exist_ok=True)
    created_files = []
    try:
        with db.begin_nested():
            # A new policy revision is needed only when the effective document
            # changed. Source re-exports otherwise remain idempotent.
            if digest(current.document) != digest(document):
                policy = SbomPolicyRevision(version=current.version + 1, document=document, created_by=actor)
                db.add(policy)
                db.flush()
            else:
                policy = current
            imported_runs, imported_revisions, imported_reviews, queued = [], 0, 0, 0
            for source_item in bundle["projects"]:
                project = source_item["project"]
                project_id = project["uuid"]
                plan = report["projectPlan"][project_id]
                run = db.get(SbomRun, plan["runId"])
                if run is None:
                    service = db.get(Service, plan["serviceId"])
                    if service is None:
                        service = Service(id=plan["serviceId"], slug="legacy-" + plan["serviceId"], name=str(project.get("name") or project_id)[:255], active=project.get("active", True) is not False)
                        db.add(service)
                    environment = db.get(Environment, plan["environmentId"])
                    if environment is None:
                        environment = Environment(id=plan["environmentId"], slug="legacy-" + plan["environmentId"][:16], name="이관", active=True)
                        db.add(environment)
                    db.flush()
                    version = str(project.get("version") or "unversioned")
                    if len(version) > 255:
                        raise MigrationError("원본 프로젝트 버전이 KODA 길이 제한을 초과했습니다")
                    release = db.scalar(select(Release).where(Release.service_id == service.id, Release.environment_id == environment.id, Release.version == version).with_for_update())
                    if release is None:
                        release = Release(id=_id(source_id, "release", project_id + ":" + version), service_id=service.id, environment_id=environment.id, version=version)
                        db.add(release)
                        db.flush()
                    raw = _json(source_item["bom"])
                    normalized, media = parse_sbom(raw)
                    source_components = {value.get("uuid"): value for value in source_item.get("components", [])}
                    for component in normalized.get("components") or []:
                        source_component = source_components.get(str(component.get("bom-ref", "")).removeprefix("urn:uuid:")) or next((value for value in source_components.values() if value.get("purl") and value.get("purl") == component.get("purl")), {})
                        if "isInternal" in source_component:
                            component["isInternal"] = source_component["isInternal"] is True
                        if source_component.get("swidTagId"):
                            component["swid"] = {"tagId": source_component["swidTagId"]}
                    checksum = hashlib.sha256(raw).hexdigest()
                    path = root / (plan["runId"] + ".json")
                    if path.exists():
                        if hashlib.sha256(path.read_bytes()).hexdigest() != checksum:
                            raise MigrationError("이관 산출물 파일의 기존 해시가 일치하지 않습니다")
                    else:
                        with path.open("xb") as target:
                            target.write(raw)
                        created_files.append(path)
                    round_number = (db.scalar(select(func.max(SbomRun.round_number)).where(SbomRun.release_id == release.id)) or 0) + 1
                    run = SbomRun(id=plan["runId"], release_id=release.id, round_number=round_number, state=ProcessingState.COMPLETED, analysis_state=JobState.COMPLETED, dtrack_state=JobState.COMPLETED, source="legacy_import", original_filename="legacy-" + project_id + ".cdx.json", media_type=media, spec_version=normalized["specVersion"], serial_number=normalized.get("serialNumber"), sha256=checksum, size_bytes=len(raw), artifact_path=str(path), normalized_bom=normalized, note="원본 시스템 이관", source_metadata={"migrationId": batch.id, "sourceId": source_id, "sourceProjectUuid": project_id, "sourceProject": project, "sourceBomHash": plan["bomHash"]})
                    db.add(run)
                    db.flush()
                    for component in normalized.get("components") or []:
                        identity, status = normalized_identity(component)
                        db.add(RunComponent(run_id=run.id, identity_key=identity, identity_status=status, component_type=component.get("type") or "library", group_name=component.get("group") or "", name=component.get("name") or "unknown", version=component.get("version") or "", purl=component.get("purl") or "", bom_ref=component.get("bom-ref") or "", search_text=" ".join(str(component.get(key) or "") for key in ("type", "group", "name", "version", "purl")).lower(), licenses=component.get("licenses") or [], properties=component.get("properties") or []))
                imported_reviews += _reviews(db, batch, source_item, run, actor, actor_id, trust_source_reviews)
                source_hash = digest(_analysis_content(source_item))
                previous = db.get(LegacyObjectMap, (source_id, "analysis", project_id))
                if previous is None or previous.content_hash != source_hash or previous.provenance.get("runId") != run.id:
                    sequence = (db.scalar(select(func.max(AnalysisRevision.sequence)).where(AnalysisRevision.run_id == run.id)) or 0) + 1
                    revision = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.COMPLETED, tool_version="legacy-import", data_as_of=str((bundle.get("source") or {}).get("exportedAt") or "unknown")[:64], data_sources={"migration": {"migrationId": batch.id, "sourceId": source_id, "digest": batch.digest, "projectUuid": project_id, "original": {key: source_item[key] for key in ("findings", "analyses", "violations", "violationAnalyses")}}}, findings=[_finding(value) for value in (source_item["findings"].get("findings") or [])])
                    db.add(revision)
                    db.flush()
                    from .workflows import approved_for_run, identity, review_dict, SUPPRESS_STATES, apply_vex_reviews
                    decisions = approved_for_run(db, run)
                    revision.findings = [{**finding, **({"vex": {**review_dict(decisions[identity(finding)]), "suppressed": decisions[identity(finding)].state in SUPPRESS_STATES}} if identity(finding) in decisions else {})} for finding in revision.findings]
                    evaluate_revision(db, run, revision)
                    if revision.policy_state != "completed":
                        raise MigrationError("이관된 정책의 실제 평가가 실패했습니다: " + str(revision.policy_error or "unknown"))
                    apply_vex_reviews(db, run, revision)
                    run.analysis_state, run.state = JobState.COMPLETED, ProcessingState.COMPLETED
                    _map(db, source_id, "analysis", project_id, revision.id, _analysis_content(source_item), {"runId": run.id, "migrationId": batch.id})
                    imported_revisions += 1
                _map(db, source_id, "project", project_id, run.id, source_item["project"], {"bomHash": plan["bomHash"], "migrationId": batch.id, "sourceProject": project})
                imported_runs.append(run.id)
            for value in report["convertedPolicies"]:
                _map(db, source_id, "policy", value["sourcePolicyUuid"], value["rule"]["id"], value["original"], {"migrationId": batch.id, "rule": value["rule"]})
            if trust_source_reviews:
                for value in report["convertedExceptions"]:
                    _map(db, source_id, "exception", value["sourceViolationUuid"], value["exception"]["id"], value["original"], {"migrationId": batch.id, "trusted": True, "exception": value["exception"]})
            batch.state, batch.applied_at = "applied", now()
            batch.report = report
            batch.result = {"runIds": imported_runs, "analysisRevisionsCreated": imported_revisions, "reviewsCreated": imported_reviews, "policyVersion": policy.version, "trustSourceReviews": trust_source_reviews, "actor": actor, "grypeReanalysis": "Imported results are historical source evidence; enqueue a native reanalysis cycle to verify against the current Grype DB."}
            db.add(AuditEvent(actor=actor, action="legacy_migration.apply", target_type="legacy_migration", target_id=batch.id, detail={"digest": batch.digest, "sourceId": source_id, "trustSourceReviews": trust_source_reviews, "result": batch.result}))
            db.flush()
    except BaseException:
        for path in created_files:
            path.unlink(missing_ok=True)
        raise
    return batch
