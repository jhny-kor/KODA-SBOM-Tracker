"""Read-only package inventory derived from preserved SBOM observations.

The catalog streams narrow component rows rather than loading SBOM documents or
analysis evidence for every package. Inventory means the latest completed,
unarchived snapshot per service/environment, never proof of a live deployment.
"""
from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl, quote, unquote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .db import get_db
from .models import AnalysisRevision, Environment, JobState, ProcessingState, Release, RunComponent, SbomRun, Service
from .package_metadata import iso
from .project_catalog_models import NativeReanalysisPending
from .security import require_permission

router = APIRouter(prefix="/api/v1/libraries", tags=["Library inventory"])
RELATED_RUN_LIMIT = 1000
RELATED_RECORD_LIMIT = 200


def package_coordinate(purl: str, component_type: str = "library", group: str = "", name: str = "") -> str:
    """Remove only a PURL version, retaining distro, architecture and subpath."""
    if purl.startswith("pkg:"):
        path, _, subpath = purl.partition("#")
        path, _, qualifiers = path.partition("?")
        version_at = path.rfind("@")
        if version_at > path.rfind("/"):
            path = path[:version_at]
        ecosystem, slash, coordinates = path[4:].partition("/")
        if slash and coordinates:
            ecosystem = ecosystem.lower()
            segments = [unquote(part) for part in coordinates.split("/")]
            if ecosystem in {"npm", "nuget", "pypi"}:
                segments = [part.lower() for part in segments]
            if ecosystem == "pypi":
                segments[-1] = re.sub(r"[-_.]+", "-", segments[-1])
            canonical = "pkg:" + ecosystem + "/" + "/".join(quote(part, safe="@._-~") for part in segments)
            if qualifiers:
                canonical += "?" + urlencode(sorted(parse_qsl(qualifiers, keep_blank_values=True)))
            if subpath:
                canonical += "#" + "/".join(quote(unquote(part), safe="._-~") for part in subpath.split("/"))
            return canonical
    return "coordinate:" + json.dumps([component_type.lower(), group.strip().lower(), name.strip().lower()], ensure_ascii=False, separators=(",", ":"))


def library_key(coordinate: str) -> str:
    return base64.urlsafe_b64encode(coordinate.encode()).decode().rstrip("=")


def _coordinate(key: str) -> str:
    try:
        value = base64.b64decode(key + "=" * (-len(key) % 4), altchars=b"-_", validate=True).decode()
        if not value.startswith(("pkg:", "coordinate:")) or len(value) > 4096:
            raise ValueError
        if value.startswith("coordinate:"):
            parts = json.loads(value[len("coordinate:"):])
            if not isinstance(parts, list) or len(parts) != 3 or not all(isinstance(part, str) for part in parts):
                raise ValueError
        return value
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(422, "라이브러리 식별자가 올바르지 않습니다") from exc


def _latest_runs(db: Session, environment_id: str | None = None) -> set[str]:
    query = select(SbomRun.id, func.row_number().over(
        partition_by=(Release.service_id, Release.environment_id),
        order_by=(SbomRun.created_at.desc(), SbomRun.id.desc()),
    ).label("position")).join(Release).where(
        SbomRun.state == ProcessingState.COMPLETED, SbomRun.archived_at.is_(None),
    )
    if environment_id:
        query = query.where(Release.environment_id == environment_id)
    ranked = query.subquery()
    return set(db.scalars(select(ranked.c.id).where(ranked.c.position == 1)))


def _rows(db: Session, *, environment_id: str | None = None, q: str = "", version: str = "", alternate_hints: tuple[str, ...] = ()):
    query = select(
        RunComponent.name, RunComponent.group_name, RunComponent.component_type, RunComponent.purl,
        RunComponent.version, RunComponent.identity_status, RunComponent.bom_ref,
        SbomRun.id.label("run_id"), SbomRun.created_at, SbomRun.round_number, SbomRun.state,
        SbomRun.archived_at, Release.version.label("release_version"),
        Service.id.label("service_id"), Service.name.label("service_name"),
        Environment.id.label("environment_id"), Environment.name.label("environment_name"),
    ).join(SbomRun, RunComponent.run_id == SbomRun.id).join(Release).join(Service).join(Environment)
    if environment_id:
        query = query.where(Environment.id == environment_id)
    hints = {hint for hint in (q, *alternate_hints) if hint}
    if hints:
        conditions = []
        for hint in hints:
            pattern = "%" + hint.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conditions.extend((RunComponent.name.ilike(pattern, escape="\\"), RunComponent.purl.ilike(pattern, escape="\\"), RunComponent.identity_key.ilike(pattern, escape="\\")))
        query = query.where(or_(*conditions))
    if version:
        query = query.where(RunComponent.version == version)
    return db.execute(query.execution_options(yield_per=1000)).mappings()


def _ecosystem(coordinate: str) -> str:
    return coordinate[4:].split("/", 1)[0] if coordinate.startswith("pkg:") else "unidentified"


def _observation(row, current: set[str]) -> dict:
    return {
        "name": row["name"], "runId": row["run_id"], "at": iso(row["created_at"]), "roundNumber": row["round_number"],
        "service": {"id": row["service_id"], "name": row["service_name"]},
        "environment": {"id": row["environment_id"], "name": row["environment_name"]},
        "releaseVersion": row["release_version"], "libraryVersion": row["version"],
        "purl": row["purl"], "bomRef": row["bom_ref"], "state": row["state"].value,
        "current": row["run_id"] in current, "archived": row["archived_at"] is not None or row["state"] == ProcessingState.ARCHIVED,
        "identityStatus": row["identity_status"] if row["purl"].startswith("pkg:") else "review_required",
    }


@router.get("")
def list_libraries(
    q: str = Query("", max_length=200), environmentId: str | None = None,
    ecosystem: str = Query("", max_length=64), version: str = Query("", max_length=255),
    page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db), _=Depends(require_permission("runs.view")),
):
    current = _latest_runs(db, environmentId)
    groups: dict[str, dict] = {}
    ecosystems: set[str] = set()
    for row in _rows(db, environment_id=environmentId, q=q.strip(), version=version.strip()):
        coordinate = package_coordinate(row["purl"], row["component_type"], row["group_name"], row["name"])
        kind = _ecosystem(coordinate)
        ecosystems.add(kind)
        if ecosystem and ecosystem != kind:
            continue
        item = groups.setdefault(coordinate, {"key": library_key(coordinate), "coordinate": coordinate,
            "name": row["name"], "ecosystem": kind, "versions": set(), "services": set(), "environments": {},
            "currentServices": set(), "currentEnvironments": set(), "currentVersions": set(), "lastObservedAt": "", "observationCount": 0})
        item["versions"].add(row["version"])
        item["services"].add(row["service_id"])
        item["environments"][row["environment_id"]] = row["environment_name"]
        item["lastObservedAt"] = max(item["lastObservedAt"], iso(row["created_at"]) or "")
        item["observationCount"] += 1
        if row["run_id"] in current:
            item["currentServices"].add(row["service_id"])
            item["currentEnvironments"].add(row["environment_id"])
            item["currentVersions"].add(row["version"])
    ordered = sorted(groups.values(), key=lambda item: (item["name"].casefold(), item["coordinate"]))
    items = []
    for item in ordered[(page - 1) * size:page * size]:
        items.append({**item, "versions": sorted(item["versions"]), "serviceCount": len(item["services"]),
            "services": None, "environments": [{"id": key, "name": value} for key, value in sorted(item["environments"].items())],
            "currentServiceCount": len(item["currentServices"]), "currentEnvironmentCount": len(item["currentEnvironments"]),
            "currentServices": None, "currentEnvironments": None, "currentVersions": sorted(item["currentVersions"])})
    return {"items": items, "total": len(ordered), "page": page, "size": size,
        "basis": "latest_completed_sbom_per_service_environment",
        "filters": {"ecosystems": sorted(ecosystems), "environments": [{"id": value.id, "name": value.name} for value in db.scalars(select(Environment).order_by(Environment.sort_order, Environment.name))]}}


def _global_complete(compositions) -> bool:
    # A scoped composition cannot prove that an absent package was removed from
    # the whole service. Unspecified or incomplete inventories remain unknown.
    return isinstance(compositions, list) and any(isinstance(value, dict) and value.get("aggregate") == "complete"
        and not any(value.get(field) for field in ("assemblies", "dependencies", "vulnerabilities")) for value in compositions)


@router.get("/detail")
def library_detail(
    key: str = Query(min_length=1, max_length=6000), environmentId: str | None = None,
    page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db), _=Depends(require_permission("runs.view")),
):
    coordinate = _coordinate(key)
    current = _latest_runs(db, environmentId)
    matches = []
    # Narrow by package name before canonical comparison; no original SBOM JSON
    # or analysis documents are materialized during package lookup.
    name_hint = unquote(coordinate.split("?", 1)[0].split("#", 1)[0].rsplit("/", 1)[-1]) if coordinate.startswith("pkg:") else json.loads(coordinate[len("coordinate:"):])[-1]
    # PyPI treats runs of -, _ and . as equivalent. A literal canonical name
    # would miss an original PURL such as Foo_Bar when its key is foo-bar.
    lookup_hint = re.split(r"[-_.]+", name_hint)[0] if coordinate.startswith("pkg:pypi/") else name_hint
    encoded_hint = coordinate.split("?", 1)[0].split("#", 1)[0].rsplit("/", 1)[-1] if coordinate.startswith("pkg:") else ""
    for row in _rows(db, environment_id=environmentId, q=lookup_hint, alternate_hints=(encoded_hint,)):
        if package_coordinate(row["purl"], row["component_type"], row["group_name"], row["name"]) == coordinate:
            matches.append(_observation(row, current))
    if not matches:
        raise HTTPException(404, "라이브러리 관측 기록을 찾을 수 없습니다")
    matches.sort(key=lambda item: (item["at"], item["runId"], item["libraryVersion"]), reverse=True)
    by_run: dict[str, set[str]] = defaultdict(set)
    names_by_run: dict[str, set[str]] = defaultdict(set)
    scopes: set[tuple[str, str]] = set()
    for item in matches:
        by_run[item["runId"]].add(item["libraryVersion"])
        names_by_run[item["runId"]].add(item["name"])
        scopes.add((item["service"]["id"], item["environment"]["id"]))
    from sqlalchemy import and_
    run_query = select(SbomRun.id, SbomRun.created_at, SbomRun.state, SbomRun.archived_at,
        SbomRun.round_number, SbomRun.normalized_bom["compositions"].label("compositions"),
        Release.version.label("release_version"), Service.id.label("service_id"), Service.name.label("service_name"),
        Environment.id.label("environment_id"), Environment.name.label("environment_name"),
    ).select_from(SbomRun).join(Release, SbomRun.release_id == Release.id).join(Service, Release.service_id == Service.id).join(Environment, Release.environment_id == Environment.id).where(or_(*[and_(Release.service_id == service, Release.environment_id == env) for service, env in scopes]))
    previous: dict[tuple[str, str], dict] = {}
    seen: set[tuple[str, str]] = set()
    events = []
    for row in db.execute(run_query.order_by(SbomRun.created_at, SbomRun.id).execution_options(yield_per=1000)).mappings():
        scope = (row["service_id"], row["environment_id"])
        versions = sorted(by_run.get(row["id"], ()))
        reliable = row["state"] == ProcessingState.COMPLETED and row["archived_at"] is None
        prior = previous.get(scope)
        if versions:
            kind = "first_seen" if scope not in seen else "reappeared" if prior and not prior["versions"] else "version_changed" if prior and prior["versions"] != versions else "observed"
            seen.add(scope)
        elif reliable and _global_complete(row["compositions"]) and prior and prior["versions"]:
            kind = "removed"
        else:
            continue
        events.append({"kind": kind, "runId": row["id"], "at": iso(row["created_at"]),
            "service": {"id": scope[0], "name": row["service_name"]},
            "environment": {"id": scope[1], "name": row["environment_name"]},
            "releaseVersion": row["release_version"], "roundNumber": row["round_number"],
            "versions": versions, "previousVersions": prior["versions"] if prior else [],
            "previousRunId": prior["runId"] if prior else None, "reliable": reliable})
        if reliable:
            previous[scope] = {"versions": versions, "runId": row["id"]}
    events.reverse()
    related = []
    run_ids = list(by_run)
    related_truncated = len(run_ids) > RELATED_RUN_LIMIT
    related_limit_reached = False
    related_run_ids = run_ids[:RELATED_RUN_LIMIT]
    for offset in range(0, len(related_run_ids), 500):
        latest_analysis = select(AnalysisRevision.id, func.row_number().over(partition_by=AnalysisRevision.run_id, order_by=AnalysisRevision.sequence.desc()).label("position")).where(AnalysisRevision.run_id.in_(related_run_ids[offset:offset + 500]), AnalysisRevision.state == JobState.COMPLETED).subquery()
        reanalysis_pending = select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id == SbomRun.id).exists()
        query = select(AnalysisRevision.id, AnalysisRevision.run_id, AnalysisRevision.findings, AnalysisRevision.data_as_of,
            SbomRun.analysis_state, reanalysis_pending.label("reanalysis_pending"),
        ).select_from(AnalysisRevision).join(latest_analysis, latest_analysis.c.id == AnalysisRevision.id).join(SbomRun, SbomRun.id == AnalysisRevision.run_id).where(latest_analysis.c.position == 1)
        for analysis in db.execute(query.order_by(SbomRun.created_at.desc(), SbomRun.id.desc()).execution_options(yield_per=20)).mappings():
            analysis_current = analysis["analysis_state"] == JobState.COMPLETED and not analysis["reanalysis_pending"]
            component_names = {name_hint, coordinate, *names_by_run[analysis["run_id"]]}
            for finding in analysis["findings"] or []:
                if not isinstance(finding, dict):
                    continue
                artifact = finding.get("artifact") if isinstance(finding.get("artifact"), dict) else {}
                component = str(finding.get("component") or artifact.get("name") or "")
                purl = str(finding.get("purl") or artifact.get("purl") or (component if component.startswith("pkg:") else ""))
                # Prefer PURL evidence. A bare same-name match is marked for review.
                exact = bool(purl and package_coordinate(purl) == coordinate)
                if exact or (not purl and component in component_names):
                    if len(related) >= RELATED_RECORD_LIMIT:
                        related_limit_reached = related_truncated = True
                        break
                    related.append({"id": str(finding.get("canonicalId") or finding.get("id") or "unknown"),
                        "severity": str(finding.get("severity") or "unknown"), "runId": analysis["run_id"],
                        "analysisId": analysis["id"], "dataAsOf": analysis["data_as_of"],
                        "matchBasis": "purl" if exact else "name_review_required", "current": analysis["run_id"] in current and analysis_current,
                        "analysisCurrent": analysis_current, "evaluationState": "completed" if analysis_current else "reanalysis_required"})
            if related_limit_reached:
                break
        if related_limit_reached:
            break
    return {"key": key, "coordinate": coordinate, "name": matches[0]["name"],
        "ecosystem": _ecosystem(coordinate), "observations": [item for item in matches if item["current"]],
        "observationsTotal": len(matches), "historicalObservations": matches[(page - 1) * size:page * size],
        "history": {"items": events[(page - 1) * size:page * size], "total": len(events), "page": page, "size": size},
        "vulnerabilities": related, "vulnerabilitiesTruncated": related_truncated,
        "vulnerabilityCoverage": {"runLimit": RELATED_RUN_LIMIT, "recordLimit": RELATED_RECORD_LIMIT, "matchingRuns": len(run_ids), "runsInScope": len(related_run_ids)},
        "basis": "latest_completed_sbom_per_service_environment",
        "notice": "최신 완료 SBOM 관측 기준입니다. 미수집·불완전 SBOM의 부재를 제거로 판단하지 않습니다."}
