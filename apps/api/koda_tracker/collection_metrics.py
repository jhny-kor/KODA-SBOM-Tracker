"""Live collection rollups over immutable completed native analysis evidence.

Collection nodes contribute no own SBOM. Direct-child modes recursively respect
nested collection configuration; the explicit descendant mode selects all active
ordinary descendants. Occurrence counts sum across projects, unique IDs do not.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from enum import Enum
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import AnalysisRevision, JobState, Release, SbomRun, now
from .project_catalog_models import NativeCollectionConfig, NativeProject, NativeReanalysisPending, ProjectRunLink
from .vulnerability import project_cve_findings


class CollectionLogic(str, Enum):
    NONE = "NONE"
    AGGREGATE_DIRECT_CHILDREN = "AGGREGATE_DIRECT_CHILDREN"
    AGGREGATE_DIRECT_CHILDREN_WITH_TAG = "AGGREGATE_DIRECT_CHILDREN_WITH_TAG"
    AGGREGATE_LATEST_VERSION_CHILDREN = "AGGREGATE_LATEST_VERSION_CHILDREN"
    AGGREGATE_ALL_DESCENDANTS = "AGGREGATE_ALL_DESCENDANTS"


def configure_collection(project: NativeProject, logic: str, tag: str | None) -> None:
    logic = CollectionLogic(logic).value
    tag = tag.strip() if isinstance(tag, str) else None
    if tag and len(tag) > 255:
        raise ValueError("Collection 태그는 최대 255자입니다")
    if logic == CollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG and not tag:
        raise ValueError("태그 Collection에는 집계할 태그가 필요합니다")
    if logic != CollectionLogic.AGGREGATE_DIRECT_CHILDREN_WITH_TAG:
        tag = None
    if project.collection_config is None:
        project.collection_config = NativeCollectionConfig(logic=logic, tag=tag)
    else:
        project.collection_config.logic, project.collection_config.tag = logic, tag


def collection_config(project: NativeProject) -> dict:
    config = project.collection_config
    return {"collectionLogic": config.logic if config else "NONE", "collectionTag": config.tag if config else None}


def collection_metrics(db: Session, root: NativeProject) -> dict:
    nodes = list(db.scalars(select(NativeProject).where(NativeProject.source_id == root.source_id).limit(10001)))
    if len(nodes) > 10000:
        raise ValueError("Collection 원본 범위가 10,000개 프로젝트 제한을 초과했습니다")
    children = defaultdict(list)
    for node in nodes:
        children[node.parent_project_id].append(node)
    selected: dict[str, NativeProject] = {}

    stack = [(root, frozenset(), False)]
    while stack:
        node, path, all_descendants = stack.pop()
        if node.id in path or len(path) >= 1000:
            raise ValueError("Collection 계층에 순환 또는 과도한 깊이가 있습니다")
        if not node.active:
            continue
        config = collection_config(node)
        logic = config["collectionLogic"]
        if node.id != root.id and logic == "NONE":
            selected[node.id] = node
            if not all_descendants:
                continue
        if logic == "NONE" and node.id == root.id:
            selected[node.id] = node
            continue
        all_descendants = all_descendants or logic == "AGGREGATE_ALL_DESCENDANTS"
        for child in sorted(children[node.source_project_id], key=lambda p: p.id):
            if not all_descendants:
                if logic == "AGGREGATE_DIRECT_CHILDREN_WITH_TAG" and config["collectionTag"] not in (child.tags or []):
                    continue
                if logic == "AGGREGATE_LATEST_VERSION_CHILDREN" and not child.is_latest:
                    continue
            stack.append((child, path | {node.id}, all_descendants))
    project_ids = set(selected)
    linked = list(db.execute(select(ProjectRunLink.project_id, SbomRun).join(SbomRun, SbomRun.id == ProjectRunLink.run_id).where(ProjectRunLink.project_id.in_(project_ids), SbomRun.archived_at.is_(None)))) if project_ids else []
    candidates = defaultdict(dict)
    for project_id, run in linked:
        candidates[project_id][run.id] = run
    # Ordinary uploads inherit a catalog release only when it is unambiguous,
    # matching project_for_run rather than relying on a stale currentRunId.
    service_ids = {node.service_id for node in selected.values()}
    # Uniqueness must include every source, exactly as project_for_run does.
    # Count in SQL so other catalogs' project rows and IDs need not be exposed.
    coordinate_projects = {}
    if service_ids:
        coordinates = db.execute(select(
            NativeProject.service_id, NativeProject.environment_id, NativeProject.version,
            func.count(NativeProject.id), func.min(NativeProject.id),
        ).where(NativeProject.service_id.in_(service_ids)).group_by(
            NativeProject.service_id, NativeProject.environment_id, NativeProject.version,
        ))
        coordinate_projects = {(service, environment, version): (count, owner)
                               for service, environment, version, count, owner in coordinates}
    selected_coordinates = defaultdict(list)
    for node in selected.values():
        selected_coordinates[(node.service_id, node.environment_id, node.version)].append(node.id)
    ambiguous_projects = set()
    inherited = db.execute(select(Release, SbomRun).join(SbomRun, SbomRun.release_id == Release.id).where(Release.service_id.in_(service_ids), SbomRun.archived_at.is_(None))) if service_ids else []
    for release, run in inherited:
        # Explicit ownership was collected above, and must never be replaced by
        # coordinate inheritance, even when it belongs to another source.
        if db.get(ProjectRunLink, run.id) is not None:
            continue
        coordinate = (release.service_id, release.environment_id, release.version)
        count, owner = coordinate_projects.get(coordinate, (0, None))
        if count == 1 and owner in selected:
            candidates[owner][run.id] = run
        elif count > 1:
            ambiguous_projects.update(selected_coordinates[coordinate])
    newest = {pid: max(runs.values(), key=lambda r: (r.created_at, r.round_number, r.id)) for pid, runs in candidates.items()}
    run_ids = [run.id for run in newest.values()]
    analyses = defaultdict(list)
    for revision in db.scalars(select(AnalysisRevision).where(AnalysisRevision.run_id.in_(run_ids))):
        analyses[revision.run_id].append(revision)
    pending = set(db.scalars(select(NativeReanalysisPending.run_id).where(NativeReanalysisPending.run_id.in_(run_ids))))
    totals = Counter({k: 0 for k in ("componentCount", "vulnerabilityCount", "vulnerableComponentCount", "kevCount", "policyViolationCount", "suppressedVulnerabilityCount", "rawVulnerabilityCount", "policyFailCount", "policyWarnCount", "policyInfoCount", "policySuppressedCount")})
    severities, unique_ids, seen_runs = Counter(), set(), set()
    rows, analyzed, missing, stale, policy_incomplete, ambiguous = [], 0, 0, 0, 0, 0
    for project in sorted(selected.values(), key=lambda p: (p.name, p.version, p.id)):
        run = newest.get(project.id)
        completed = [a for a in analyses[run.id] if a.state == JobState.COMPLETED] if run else []
        revision = max(completed, key=lambda a: a.sequence, default=None)
        latest = max(analyses[run.id], key=lambda a: a.sequence, default=None) if run else None
        unresolved = run is None and project.id in ambiguous_projects
        state = "ambiguous" if unresolved else "missing"
        ambiguous += unresolved
        metrics = None
        if revision:
            state = "stale" if run.id in pending or run.analysis_state != JobState.COMPLETED or revision != latest else "completed"
            analyzed += 1
            stale += state == "stale"
            policy_incomplete += revision.policy_state != "completed" or (revision.metrics or {}).get("policyDataComplete") is False
            findings = project_cve_findings(revision.findings or [])
            active = [f for f in findings if not (f.get("vex") or {}).get("suppressed")]
            severity = Counter(str(f.get("severity") or "unknown").lower() for f in active)
            severity = Counter({k: sum(v for s, v in severity.items() if (s if s in {"critical", "high", "medium", "low", "info"} else "unknown") == k) for k in {"critical", "high", "medium", "low", "info", "unknown"}})
            metrics = {"componentCount": len(run.components), "vulnerabilityCount": len(active), "vulnerableComponentCount": len({(f.get("component"), f.get("version")) for f in active}), "kevCount": sum(f.get("kev") is True for f in active), "policyViolationCount": sum(not p.get("suppressed", False) for p in revision.policies or []), "suppressedVulnerabilityCount": len(findings) - len(active), "severityCounts": dict(severity)}
            metrics.update({"rawVulnerabilityCount": len(findings), "policySuppressedCount": sum(p.get("suppressed", False) for p in revision.policies or [])})
            for action in ("fail", "warn", "info"):
                metrics["policy" + action.title() + "Count"] = sum(not p.get("suppressed", False) and p.get("action") == action for p in revision.policies or [])
            # Defensive deduplication if old imported catalog data shares a run.
            if run.id not in seen_runs:
                totals.update({k: v for k, v in metrics.items() if k != "severityCounts"})
                severities.update(severity)
                unique_ids.update(str(f.get("canonicalId") or f.get("id")) for f in active)
                seen_runs.add(run.id)
        else:
            missing += 1
            if run:
                state = run.analysis_state.value
        rows.append({"projectId": project.id, "name": project.name, "version": project.version, "runId": run.id if run else None, "analysisId": revision.id if revision else None, "analysisSequence": revision.sequence if revision else None, "state": state, "policyState": revision.policy_state if revision else "not_evaluated", "metrics": metrics})
    return {"projectId": root.id, **collection_config(root), "generatedAt": now().isoformat(), "coverage": {"selectedProjectCount": len(selected), "analyzedProjectCount": analyzed, "missingProjectCount": missing, "staleProjectCount": stale, "policyIncompleteProjectCount": policy_incomplete, "ambiguousProjectCount": ambiguous, "complete": not (missing or stale or policy_incomplete or ambiguous)}, "totals": {**dict(totals), "severityCounts": dict(severities), "uniqueVulnerabilityCount": len(unique_ids)}, "projects": rows}
