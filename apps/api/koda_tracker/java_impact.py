"""Evidence-based Maven impact review against an explicitly registered deployment."""
from collections import defaultdict, deque
from datetime import datetime
import re

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from .db import Base, get_db
from .library_api import package_coordinate
from .external_api import read_token, require_run, router as external_router
from .models import AnalysisRevision, Environment, JobState, ProcessingState, Release, RunComponent, SbomRun, Service, new_id, now
from .security import require_csrf, require_permission, environment_scope, require_run_scope
from .services import audit
from .version_ordering import MavenVersion

router = APIRouter(prefix="/api/v1/java-impact", tags=["Java upgrade review"])
_view = require_permission("runs.view")
_manage = require_permission("catalog.manage")
_MAVEN = re.compile(r"pkg:maven/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_MAX_DEPLOYMENTS = 100
_MAX_EDGES = 200_000


class JavaDeployment(Base):
    __tablename__ = "java_deployments"
    __table_args__ = (UniqueConstraint("service_id", "environment_id", "target"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    service_id: Mapped[str] = mapped_column(ForeignKey("services.id"))
    environment_id: Mapped[str] = mapped_column(ForeignKey("environments.id"))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("sbom_runs.id", ondelete="SET NULL"))
    target: Mapped[str] = mapped_column(String(128))
    java_major: Mapped[int] = mapped_column()
    os: Mapped[str] = mapped_column(String(128))
    architecture: Mapped[str] = mapped_column(String(64))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    service: Mapped[Service] = relationship(lazy="selectin")
    environment: Mapped[Environment] = relationship(lazy="selectin")


class DeploymentRequest(BaseModel):
    runId: str
    target: str = Field(min_length=1, max_length=128, pattern=r"^\S(?:.*\S)?$")
    javaMajor: int = Field(ge=6, le=99)
    os: str = Field(min_length=1, max_length=128, pattern=r"^\S(?:.*\S)?$")
    architecture: str = Field(min_length=1, max_length=64, pattern=r"^\S(?:.*\S)?$")


class AssessmentRequest(BaseModel):
    deploymentId: str
    coordinate: str = Field(min_length=1, max_length=512)
    candidateVersion: str | None = Field(default=None, min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.+-]+$")
    candidateRunId: str | None = None
    minimumJavaMajor: int | None = Field(default=None, ge=6, le=99)
    requirementEvidence: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def check_inputs(self):
        if not _MAVEN.fullmatch(self.coordinate):
            raise ValueError("Maven PURL은 pkg:maven/group/artifact 형식이어야 합니다")
        if bool(self.candidateVersion) == bool(self.candidateRunId):
            raise ValueError("후보 버전 또는 후보 SBOM 중 하나를 지정하세요")
        if self.minimumJavaMajor and not (self.requirementEvidence or "").strip():
            raise ValueError("최소 Java 버전의 근거를 입력하세요")
        return self


def _completed(db: Session, run_id: str | None):
    run = db.get(SbomRun, run_id) if run_id else None
    if not run or run.state != ProcessingState.COMPLETED or run.archived_at is not None:
        raise HTTPException(409, "보관되지 않은 완료 SBOM 회차를 지정하세요")
    return run


def _deployment_info(d):
    return {"id": d.id, "serviceId": d.service_id, "environmentId": d.environment_id, "runId": d.run_id,
            "serviceName": d.service.name, "environmentName": d.environment.name, "target": d.target, "javaMajor": d.java_major, "os": d.os, "architecture": d.architecture,
            "recordedAt": d.recorded_at, "basis": "operator_registered"}


def _registered_deployments():
    return select(JavaDeployment).join(Environment, Environment.id == JavaDeployment.environment_id).join(
        SbomRun, SbomRun.id == JavaDeployment.run_id).join(Release, Release.id == SbomRun.release_id).where(
        Release.service_id == JavaDeployment.service_id, Release.environment_id == JavaDeployment.environment_id,
        Environment.active.is_(True), SbomRun.state == ProcessingState.COMPLETED, SbomRun.archived_at.is_(None))


@router.get("/deployments", dependencies=[Depends(_view)])
def deployments(serviceId: str | None = None, db: Session = Depends(get_db), principal=Depends(_view)):
    q = _registered_deployments().where(environment_scope(principal, Release.environment_id))
    if serviceId:
        q = q.where(JavaDeployment.service_id == serviceId)
    rows = list(db.scalars(q.order_by(JavaDeployment.recorded_at.desc(), JavaDeployment.id).limit(_MAX_DEPLOYMENTS + 1)))
    return {"items": [_deployment_info(d) for d in rows[:_MAX_DEPLOYMENTS]], "truncated": len(rows) > _MAX_DEPLOYMENTS}


@router.put("/deployments", dependencies=[Depends(_manage), Depends(require_csrf)])
def register_deployment(body: DeploymentRequest, db: Session = Depends(get_db), user=Depends(_manage)):
    require_run_scope(db, user, body.runId)
    run = _completed(db, body.runId)
    release = run.release
    if not release.environment.active:
        raise HTTPException(409, "활성 환경의 SBOM 회차를 지정하세요")
    # Serialize updates for the same service on PostgreSQL; SQLite also has the unique key.
    db.execute(select(Service.id).where(Service.id == release.service_id).with_for_update()).scalar_one()
    d = db.scalar(select(JavaDeployment).where(JavaDeployment.service_id == release.service_id,
                    JavaDeployment.environment_id == release.environment_id, JavaDeployment.target == body.target))
    if d is None:
        d = JavaDeployment(service_id=release.service_id, environment_id=release.environment_id, target=body.target)
        db.add(d)
    d.run_id, d.java_major, d.os, d.architecture = run.id, body.javaMajor, body.os.strip(), body.architecture.strip()
    d.recorded_at = now()
    db.flush()
    audit(db, user.username, "java_deployment.register", "java_deployment", d.id, {"runId": run.id})
    db.commit()
    return _deployment_info(d)


@router.delete("/deployments/{deployment_id}", dependencies=[Depends(_manage), Depends(require_csrf)])
def delete_deployment(deployment_id: str, db: Session = Depends(get_db), user=Depends(_manage)):
    d = db.get(JavaDeployment, deployment_id)
    if not d or not d.run_id:
        raise HTTPException(404, "배포 기준을 찾을 수 없습니다")
    require_run_scope(db, user, d.run_id)
    audit(db, user.username, "java_deployment.delete", "java_deployment", d.id, {})
    db.delete(d)
    db.commit()
    return {"deleted": True}


@router.get("/candidates", dependencies=[Depends(_view)])
def candidates(serviceId: str, db: Session = Depends(get_db), principal=Depends(_view)):
    q = select(SbomRun).join(Release).join(Environment).where(
        Release.service_id == serviceId, Environment.active.is_(True), SbomRun.state == ProcessingState.COMPLETED,
        SbomRun.archived_at.is_(None), environment_scope(principal, Release.environment_id),
    ).order_by(SbomRun.created_at.desc(), SbomRun.id).limit(101)
    runs = list(db.scalars(q))
    return {"items": [{"runId": run.id, "releaseVersion": run.release.version, "roundNumber": run.round_number,
                       "environment": run.release.environment.name, "observedAt": run.created_at} for run in runs[:100]],
            "truncated": len(runs) > 100}


def dependency_paths(bom, refs):
    """Return one shortest observed path per package occurrence, not inferred edges."""
    bom = bom or {}
    root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    graph = bom.get("dependencies")
    if not root or not isinstance(graph, list):
        return [], "unknown"
    edges = defaultdict(set)
    edge_count = 0
    for entry in graph:
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            continue
        children = entry.get("dependsOn")
        if not isinstance(children, list):
            continue
        edge_count += len(children)
        if edge_count > _MAX_EDGES:
            return [], "limit_reached"
        for child in children:
            if isinstance(child, str):
                edges[entry["ref"]].add(child)
    queue = deque([(root,)])
    # Walk forward from root. A visited node is sufficient for one shortest path.
    visited = {root}
    targets = set(refs) - {""}
    paths = []
    while queue and targets:
        path = queue.popleft()
        if path[-1] in targets:
            paths.append(path)
            targets.remove(path[-1])
        if len(path) >= 40:
            continue
        for child in sorted(edges[path[-1]] - visited):
            visited.add(child)
            queue.append((*path, child))
    return paths, "observed_paths" if paths and not targets else "partial" if paths else "unknown"


def _maven_coordinate(purl: str) -> str:
    # Compare Maven group/artifact across versions and packaged variants such as type=jar.
    return package_coordinate(purl).partition("?")[0].partition("#")[0]


def _versions(db, run_id, coordinate):
    rows = db.scalars(select(RunComponent).where(
        RunComponent.run_id == run_id, RunComponent.purl.startswith(coordinate, autoescape=True)))
    return sorted({r.version for r in rows if r.version and _maven_coordinate(r.purl) == coordinate}, key=MavenVersion)


def _component_version_changes(base, candidate):
    def versions(run):
        groups = defaultdict(set)
        names = {}
        for part in run.components:
            key = package_coordinate(part.purl) if part.purl.startswith("pkg:") else part.identity_key
            groups[key].add(part.version)
            names[key] = part.name
        return groups, names

    left, left_names = versions(base)
    right, right_names = versions(candidate)
    changes = []
    for key in sorted(left.keys() | right.keys()):
        before, after = left.get(key, set()), right.get(key, set())
        if before != after:
            changes.append({
                "identityKey": key, "name": right_names.get(key) or left_names[key],
                "baseVersions": sorted(before), "targetVersions": sorted(after),
            })
    return changes


def _compare_cves(db: Session, base, candidate):
    if candidate is None:
        return {"status": "not_comparable", "reason": "candidate_sbom_required"}
    revisions = []
    for run in (base, candidate):
        revision = db.scalar(select(AnalysisRevision).where(
            AnalysisRevision.run_id == run.id, AnalysisRevision.state == JobState.COMPLETED,
        ).order_by(AnalysisRevision.sequence.desc()).limit(1))
        if not revision:
            return {"status": "not_comparable", "reason": "completed_revisions_required"}
        revisions.append(revision)
    left, right = revisions
    sources = [(r.data_sources or {}) for r in revisions]
    digest = sources[0].get("bundleManifestSha256")
    if (not digest or digest != sources[1].get("bundleManifestSha256")
            or left.tool_version in {"", "unknown", "grype"} or left.tool_version != right.tool_version
            or not sources[0].get("sbomNormalization") or sources[0].get("sbomNormalization") != sources[1].get("sbomNormalization")
            or any((src.get("vulnerabilityDataStatus") or {}).get("status") == "unavailable" for src in sources)):
        return {"status": "not_comparable", "reason": "same_dataset_and_scanner_required"}

    def cve_ids(revision):
        ids = {str(row.get("canonicalId") or row.get("id") or "").upper() for row in revision.findings or []
               if isinstance(row, dict) and row.get("sourceKind") != "private_vulnerability"}
        return {identifier for identifier in ids if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,16}", identifier)}

    before, after = cve_ids(left), cve_ids(right)
    added, removed = sorted(after - before), sorted(before - after)
    return {"status": "compared", "added": added[:100], "removed": removed[:100],
            "addedCount": len(added), "removedCount": len(removed),
            "baseAnalysisId": left.id, "candidateAnalysisId": right.id, "datasetSha256": digest}


@router.post("/assessments", dependencies=[Depends(_view), Depends(require_csrf)])
def assess(body: AssessmentRequest, db: Session = Depends(get_db), principal=Depends(_view)):
    return _assess(body, db, principal=principal)


@external_router.post("/upgrade-assessments")
def external_assess(body: AssessmentRequest, db: Session = Depends(get_db), token=Depends(read_token)):
    return _assess(body, db, token)


def _assess(body: AssessmentRequest, db: Session, token=None, *, principal=None):
    d = db.get(JavaDeployment, body.deploymentId)
    if d is None:
        raise HTTPException(404, "배포 기준을 찾을 수 없습니다")
    if token:
        if (d.service_id != token.service_id or
                (token.environment_id and d.environment_id != token.environment_id) or not d.run_id):
            raise HTTPException(404, "배포 기준을 찾을 수 없습니다")
        require_run(db, token, d.run_id)
        if body.candidateRunId:
            require_run(db, token, body.candidateRunId)
    if d.run_id:
        require_run_scope(db, principal, d.run_id)
    if body.candidateRunId:
        require_run_scope(db, principal, body.candidateRunId)
    base = _completed(db, d.run_id)
    if (base.release.service_id, base.release.environment_id) != (d.service_id, d.environment_id):
        raise HTTPException(409, "SBOM의 서비스·환경이 바뀌었습니다. 배포 기준을 다시 등록하세요")
    base_parts = [r for r in base.components if _maven_coordinate(r.purl) == body.coordinate]
    if not base_parts:
        raise HTTPException(422, "배포 기준 SBOM에서 해당 Maven 좌표를 찾을 수 없습니다")
    current = sorted({r.version for r in base_parts if r.version}, key=MavenVersion)
    candidate = _completed(db, body.candidateRunId) if body.candidateRunId else None
    if candidate and (candidate.release.service_id != d.service_id or candidate.id == base.id):
        raise HTTPException(422, "동일 서비스의 다른 완료 회차를 후보로 지정하세요")
    versions = _versions(db, candidate.id, body.coordinate) if candidate else [body.candidateVersion]
    if not versions:
        raise HTTPException(422, "후보 SBOM에서 해당 Maven 좌표와 버전을 확인할 수 없습니다")
    conflict = body.minimumJavaMajor is not None and d.java_major < body.minimumJavaMajor
    paths, coverage = dependency_paths(base.normalized_bom, {p.bom_ref for p in base_parts})
    q = select(JavaDeployment, RunComponent.version).join(RunComponent, RunComponent.run_id == JavaDeployment.run_id).join(
        SbomRun, SbomRun.id == JavaDeployment.run_id).join(Release, Release.id == SbomRun.release_id).where(
        Release.service_id == JavaDeployment.service_id, Release.environment_id == JavaDeployment.environment_id,
        RunComponent.purl.startswith(body.coordinate, autoescape=True),
        SbomRun.state == ProcessingState.COMPLETED, SbomRun.archived_at.is_(None),
    ).add_columns(RunComponent.purl).order_by(JavaDeployment.id, RunComponent.id)
    if token:
        q = q.join(Environment, Environment.id == JavaDeployment.environment_id).where(
            JavaDeployment.service_id == token.service_id, Environment.active.is_(True))
        if token.environment_id:
            q = q.where(JavaDeployment.environment_id == token.environment_id)
    q = q.where(environment_scope(principal, Release.environment_id))
    affected = {}
    rows = db.execute(q.limit(1001)).all()
    for deployment, version, purl in rows[:1000]:
        if _maven_coordinate(purl) == body.coordinate:
            item = affected.setdefault(deployment.id, {**_deployment_info(deployment), "observedVersions": set()})
            item["observedVersions"].add(version)
    for item in affected.values():
        item["observedVersions"] = sorted(item["observedVersions"], key=MavenVersion)
    changes = _component_version_changes(base, candidate) if candidate else None
    return {"status": "declared_conflict" if conflict else "needs_verification",
            "deployment": _deployment_info(d), "coordinate": body.coordinate, "currentVersions": current,
            "candidateVersions": versions, "candidateRunId": candidate.id if candidate else None,
            "minimumJavaMajor": body.minimumJavaMajor, "requirementEvidence": body.requirementEvidence,
            "dependencyPaths": paths[:25], "pathsTruncated": len(paths) > 25, "graphCoverage": coverage,
            "affectedDeployments": list(affected.values())[:_MAX_DEPLOYMENTS],
            "affectedTruncated": len(rows) > 1000 or len(affected) > _MAX_DEPLOYMENTS,
            "componentChanges": changes[:100] if changes is not None else None,
            "componentChangeCount": len(changes) if changes is not None else None,
            "vulnerabilityComparison": _compare_cves(db, base, candidate),
            "runtimeTest": "not_run"}


@external_router.get("/java-deployments")
def external_deployments(db: Session = Depends(get_db), token=Depends(read_token)):
    query = _registered_deployments().where(JavaDeployment.service_id == token.service_id)
    if token.environment_id:
        query = query.where(JavaDeployment.environment_id == token.environment_id)
    rows = list(db.scalars(query.order_by(JavaDeployment.recorded_at.desc(), JavaDeployment.id).limit(_MAX_DEPLOYMENTS + 1)))
    return {"items": [_deployment_info(d) for d in rows[:_MAX_DEPLOYMENTS]], "truncated": len(rows) > _MAX_DEPLOYMENTS}
