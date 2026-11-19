"""Review offline candidate evidence against an immutable deployment SBOM."""
import hashlib
import json
import re
from typing import Annotated, Literal
from urllib.parse import parse_qsl, unquote, urlencode

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import ForeignKey, JSON, String, UniqueConstraint, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column, selectinload

from .compatibility_data import can_view_references, matching_references
from .db import Base, get_db
from .java_impact import JavaDeployment, _maven_coordinate
from .library_api import package_coordinate
from .models import Environment, ProcessingState, Release, RunComponent, SbomRun, new_id, now
from .security import require_csrf, require_permission
from .services import audit
from .shared_ai import upgrade_explanation
from .upgrade_elf import ElfEvidence, eval_elf
from .upgrade_maven import MavenEvidence, eval_maven, maven_version_key
from .upgrade_native_versions import deb_version_key, rpm_version_key
from .upgrade_python import PythonEvidence, eval_python, python_version_key

router = APIRouter(prefix="/api/v1/upgrade-batches", tags=["Offline upgrade review"])
_view = require_permission("runs.view")
_manage = require_permission("catalog.manage")
Ecosystem = Literal["maven", "python", "elf"]
Id = Annotated[str, Field(min_length=1, max_length=36, pattern=r"^[A-Za-z0-9-]+$")]
Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
VersionText = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+!~:^-]*$")]
Label = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S(?:.*\S)?$")]
Evidence = Annotated[MavenEvidence | PythonEvidence | ElfEvidence, Field(discriminator="kind")]


class UpgradeBatch(Base):
    __tablename__ = "upgrade_batches"
    __table_args__ = (UniqueConstraint("baseline_run_id", "manifest_sha256"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    baseline_run_id: Mapped[str] = mapped_column(ForeignKey("sbom_runs.id", ondelete="CASCADE"), index=True)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    result: Mapped[dict] = mapped_column(JSON)


class BoundRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    runId: Id
    sha256: Sha


class Platform(BaseModel):
    model_config = ConfigDict(extra="forbid")
    server: Label
    os: Label
    architecture: Label
    source: Label
    javaMajor: int | None = Field(default=None, ge=6, le=99)
    pythonVersion: Annotated[str, Field(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")] | None = None
    pythonImplementation: Literal["cpython", "pypy"] | None = None
    pythonSysPlatform: Literal["linux", "darwin", "win32"] | None = None
    nativePlatform: Literal["linux"] | None = None
    pythonEnvironment: dict[Annotated[str, Field(max_length=64)], Annotated[str, Field(max_length=512)]] | None = Field(default=None, max_length=16)


class Verification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["passed", "failed"]
    reference: Annotated[str, Field(min_length=1, max_length=300, pattern=r"^\S(?:.*\S)?$")]
    artifactSha256: Sha
    os: Label
    architecture: Label
    javaMajor: int | None = Field(default=None, ge=6, le=99)
    pythonVersion: Annotated[str, Field(pattern=r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")] | None = None


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: VersionText
    sbom: BoundRun | None = None
    evidence: Evidence | None = None
    artifactSha256: Sha | None = None
    build: Verification | None = None
    runtime: Verification | None = None

    @model_validator(mode="after")
    def verification_matches_artifact(self):
        if any(check and (not self.sbom or check.artifactSha256 != self.artifactSha256) for check in (self.build, self.runtime)):
            raise ValueError("빌드·실행 기록에는 후보 SBOM과 일치하는 검증 산출물 해시가 필요합니다")
        return self


class BatchManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schemaVersion: Literal[1]
    baseline: BoundRun
    ecosystem: Ecosystem
    coordinate: Annotated[str, Field(min_length=1, max_length=512)]
    deploymentId: Id | None = None
    platform: Platform
    candidates: list[Candidate] = Field(min_length=1, max_length=40)

    @model_validator(mode="after")
    def validate_scope(self):
        if self.ecosystem == "maven":
            if not self.deploymentId or not self.platform.javaMajor:
                raise ValueError("Maven 검토에는 등록된 배포 기준과 Java 버전이 필요합니다")
        elif self.deploymentId:
            raise ValueError("Java 배포 ID는 Maven 검토에 사용합니다")
        if self.ecosystem == "python" and not all((self.platform.pythonVersion, self.platform.pythonImplementation,
                                                   self.platform.pythonSysPlatform)):
            raise ValueError("Python 전체 버전, 구현체, sys.platform이 필요합니다")
        if self.ecosystem == "elf" and self.platform.nativePlatform != "linux":
            raise ValueError("C/ELF 검토에는 Linux 배포 기준을 지정하세요")
        if _coordinate(self.ecosystem, self.coordinate) != self.coordinate:
            raise ValueError("버전이 없는 정규 패키지 PURL을 지정하세요")
        if len({row.version for row in self.candidates}) != len(self.candidates):
            raise ValueError("같은 버전을 두 번 반입할 수 없습니다")
        if any(row.evidence and row.evidence.kind != self.ecosystem for row in self.candidates):
            raise ValueError("검토 종류와 후보 근거 종류가 다릅니다")
        for row in self.candidates:
            for check in (row.build, row.runtime):
                if check and (check.os, check.architecture, check.javaMajor, check.pythonVersion) != (
                    self.platform.os, self.platform.architecture, self.platform.javaMajor, self.platform.pythonVersion,
                ):
                    raise ValueError("빌드·실행 기록과 검토 대상 환경이 다릅니다")
        return self


def _coordinate(ecosystem, purl):
    if not purl:
        return ""
    if ecosystem == "maven":
        value = _maven_coordinate(purl)
        return value if re.fullmatch(r"pkg:maven/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value) else ""
    value = package_coordinate(purl)
    if ecosystem == "python":
        return value if re.fullmatch(r"pkg:pypi/[a-z0-9][a-z0-9-]*", value) else ""
    if value.startswith("pkg:rpm/"):
        package, _, subpath = value.partition("#")
        name, _, qualifiers = package.partition("?")
        qualifiers = urlencode([(key, field) for key, field in parse_qsl(qualifiers) if key != "epoch"])
        return name + ("?" + qualifiers if qualifiers else "") + ("#" + subpath if subpath else "")
    return value if value.startswith(("pkg:deb/", "pkg:apk/", "pkg:generic/")) else ""


def _scope(run):
    return run.release.service_id, run.release.environment_id


def _live_runs():
    return select(SbomRun).join(Release).join(Environment).where(
        SbomRun.state == ProcessingState.COMPLETED, SbomRun.archived_at.is_(None), Environment.active.is_(True))


def _get_baseline(db, run_id):
    run = db.scalar(_live_runs().where(SbomRun.id == run_id))
    if run is None:
        raise HTTPException(404, "활성 환경의 완료 SBOM 회차를 찾을 수 없습니다")
    return run


def _run_ref(run):
    return {"runId": run.id, "sha256": run.sha256, "releaseVersion": run.release.version,
            "roundNumber": run.round_number}


@router.get("/{run_id}/context", dependencies=[Depends(_view)])
def context(run_id: Id, db: Session = Depends(get_db)):
    base = _get_baseline(db, run_id)
    service, environment = _scope(base)
    runs = list(db.scalars(_live_runs().options(selectinload(SbomRun.release)).where(
        Release.service_id == service, Release.environment_id == environment, SbomRun.id != base.id,
    ).order_by(SbomRun.created_at.desc(), SbomRun.id).limit(101)))
    deployments = db.scalars(select(JavaDeployment).where(
        JavaDeployment.run_id == base.id, JavaDeployment.service_id == service, JavaDeployment.environment_id == environment,
    ).order_by(JavaDeployment.target))
    return {"baseline": _run_ref(base), "service": base.release.service.name, "environment": base.release.environment.name,
            "candidates": [_run_ref(row) for row in runs[:100]], "candidatesTruncated": len(runs) > 100,
            "javaDeployments": [{"id": row.id, "server": row.target, "os": row.os, "architecture": row.architecture,
                                 "javaMajor": row.java_major} for row in deployments]}


def _purl_version(package):
    coordinate, separator, version = package.rpartition("@")
    return unquote(version) if separator and "/" in coordinate else None


def _native_observed_version(purl, fallback):
    if not purl.startswith(("pkg:rpm/", "pkg:deb/")):
        return fallback
    package, _, qualifiers = purl.partition("#")[0].partition("?")
    declared = _purl_version(package)
    value = fallback if declared is None else declared
    if purl.startswith("pkg:rpm/") and ":" not in value:
        epoch = dict(parse_qsl(qualifiers)).get("epoch", "0")
        if re.fullmatch(r"[0-9]{1,9}", epoch) and int(epoch):
            value = f"{epoch}:{value}"
    return value


def _package_versions(db, run_ids, ecosystem, *, check_purl_version=False):
    inventories = {run_id: {} for run_id in run_ids}
    components = db.execute(select(RunComponent.run_id, RunComponent.purl, RunComponent.version).where(
        RunComponent.run_id.in_(run_ids), RunComponent.purl.startswith({
            "maven": "pkg:maven/", "python": "pkg:pypi/", "elf": "pkg:",
        }[ecosystem], autoescape=True)).distinct().limit(200_001))
    for index, (run_id, purl, version) in enumerate(components):
        if index == 200_000:
            raise HTTPException(422, "한 번에 대조할 구성요소 수를 초과했습니다. 후보를 나눠서 반입하세요")
        coordinate = _coordinate(ecosystem, purl)
        if coordinate:
            versions = inventories[run_id].setdefault(coordinate, set())
            versions.add(_native_observed_version(purl, version) if ecosystem == "elf" else version)
            if check_purl_version and ecosystem in {"maven", "python"}:
                declared = _purl_version(re.split(r"[?#]", purl, maxsplit=1)[0])
                if declared is not None and declared != version:
                    key = python_version_key(version) if ecosystem == "python" else None
                    if key is None or key != python_version_key(declared):
                        versions.add(declared)
    return inventories


def _review(candidate, ecosystem, coordinate, platform, observed):
    evidence = candidate.evidence
    if evidence is None:
        return "unknown", ["반입된 후보 근거가 없습니다"]
    if ecosystem == "maven":
        return eval_maven(evidence, candidate.version, coordinate, platform, observed)
    if ecosystem == "python":
        return eval_python(evidence, candidate.version, coordinate, platform, observed)
    if not _exact_candidate(ecosystem, observed, coordinate, candidate.version):
        return "unknown", ["ELF 근거와 대조할 정확한 후보 버전이 SBOM에서 확인되지 않습니다"]
    return eval_elf(evidence, platform["architecture"])


def _version_key(ecosystem, coordinate):
    def numeric_key(version):
        if not re.fullmatch(r"\d{1,9}(?:\.\d{1,9}){0,7}", version):
            return None
        parts = tuple(int(item) for item in version.split("."))
        return parts + (0,) * (8 - len(parts))

    if ecosystem == "elf":
        scheme = coordinate.split(":", 1)[1].split("/", 1)[0]
        return {"generic": numeric_key, "rpm": rpm_version_key, "deb": deb_version_key}.get(scheme, lambda _: None)
    return maven_version_key if ecosystem == "maven" else python_version_key


def _highest(rows, keys):
    if not rows or any(keys[row["version"]] is None for row in rows):
        return None
    return max((row["version"] for row in rows), key=lambda version: (keys[version], version))


def _exact_candidate(ecosystem, observed, coordinate, version):
    versions = observed.get(coordinate, set())
    if versions == {version}:
        return True
    if len(versions) == 1 and (ecosystem == "python" or coordinate.startswith(("pkg:rpm/", "pkg:deb/"))):
        key = _version_key(ecosystem, coordinate)
        expected = key(version)
        return expected is not None and expected == key(next(iter(versions)))
    return False


def _result(body, base, inventories, actor, digest):
    platform = body.platform.model_dump(exclude_none=True)
    rows = []
    for candidate in body.candidates:
        observed = inventories[candidate.sbom.runId] if candidate.sbom else {}
        matches_candidate = _exact_candidate(body.ecosystem, observed, body.coordinate, candidate.version)
        if (candidate.build or candidate.runtime) and not matches_candidate:
            raise HTTPException(422, "빌드·실행 기록의 버전이 후보 SBOM에서 확인되지 않습니다")
        status, reasons = _review(candidate, body.ecosystem, body.coordinate, platform, observed)
        if status == "conditions_met" and not matches_candidate:
            status, reasons = "unknown", ["후보 SBOM에서 해당 패키지와 단일 후보 버전을 확인하지 못했습니다"]
        rows.append({"version": candidate.version, "sbom": candidate.sbom.model_dump() if candidate.sbom else None,
                     "conditionStatus": status, "reasons": reasons,
                     "evidenceSource": getattr(candidate.evidence, "source", None),
                     "reportSha256": getattr(candidate.evidence, "reportSha256", None),
                     "artifactSha256": candidate.artifactSha256,
                     "build": candidate.build.model_dump() if candidate.build else {"status": "not_reported"},
                     "runtime": candidate.runtime.model_dump() if candidate.runtime else {"status": "not_reported"}})
    order = _version_key(body.ecosystem, body.coordinate)
    keys = {row["version"]: order(row["version"]) for row in rows}
    if all(key is not None for key in keys.values()):
        rows.sort(key=lambda row: (keys[row["version"]], row["version"]))
    conditions = [row for row in rows if row["conditionStatus"] == "conditions_met"]
    verified = [row for row in rows if row["build"]["status"] == row["runtime"]["status"] == "passed"]
    return {"schemaVersion": 1, "manifestSha256": digest, "createdAt": now().isoformat(), "importedBy": actor,
            "baseline": body.baseline.model_dump(), "serviceId": base.release.service_id, "environmentId": base.release.environment_id,
            "ecosystem": body.ecosystem, "coordinate": body.coordinate, "deploymentId": body.deploymentId, "platform": platform,
            "currentVersions": sorted(inventories[base.id].get(body.coordinate, [])), "candidates": rows,
            "highestConditionVersion": _highest(conditions, keys), "highestVerifiedVersion": _highest(verified, keys),
            "orderingLimited": any(key is None for key in keys.values())}


def _batch_response(db, item, user):
    result = {"id": item.id, **item.result}
    if not can_view_references(db, user):
        return result
    ecosystem, coordinate = result["ecosystem"], result["coordinate"]
    candidates = result["candidates"]
    references = matching_references(db, ecosystem, coordinate, {row["version"] for row in candidates if row["sbom"]})
    eligible = {}
    if references:
        bound_ids = {row["sbom"]["runId"] for row in candidates if row["sbom"] and row["version"] in references}
        runs = dict(db.execute(_live_runs().with_only_columns(SbomRun.id, SbomRun.sha256).where(
            SbomRun.id.in_(bound_ids), Release.service_id == result["serviceId"],
            Release.environment_id == result["environmentId"])).all())
        eligible = {row["version"]: row["sbom"]["runId"] for row in candidates
                    if row["sbom"] and row["version"] in references
                    and runs.get(row["sbom"]["runId"]) == row["sbom"]["sha256"]}
    observed = _package_versions(db, set(eligible.values()), ecosystem, check_purl_version=True) if eligible else {}
    return {**result, "candidates": [
        {**row, "officialReferences": references.get(row["version"], []) if _exact_candidate(
            ecosystem, observed.get(eligible.get(row["version"]), {}), coordinate, row["version"]) else []}
        for row in candidates
    ]}



@router.post("/import", dependencies=[Depends(_manage), Depends(_view), Depends(require_csrf)])
def import_batch(body: BatchManifest, db: Session = Depends(get_db), user=Depends(_manage)):
    references = [body.baseline, *(item.sbom for item in body.candidates if item.sbom)]
    run_ids = {item.runId for item in references}
    runs = {row.id: row for row in db.scalars(_live_runs().options(selectinload(SbomRun.release))
            .where(SbomRun.id.in_(run_ids)).order_by(SbomRun.id).with_for_update(read=True, of=SbomRun))}
    base = runs.get(body.baseline.runId)
    if base is None or any(item.runId not in runs or _scope(runs[item.runId]) != _scope(base) for item in references):
        raise HTTPException(404, "같은 서비스·환경에서 완료된 기준 및 후보 회차를 지정하세요")
    if any(item.sha256 != runs[item.runId].sha256 for item in references):
        raise HTTPException(409, "반입 근거와 SBOM 해시가 다릅니다")
    if any(item.sbom and item.sbom.runId == base.id for item in body.candidates):
        raise HTTPException(422, "배포 기준과 다른 회차를 후보로 지정하세요")
    if body.ecosystem == "maven":
        deployment = db.scalar(select(JavaDeployment).where(JavaDeployment.id == body.deploymentId)
                               .with_for_update(read=True, of=JavaDeployment))
        profile = body.platform
        if (not deployment or (deployment.service_id, deployment.environment_id) != _scope(base)
                or (deployment.run_id, deployment.target, deployment.java_major, deployment.os, deployment.architecture)
                != (base.id, profile.server, profile.javaMajor, profile.os, profile.architecture)):
            raise HTTPException(409, "반입한 Java 서버 정보와 등록된 배포 기준이 다릅니다")
    digest = hashlib.sha256(json.dumps(body.model_dump(), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    lookup = select(UpgradeBatch).where(UpgradeBatch.baseline_run_id == base.id, UpgradeBatch.manifest_sha256 == digest)
    item = db.scalar(lookup)
    if item:
        return _batch_response(db, item, user)
    inventories = _package_versions(db, run_ids, body.ecosystem)
    if not any(inventories[base.id].get(body.coordinate, [])):
        raise HTTPException(422, "배포 기준 SBOM에서 해당 패키지와 버전을 확인할 수 없습니다")
    result = _result(body, base, inventories, user.username, digest)
    item = UpgradeBatch(baseline_run_id=base.id, manifest_sha256=digest, result=result)
    db.add(item)
    try:
        db.flush()
        audit(db, user.username, "upgrade_batch.import", "upgrade_batch", item.id,
              {"runId": base.id, "manifestSha256": digest, "ecosystem": body.ecosystem})
        db.commit()
    except IntegrityError:
        db.rollback()
        item = db.scalar(lookup)
        if item is None:
            raise
    return _batch_response(db, item, user)


@router.get("/{run_id}", dependencies=[Depends(_view)])
def list_batches(run_id: Id, db: Session = Depends(get_db), page: int = Query(default=1, ge=1, le=1000)):
    base = _get_baseline(db, run_id)
    rows = db.scalars(select(UpgradeBatch).where(
        UpgradeBatch.baseline_run_id == base.id,
        UpgradeBatch.result["serviceId"].as_string() == base.release.service_id,
        UpgradeBatch.result["environmentId"].as_string() == base.release.environment_id,
    ).order_by(UpgradeBatch.result["createdAt"].as_string().desc(), UpgradeBatch.id).offset((page - 1) * 20).limit(21)).all()
    return {"items": [{"id": row.id, **{key: row.result[key] for key in (
        "createdAt", "ecosystem", "coordinate", "highestConditionVersion", "highestVerifiedVersion",
    )}} for row in rows[:20]], "hasMore": len(rows) > 20}


@router.get("/{run_id}/{batch_id}")
def get_batch(run_id: Id, batch_id: Id, db: Session = Depends(get_db), user=Depends(_view)):
    base = _get_baseline(db, run_id)
    item = db.get(UpgradeBatch, batch_id)
    if not item or item.baseline_run_id != base.id or (item.result["serviceId"], item.result["environmentId"]) != _scope(base):
        raise HTTPException(404, "해당 회차의 검토 기록을 찾을 수 없습니다")
    return _batch_response(db, item, user)


@router.post("/{run_id}/{batch_id}/ai-explanation", dependencies=[Depends(_view), Depends(require_csrf)])
def explain_batch(run_id: Id, batch_id: Id, db: Session = Depends(get_db), user=Depends(_view)):
    return upgrade_explanation(db, get_batch(run_id, batch_id, db, user))
