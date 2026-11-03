from __future__ import annotations

import json
import os
import subprocess
from contextlib import nullcontext
from collections import Counter
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import (
    AnalysisRevision,
    AuditEvent,
    Job,
    JobState,
    ProcessingState,
    RunComponent,
    SbomRun,
)
from .sbom import SBOM_ARCHIVE_MEDIA_TYPES, iter_components, licenses_for, normalized_identity, sbom_document_path, sha256_for
from . import package_metadata_models
from .package_metadata import enqueue_components
from . import workflow_models  # Register workflow tables before standalone create_all callers.
from .private_vulnerability import match_private_vulnerabilities
from .sbom_normalization import mark_current
from .sbom_workbook import WORKBOOK_MEDIA_TYPE
from .policies import evaluate_revision
from .quality import evaluate_quality, revision_payload as quality_payload
from .vulnerability import active_bundle, load_context, normalize_finding
from .cpe_analysis import enrich_cpe_findings


def create_components(db: Session, run: SbomRun, *, refresh: bool = False) -> None:
    if refresh:
        db.execute(delete(RunComponent).where(RunComponent.run_id == run.id))
        db.expire(run, ["components"])
    elif db.scalar(select(func.count()).select_from(RunComponent).where(RunComponent.run_id == run.id)):
        return
    raw_components = list(iter_components((run.normalized_bom or {}).get("components", [])))
    enqueue_components(db, raw_components)
    identities = [normalized_identity(raw)[0] for raw in raw_components]
    duplicates = Counter(identities)
    for index, raw in enumerate(raw_components):
        identity, status = normalized_identity(raw)
        if duplicates[identity] > 1:
            bom_ref = str(raw.get("bom-ref") or "")
            identity = f"{identity}|bom-ref:{bom_ref}" if bom_ref else f"{identity}|ambiguous:{index}"
            status = "review_required"
        group_name = str(raw.get("group") or "")
        name = str(raw.get("name") or raw.get("bom-ref") or "unknown")
        version = str(raw.get("version") or "")
        purl = str(raw.get("purl") or "")
        bom_ref = str(raw.get("bom-ref") or "")
        db.add(
            RunComponent(
                run_id=run.id,
                identity_key=identity,
                identity_status=status,
                component_type=str(raw.get("type") or "library"),
                group_name=group_name,
                name=name,
                version=version,
                purl=purl,
                bom_ref=bom_ref,
                search_text=" ".join((group_name, name, version, purl, bom_ref)).lower(),
                sha256=sha256_for(raw),
                licenses=licenses_for(raw),
                properties=list(raw.get("properties") or []),
            )
        )
    mark_current(db, run)
    db.flush()
    if refresh:
        db.expire(run, ["components"])


def analyze_offline(db: Session, run: SbomRun) -> AnalysisRevision:
    from .data_updates import release_read_lease
    with release_read_lease(get_settings()):
        return _analyze_offline(db, run)


def _analyze_offline(db: Session, run: SbomRun) -> AnalysisRevision:
    sequence = int(db.scalar(select(func.max(AnalysisRevision.sequence)).where(AnalysisRevision.run_id == run.id)) or 0) + 1
    revision = AnalysisRevision(run_id=run.id, sequence=sequence, state=JobState.RUNNING)
    db.add(revision)
    db.flush()
    if isinstance(run, SbomRun):
        enqueue_components(db, list(iter_components((run.normalized_bom or {}).get("components", []))))
    findings: list[dict] = []
    quality = quality_payload(evaluate_quality(db, run, actor="worker", force=True))
    quality_evidence = {**quality["summary"], "state": quality["state"], "revisionId": quality["id"],
                        "profileSnapshot": quality["profileSnapshot"], "originalSha256": quality["originalSha256"]}
    revision.data_sources = {"sbomQuality": quality_evidence}
    try:
        settings = get_settings()
        initial_bundle = active_bundle(settings)
        from .data_updates import assert_approved_release
        assert_approved_release(settings, initial_bundle.path if initial_bundle else None)
        context = load_context(settings, release_path=initial_bundle.path) if initial_bundle else load_context(settings)
        revision.data_sources = {**context.sources, "sbomNormalization": {"version": 2}, "sbomQuality": quality_evidence}
        revision.data_as_of = context.bundle.data_as_of if context.bundle else "unknown"
        if context.bundle is None:
            metadata_path = settings.grype_db_dir.parent / "metadata.env"
            revision.data_as_of = _metadata_value(metadata_path, "DATASET_DATE") or "unknown"
        env = os.environ.copy()
        # Pin the immutable composite release for this analysis. A concurrent
        # offline data update may switch ``current`` while Grype is running.
        env["GRYPE_DB_CACHE_DIR"] = str(
            context.bundle.path / "grype-db" if context.bundle is not None else settings.grype_db_dir
        )
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        env["GRYPE_DB_VALIDATE_AGE"] = "false"
        env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        env["GRYPE_EXTERNAL_SOURCES_ENABLE"] = "false"
        source = Path(run.artifact_path)
        media_type = getattr(run, "media_type", "")
        document = (
            sbom_document_path(source, max_bytes=settings.max_upload_bytes, workbook=media_type == WORKBOOK_MEDIA_TYPE)
            if media_type == WORKBOOK_MEDIA_TYPE or media_type in SBOM_ARCHIVE_MEDIA_TYPES.values()
            else nullcontext(source)
        )
        with document as selected:
            process = subprocess.run(
                [settings.grype_binary, f"sbom:{selected}", "-o", "json"],
                text=True,
                capture_output=True,
                timeout=300,
                env=env,
                check=False,
            )
        if process.returncode == 0:
            payload = json.loads(process.stdout)
            for match in payload.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                findings.append(
                    {
                        # Grype emits CVE aliases next to ``vulnerability``
                        # for GHSA matches. Keep them before canonicalization
                        # so CVE projection, KEV and NVD enrichment agree.
                        **normalize_finding({
                            **vuln,
                            "relatedVulnerabilities": [
                                *(vuln.get("relatedVulnerabilities") or []),
                                *(match.get("relatedVulnerabilities") or []),
                            ],
                        }, context),
                        "component": artifact.get("purl") or artifact.get("name"),
                        "version": artifact.get("version"),
                        "fixedIn": [
                            str(item.get("version") if isinstance(item, dict) else item)
                            for item in vuln.get("fix", {}).get("versions", [])
                            if item
                        ],
                    }
                )
            if isinstance(run, SbomRun):
                findings, cpe_evidence = enrich_cpe_findings(
                    (run.normalized_bom or {}).get("components", []), context, findings
                )
                revision.data_sources = {**revision.data_sources, "cpeApplicability": cpe_evidence}
                private_findings, private_snapshot = match_private_vulnerabilities(
                    db, (run.normalized_bom or {}).get("components", [])
                )
                findings.extend(private_findings)
                revision.data_sources = {**revision.data_sources, "privateVulnerabilityDb": private_snapshot}
            revision.state = JobState.COMPLETED
            revision.tool_version = str(payload.get("descriptor", {}).get("version", "grype"))
        else:
            revision.state = JobState.FAILED
            revision.error = process.stderr[-2000:] or "Grype 분석 실패"
    except Exception as exc:
        revision.state = JobState.FAILED
        revision.error = str(exc)[-2000:]
        from .data_updates import DataUpdateError
        if isinstance(exc,DataUpdateError):
            revision.data_sources = {**revision.data_sources,"vulnerabilityDataStatus":{"status":"unavailable","reason":revision.error}}
    revision.findings = findings
    run.analysis_state = revision.state
    # Feed aggregate CEL rules the approved effective vulnerability set while
    # retaining every raw finding and applying ordinary rule suppression later.
    from .workflows import approved_for_run, identity, review_dict, SUPPRESS_STATES
    decisions = approved_for_run(db, run)
    revision.findings = [{**finding, **({"vex": {**review_dict(decisions[identity(finding)]), "suppressed": decisions[identity(finding)].state in SUPPRESS_STATES}} if identity(finding) in decisions else {})} for finding in findings]
    evaluate_revision(db, run, revision)
    from .workflows import apply_vex_reviews, notify_analysis
    apply_vex_reviews(db, run, revision)
    notify_analysis(db, run, revision)
    _derive_state(run, revision)
    db.flush()
    return revision


def _metadata_value(path: Path, key: str) -> str | None:
    if not path.is_file():
        return None
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return None




def _derive_state(run: SbomRun, revision: AnalysisRevision | None = None) -> None:
    if getattr(run, "state", None) == ProcessingState.ARCHIVED:
        return
    if revision is None:
        revision = max(run.analyses, key=lambda item: item.sequence, default=None)
    if run.analysis_state == JobState.FAILED:
        run.state = ProcessingState.FAILED
    elif run.analysis_state == JobState.COMPLETED and revision is not None and revision.policy_state == "completed":
        run.state = ProcessingState.COMPLETED
    elif revision is not None and revision.policy_state == "failed":
        run.state = ProcessingState.PARTIAL
    else:
        run.state = ProcessingState.PROCESSING


def audit(db: Session, actor: str, action: str, target_type: str, target_id: str, detail: dict | None = None) -> None:
    db.add(AuditEvent(actor=actor, action=action, target_type=target_type, target_id=target_id, detail=detail or {}))


def enqueue(db: Session, kind: str, run_id: str) -> Job:
    job = Job(kind=kind, run_id=run_id)
    db.add(job)
    db.flush()
    return job
