from __future__ import annotations

import json
from contextlib import ExitStack
import os
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .config import get_settings
from .large_sbom import iter_large_records
from .large_sbom_scan import grype_cyclonedx_view, scan_large_sbom
from .collection_coverage import coverage_for_bom
from .models import (
    AnalysisRevision,
    AuditEvent,
    Job,
    JobState,
    ProcessingState,
    RunComponent,
    SbomRun,
)
from .sbom import MAX_UPLOAD_DOCUMENT_BYTES, SBOM_ARCHIVE_MEDIA_TYPES, SbomValidationError, iter_components, licenses_for, normalized_identity, sbom_document_path, sbom_nis_scan_path, sha256_for
from . import package_metadata_models
from .package_metadata import enqueue_components
from . import workflow_models  # Register workflow tables before standalone create_all callers.
from .private_vulnerability import match_private_vulnerabilities
from .sbom_normalization import mark_current
from .sbom_nis import NIS_SBOM_MEDIA_TYPE
from .sbom_workbook import WORKBOOK_MEDIA_TYPE
from .policies import evaluate_revision
from .quality import evaluate_quality, revision_payload as quality_payload
from .vulnerability import active_bundle, load_context, normalize_finding, project_cve_findings, vulnerable_component_count
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
        if getattr(run, "split_document", False) and (len(identity) > 1024 or "\x00" in identity):
            raise SbomValidationError("SBOM 구성요소의 정규화 식별자가 저장 한도를 초과했습니다")
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
    collection_evidence = {}
    components_for_cpe = []
    component_refs = set()
    if isinstance(run, SbomRun):
        bom = run.normalized_bom or {}
        raw_components = bom.get("components", [])
        collection_evidence, source_root = coverage_for_bom(bom)
        components = list(iter_components(raw_components))
        enqueue_components(db, components)
        component_refs = {component["bom-ref"] for component in components if isinstance(component.get("bom-ref"), str)}
        components_for_cpe = raw_components if source_root is None else [
            component for component in raw_components if component.get("bom-ref") != source_root
        ]
    findings: list[dict] = []
    quality = quality_payload(evaluate_quality(db, run, actor="worker", force=True))
    quality_evidence = {**quality["summary"], "state": quality["state"], "revisionId": quality["id"],
                        "profileSnapshot": quality["profileSnapshot"], "originalSha256": quality["originalSha256"]}
    revision.data_sources = {"sbomQuality": quality_evidence, **collection_evidence}
    try:
        settings = get_settings()
        initial_bundle = active_bundle(settings)
        from .data_updates import assert_approved_release
        assert_approved_release(settings, initial_bundle.path if initial_bundle else None)
        context = load_context(settings, release_path=initial_bundle.path) if initial_bundle else load_context(settings)
        revision.data_sources = {**context.sources, "sbomNormalization": {"version": 2}, "sbomQuality": quality_evidence, **collection_evidence}
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
        split_document = getattr(run, "split_document", False)
        finding_bytes = 0

        def record_match(match: dict) -> None:
            nonlocal finding_bytes
            finding = _grype_finding(match, context, component_refs)
            if split_document:
                finding_bytes += len(json.dumps(finding, ensure_ascii=False).encode())
                if finding_bytes > 64 * 1024**2:
                    raise ValueError("대용량 SBOM 취약점 결과가 저장 크기 한도를 초과했습니다")
            findings.append(finding)

        if split_document:
            if quality["state"] != "completed":
                raise ValueError(quality.get("error") or "원본 SBOM 또는 인덱스 검증을 완료하지 못했습니다")
            tool_version = scan_large_sbom(
                run.normalized_bom,
                lambda: iter_large_records(db, run.id, "components"),
                binary=settings.grype_binary,
                env=env,
                spool=settings.artifact_dir,
                on_match=record_match,
            )
            revision.data_sources = {**revision.data_sources, "sbomDocument": {"storage": "split_cyclonedx", "sha256": run.sha256}}
        else:
            payload = _grype_document(run, settings, env)
            for match in payload.get("matches", []):
                record_match(match)
            tool_version = str(payload.get("descriptor", {}).get("version", "grype"))
        if isinstance(run, SbomRun):
            findings, cpe_evidence = enrich_cpe_findings(components_for_cpe, context, findings)
            revision.data_sources = {**revision.data_sources, "cpeApplicability": cpe_evidence}
            private_findings, private_snapshot = match_private_vulnerabilities(
                db, (run.normalized_bom or {}).get("components", [])
            )
            findings.extend(private_findings)
            revision.data_sources = {**revision.data_sources, "privateVulnerabilityDb": private_snapshot}
        revision.state = JobState.COMPLETED
        revision.tool_version = tool_version
    except Exception as exc:
        revision.state = JobState.FAILED
        revision.error = str(exc)[-2000:]
        if getattr(run, "split_document", False):
            findings.clear()

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
    if getattr(run, "split_document", False):
        revision.metrics = {
            **(revision.metrics or {}),
            "registeredVulnerableComponentCount": vulnerable_component_count(
                run.normalized_bom, project_cve_findings(revision.findings)
            ),
        }
    from .workflows import apply_vex_reviews, notify_analysis
    apply_vex_reviews(db, run, revision)
    notify_analysis(db, run, revision)
    _derive_state(run, revision)
    db.flush()
    return revision


def _grype_document(run, settings, env: dict) -> dict:
    source = Path(run.artifact_path)
    media_type = getattr(run, "media_type", "")
    prepared_input = (
        media_type == WORKBOOK_MEDIA_TYPE
        or media_type in SBOM_ARCHIVE_MEDIA_TYPES.values()
        or (media_type.endswith("+json") and getattr(run, "size_bytes", 0) > MAX_UPLOAD_DOCUMENT_BYTES)
    )
    with ExitStack() as cleanup:
        if getattr(run, "spec_version", "") == "1.7":
            converted = cleanup.enter_context(tempfile.NamedTemporaryFile(
                "w", suffix=".cdx.json", encoding="utf-8", dir=settings.artifact_dir,
            ))
            json.dump(grype_cyclonedx_view(run.normalized_bom), converted,
                      ensure_ascii=False, separators=(",", ":"))
            converted.flush()
            grype_input = Path(converted.name)
        else:
            grype_input = source
            if prepared_input:
                grype_input = cleanup.enter_context(sbom_document_path(
                    source, max_bytes=settings.max_upload_bytes, workbook=media_type == WORKBOOK_MEDIA_TYPE,
                    keep_legacy=True,
                ))
            if media_type == NIS_SBOM_MEDIA_TYPE or media_type in SBOM_ARCHIVE_MEDIA_TYPES.values():
                grype_input = cleanup.enter_context(sbom_nis_scan_path(grype_input))
        process = subprocess.run(
            [settings.grype_binary, f"sbom:{grype_input}", "-o", "json"],
            text=True,
            capture_output=True,
            timeout=300,
            env=env,
            check=False,
        )
    if process.returncode:
        raise ValueError(process.stderr[-2000:] or "Grype 분석 실패")
    return json.loads(process.stdout)


def _grype_finding(match: dict, context, component_refs: set[str]) -> dict:
    vulnerability = match.get("vulnerability", {})
    artifact = match.get("artifact", {})
    artifact_ref = artifact.get("id")
    # GHSA aliases may be exposed next to the vulnerability in Grype output.
    return {
        **normalize_finding({
            **vulnerability,
            "relatedVulnerabilities": [
                *(vulnerability.get("relatedVulnerabilities") or []),
                *(match.get("relatedVulnerabilities") or []),
            ],
        }, context),
        "component": artifact.get("purl") or artifact.get("name"),
        "version": artifact.get("version"),
        **({"bomRef": artifact_ref} if isinstance(artifact_ref, str) and artifact_ref in component_refs else {}),
        "fixedIn": [
            str(item.get("version") if isinstance(item, dict) else item)
            for item in vulnerability.get("fix", {}).get("versions", [])
            if item
        ],
    }


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
