"""Atomic reference imports: immutable per-source snapshots, explicit current pointers."""
from __future__ import annotations

import copy
import base64
import os
import tempfile
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from .models import SbomRun
from .project_catalog_models import NativeReanalysisPending  # register reanalysis-intent table before create_all
from .offline_intelligence_models import OfflineReferenceCurrent, OfflineReferenceSnapshot

FORMAT = "koda-offline-intelligence-v1"


def digest(document):
    return hashlib.sha256(json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _date(value):
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)


def source_document(kind, source, records):
    source = {key: value for key, value in source.items() if key not in {"status", "ageDays", "rawBase64", "sourceFile"}}
    return {"format": FORMAT, "createdAt": source["fetchedAt"], "datasets": {kind: {"sources": [source], "records": copy.deepcopy(records)}}}


def active_reference_document(db, *, at=None, _include_unavailable=False):
    from .offline_intelligence import source_status
    from .data_updates import reference_import_allowed
    from .config import get_settings
    if not _include_unavailable:
        try: reference_import_allowed(get_settings())
        except ValueError: return {"format":FORMAT,"createdAt":"1970-01-01T00:00:00Z","datasets":{}}
    datasets = {}
    rows = db.scalars(select(OfflineReferenceSnapshot).join(
        OfflineReferenceCurrent, OfflineReferenceCurrent.snapshot_id == OfflineReferenceSnapshot.id
    ).order_by(OfflineReferenceSnapshot.kind, OfflineReferenceSnapshot.source_id)).all()
    for row in rows:
        dataset = row.document["datasets"][row.kind]
        target = datasets.setdefault(row.kind, {"sources": [], "records": []})
        target["sources"].extend(source_status(source, at=at) for source in dataset["sources"])
        target["records"].extend(copy.deepcopy(dataset["records"]))
    return {"format": FORMAT, "createdAt": max((source["fetchedAt"] for dataset in datasets.values() for source in dataset["sources"]), default="1970-01-01T00:00:00Z"), "datasets": datasets}


def reference_manifest(document):
    """Compact evidence saved with each analysis; records remain in immutable snapshots."""
    sources = [{"kind": kind, **{key: value for key, value in source.items() if key not in {"rawBase64", "sourceFile", "ageDays"}}}
               for kind, dataset in document.get("datasets", {}).items() for source in dataset.get("sources", [])]
    return {"format": FORMAT, "sha256": digest({"sources": sources}), "sources": sources,
            "counts": {kind: len(dataset.get("records", [])) for kind, dataset in document.get("datasets", {}).items()}}


def _project_epss(db, dataset, *, allow_older=False):
    from .vulnerability_intelligence import validate_epss, MAX_CACHE
    from .vulnerability_intelligence_models import VulnerabilityIntelligence
    from .config import get_settings
    from sqlalchemy import func
    sources = {source["id"]: source for source in dataset["sources"]}
    total = db.scalar(select(func.count()).select_from(VulnerabilityIntelligence)) or 0
    for offset in range(0, len(dataset["records"]), 500):
        batch = dataset["records"][offset:offset + 500]
        existing = {row.cve: row for row in db.scalars(select(VulnerabilityIntelligence).where(VulnerabilityIntelligence.cve.in_([record["cve"] for record in batch])))}
        for record in batch:
            source = sources[record["sourceId"]]
            doc = validate_epss({**record, "date": record.get("date") or str(source["dataDate"])[:10]})
            row = existing.get(doc["cve"])
            restore_same_source = bool(allow_older and row is not None and (row.document or {}).get("sourceKind") == "offline_reference" and (row.document or {}).get("referenceSourceId") == source["id"])
            if row is not None and row.state == "completed" and not restore_same_source and (row.document or {}).get("date", "") > doc["date"]:
                continue
            if row is not None and row.state == "completed" and not restore_same_source and (row.document or {}).get("date") == doc["date"] and any((row.document or {}).get(key) != doc.get(key) for key in ("epss", "percentile")):
                raise ValueError("동일 기준일 EPSS 소스가 서로 다릅니다: " + doc["cve"])
            if row is None:
                if total >= MAX_CACHE:
                    raise ValueError("EPSS 캐시 한도를 초과합니다")
                row = VulnerabilityIntelligence(cve=doc["cve"])
                db.add(row); existing[doc["cve"]] = row; total += 1
            fetched = _date(source["dataDate"])
            max_age = min(int(source.get("maxAgeDays", 7)), get_settings().epss_policy_max_age_days)
            row.document = {**doc, "sourceKind": "offline_reference", "sourceUrl": source.get("sourceUrl", ""),
                            "modelVersion": record.get("modelVersion"), "snapshotSha256": source["sha256"], "maxAgeDays": max_age, "referenceSourceId": source["id"]}
            row.state, row.attempts, row.error = "completed", 0, None
            row.fetched_at = fetched
            row.expires_at = fetched + timedelta(days=max_age + 1)
            row.next_attempt_at = row.expires_at
        db.flush()
    db.flush()


def original_path(sha256):
    from .config import get_settings
    if len(sha256) != 64 or any(value not in "0123456789abcdef" for value in sha256):
        raise ValueError("원본 해시가 올바르지 않습니다")
    return get_settings().artifact_dir / "offline-intelligence" / (sha256 + ".bin")


def verify_original(source):
    path = original_path(source["sha256"])
    if path.is_symlink() or not path.is_file() or path.stat().st_size != source["sizeBytes"]:
        raise ValueError("보관 원본 파일이 없거나 크기가 변경되었습니다")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""): hasher.update(chunk)
    if hasher.hexdigest() != source["sha256"]: raise ValueError("보관 원본 파일의 해시가 변경되었습니다")
    return path


def persist_original(source, *, root=None):
    path = original_path(source["sha256"])
    if path.exists():
        verify_original(source); return
    raw = (Path(root) / source["sourceFile"]).read_bytes() if root is not None else base64.b64decode(source["rawBase64"], validate=True)
    if len(raw) != source["sizeBytes"] or hashlib.sha256(raw).hexdigest() != source["sha256"]:
        raise ValueError("반입 원본의 크기 또는 해시가 일치하지 않습니다")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Content-addressed originals survive release pruning. Interrupted imports
    # may leave an unreferenced file, never a current database pointer.
    descriptor, temporary = tempfile.mkstemp(prefix=".original-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
        verify_original(source)
    finally:
        Path(temporary).unlink(missing_ok=True)


def import_reference_document(db, document, *, actor, origin="manual", request_reanalysis=True, _validated=False, _allow_older=False, _original_root=None):
    from .offline_intelligence import validate_document
    from .data_updates import reference_import_allowed
    from .config import get_settings
    reference_import_allowed(get_settings())
    document = document if _validated else validate_document(document)
    planned = []
    protected = []
    for kind, dataset in document["datasets"].items():
        for source in dataset["sources"]:
            records = [record for record in dataset["records"] if record["sourceId"] == source["id"]]
            persist_original(source, root=_original_root)
            subset = source_document(kind, source, records)
            sha = digest(subset)
            pointer = db.get(OfflineReferenceCurrent, (kind, source["id"]), with_for_update=True)
            previous = db.get(OfflineReferenceSnapshot, pointer.snapshot_id) if pointer else None
            if previous and origin == "verified_bundle" and previous.origin != "verified_bundle" and _date(previous.data_as_of) > _date(source["dataDate"]):
                protected.append(previous.id)
                continue  # A bundle rollback cannot downgrade a newer manual source.
            if previous and not _allow_older and _date(previous.data_as_of) > _date(source["dataDate"]):
                raise ValueError("활성 자료보다 오래된 기준일의 소스로 되돌릴 수 없습니다: " + source["id"])
            planned.append((kind, source, records, subset, sha, pointer, previous))
    imported, skipped, ids = 0, len(protected), list(protected)
    changed = {}
    for kind, source, records, subset, sha, pointer, previous in planned:
        if previous and previous.sha256 == sha:
            skipped += 1; ids.append(previous.id); continue
        row = db.scalar(select(OfflineReferenceSnapshot).where(
            OfflineReferenceSnapshot.kind == kind, OfflineReferenceSnapshot.source_id == source["id"], OfflineReferenceSnapshot.sha256 == sha))
        if row is None:
            row = OfflineReferenceSnapshot(kind=kind, source_id=source["id"], source_version=str(source.get("version") or source["dataDate"]),
                 data_as_of=source["dataDate"], sha256=sha, record_count=len(records), document=subset, imported_by=actor, origin=origin)
            db.add(row); db.flush()
        if pointer is None:
            pointer = OfflineReferenceCurrent(kind=kind, source_id=source["id"], snapshot_id=row.id)
            db.add(pointer)
        else:
            pointer.snapshot_id, pointer.updated_at = row.id, datetime.now(UTC)
        target = changed.setdefault(kind, {"sources": [], "records": []})
        target["sources"].append(source); target["records"].extend(records)
        imported += 1; ids.append(row.id)
    if "epss" in changed:
        _project_epss(db, changed["epss"], allow_older=_allow_older)
    db.flush()
    affected = 0
    if imported and request_reanalysis:
        from .project_catalog import request_native_reanalysis
        # Reference data affects discovery explanations, identities, licence and
        # lifecycle evidence even when the CVE set is unchanged. Re-evaluate all
        # active imported runs; durable intents handle queue capacity safely.
        run_ids = list(db.scalars(select(SbomRun.id).where(SbomRun.archived_at.is_(None))))
        affected = request_native_reanalysis(db, "offline-reference", run_ids, reason="offline_reference_update")
    return {"importedSources": imported, "skippedSources": skipped, "snapshotIds": ids,
            "reanalysisRequested": affected, "sha256": digest(document)}


def sync_reference_bundle(db, release_path: Path, *, actor="offline-bundle", request_reanalysis=True, allow_older=False):
    from .offline_intelligence import load_intelligence
    root = Path(release_path)
    index = root / "intelligence.json"
    document = load_intelligence(root) if index.is_file() else {"format": FORMAT, "datasets": {}}
    wanted = {(kind, source["id"]) for kind, dataset in document["datasets"].items() for source in dataset["sources"]}
    removed = 0
    for pointer in db.scalars(select(OfflineReferenceCurrent)).all():
        snapshot = db.get(OfflineReferenceSnapshot, pointer.snapshot_id)
        if snapshot.origin == "verified_bundle" and (pointer.kind, pointer.source_id) not in wanted:
            db.delete(pointer); removed += 1
    result = import_reference_document(db, document, actor=actor, origin="verified_bundle", request_reanalysis=False, _validated=True, _allow_older=allow_older, _original_root=root)
    result["deactivatedSources"] = removed
    changed = result["importedSources"] or removed
    if changed:
        from .vulnerability_intelligence_models import VulnerabilityIntelligence
        active = active_reference_document(db)
        epss = active["datasets"].get("epss", {"sources": [], "records": []})
        active_hashes = {source["sha256"] for source in epss["sources"]}
        cached = db.scalars(select(VulnerabilityIntelligence).where(VulnerabilityIntelligence.document["sourceKind"].as_string() == "offline_reference"))
        for row in cached:
            if (row.document or {}).get("snapshotSha256") not in active_hashes:
                row.state, row.error = "superseded", "활성 자료에서 제외된 과거 EPSS 근거"
        # Re-select current sources after an explicitly approved signed rollback.
        # Inactive cached rows retain observed evidence but cannot feed policies.
        if epss["records"]:
            epss["records"].sort(key=lambda record: str(record.get("date", "")))
            _project_epss(db, epss)
        if request_reanalysis:
            from .project_catalog import request_native_reanalysis
            run_ids = list(db.scalars(select(SbomRun.id).where(SbomRun.archived_at.is_(None))))
            result["reanalysisRequested"] = request_native_reanalysis(db, "offline-reference", run_ids, reason="offline_reference_update")
    return result
