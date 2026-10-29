#!/usr/bin/env python3
"""Initialize an empty installer data volume through the signed update engine."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import uuid

from sqlalchemy import select

from koda_tracker.config import get_settings
from koda_tracker.data_updates import DataUpdateError, assert_approved_release, managed_state
from koda_tracker.db import SessionLocal
from koda_tracker.models import AuditEvent, Job, JobState
from koda_tracker.offline_intelligence_store import sync_reference_bundle
from koda_tracker.worker import _reset_unified_live_references, _sync_bundle_epss


def _existing(settings):
    root = settings.grype_db_dir.parent.parent
    marker = root / ".managed.json"
    if marker.exists() or marker.is_symlink():
        state = managed_state(settings) or {"state": "unavailable"}
        return {"status": "preserved", "state": state.get("state", "unavailable"),
                "currentVersion": state.get("currentVersion"), "approvalChecked": False}
    current = root / "current"
    if current.exists() or current.is_symlink():
        raise DataUpdateError("Existing unapproved data was preserved; import a signed unified archive through administrator settings")
    return None


def _verify_archive_signature(engine, archive):
    """Authenticate publisher proof before creating anything in the data volume."""
    if archive.is_symlink() or not archive.is_file():
        raise DataUpdateError("Fresh installation requires unified-update.tar.gz signed by the registered data verification key")
    key = engine.settings.data_update_verify_key or os.environ.get("KODA_RELEASE_VERIFY_KEY")
    if not key or not Path(key).is_file() or Path(key).stat().st_size > 65536 or b"PRIVATE KEY" in Path(key).read_bytes():
        raise DataUpdateError("A registered public data verification key is required for installer bootstrap")
    with tempfile.TemporaryDirectory(prefix="koda-bootstrap-proof-") as temporary:
        proof = Path(temporary)
        found = set()
        expanded = 0
        with tarfile.open(archive, "r:gz") as stream:
            for count, member in enumerate(stream, 1):
                expanded += member.size
                if count > engine.limits.max_members or member.size > engine.limits.max_file_bytes or expanded > engine.limits.max_total_bytes:
                    raise DataUpdateError("Bootstrap archive exceeds data-update limits")
                name = member.name.removeprefix("./")
                if name not in {"manifest.sha256", "manifest.sha256.sig"}:
                    continue
                limit = 16 * 1024 * 1024 if name == "manifest.sha256" else 65536
                if name in found or not member.isfile() or not 0 < member.size <= limit:
                    raise DataUpdateError("Invalid signed bootstrap proof")
                source = stream.extractfile(member)
                if source is None:
                    raise DataUpdateError("Missing signed bootstrap proof")
                (proof / name).write_bytes(source.read(limit + 1))
                found.add(name)
        if found != {"manifest.sha256", "manifest.sha256.sig"}:
            raise DataUpdateError("Signed unified bootstrap manifest and signature are required")
        engine._verify_signature(proof)


def bootstrap(archive: Path, *, settings=None, session_factory=None):
    settings = settings or get_settings()
    session_factory = session_factory or SessionLocal
    preserved = _existing(settings)
    if preserved:
        return preserved
    from koda_tracker.data_updates import DataUpdateEngine
    _verify_archive_signature(DataUpdateEngine(settings, read_only=True), archive)
    engine = DataUpdateEngine(settings)
    job_id = "installer-bootstrap-" + uuid.uuid4().hex
    package = None
    activated = None
    with engine.exclusive_access():
        preserved = _existing(settings)
        if preserved:
            return preserved
        with session_factory() as db:
            try:
                if db.scalar(select(Job.id).where(Job.state == JobState.RUNNING,
                                                  Job.kind.in_(["analyze", "process_run", "data_update", "vulnerability_data_update"])).limit(1)):
                    raise DataUpdateError("Analysis or data update is running; retry installer bootstrap after it completes")
                package = engine.stage(archive, "unified")
                release = engine.apply(package, job_id=job_id)
                activated = release.version
                _reset_unified_live_references(db)
                sync_reference_bundle(db, release.path)
                _sync_bundle_epss(db, release.path)
                assert_approved_release(settings, release.path)
                db.add(AuditEvent(actor="installer-bootstrap", action="vuln_data.bootstrap.complete",
                                  target_type="vulnerability_data_bundle", target_id=release.version,
                                  detail={"manifestSha256": package.manifest_sha256}))
                db.commit()
                return {"status": "applied", "state": "active", "currentVersion": release.version, "approvalChecked": True}
            except Exception:
                db.rollback()
                if activated:
                    engine.compensate_activation(release_version=activated, job_id=job_id)
                raise
            finally:
                if package and package.root.is_dir():
                    shutil.rmtree(package.root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(bootstrap(args.archive), ensure_ascii=False))
    except (DataUpdateError, OSError, tarfile.TarError) as exc:
        print("Approved vulnerability bootstrap failed: " + str(exc), file=sys.stderr)
        return 1
    except Exception as exc:
        print("Approved vulnerability bootstrap failed (" + type(exc).__name__ + "); inspect the data updater logs", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
