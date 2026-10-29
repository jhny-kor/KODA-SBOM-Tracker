"""Installer initialization uses the same signed activation as administrator updates."""
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest
from sqlalchemy import func, select

from test_ssvc import setup  # noqa: F401 - fixture dependency
from test_unified_data_lifecycle import unified  # noqa: F401 - shared signed-source fixture
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, assert_approved_release, managed_state
from koda_tracker.models import AnalysisRevision, AuditEvent, SbomRun, User
from koda_tracker.offline_intelligence_models import OfflineReferenceSnapshot
from koda_tracker.vulnerability_intelligence_models import VulnerabilityIntelligence


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("installer_bootstrap", ROOT / "scripts/bootstrap-vuln-data.py")
bootstrap_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap_module)


def _snapshot(root):
    return {str(path.relative_to(root)): (path.readlink().as_posix() if path.is_symlink() else path.read_bytes())
            for path in root.rglob("*") if path.is_symlink() or path.is_file()}


def test_fresh_signed_bootstrap_creates_approval_and_projects_reference_database(unified):
    db, _, run, revision, settings, archive = unified
    result = bootstrap_module.bootstrap(archive(), settings=settings, session_factory=lambda: db)
    root = settings.grype_db_dir.parent.parent
    assert result == {"status": "applied", "state": "active", "currentVersion": "bundle-1", "approvalChecked": True}
    assert managed_state(settings)["state"] == "active"
    assert (root / ".release.lock").is_file()
    current = (root / "current").resolve()
    assert all((current / name).is_file() for name in ("approved-metadata.env", "approved-manifest.sha256", "approved-manifest.sha256.sig"))
    assert_approved_release(settings, current)
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot)) == 11
    assert db.get(VulnerabilityIntelligence, "CVE-2026-12345").document["epss"] == .8
    assert db.get(SbomRun, run.id) is not None and db.get(AnalysisRevision, revision.id) is not None
    assert db.scalar(select(func.count()).select_from(User)) == 2
    assert db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "vuln_data.bootstrap.complete")) == 1


@pytest.mark.parametrize("state", ["active", "purged", "purging", "unavailable"])
def test_repeat_bootstrap_preserves_existing_managed_state_without_even_reading_new_seed(unified, state, tmp_path):
    db, _, _, _, settings, archive = unified
    bootstrap_module.bootstrap(archive(), settings=settings, session_factory=lambda: db)
    if state != "active":
        DataUpdateEngine(settings).write_managed(state, version="bundle-1")
    root = settings.grype_db_dir.parent.parent
    before = _snapshot(root)
    settings.data_update_verify_key = str(tmp_path / "missing-unrelated-key.pub")
    result = bootstrap_module.bootstrap(tmp_path / "missing-seed.tar.gz", settings=settings,
                                        session_factory=lambda: pytest.fail("preserved install touched the database"))
    assert result == {"status": "preserved", "state": state, "currentVersion": "bundle-1", "approvalChecked": False}
    assert _snapshot(root) == before


@pytest.mark.parametrize("kind", ["missing", "unsigned", "wrong-key"])
def test_missing_or_untrusted_bootstrap_fails_before_creating_data_volume(unified, tmp_path, kind):
    _, _, _, _, settings, archive = unified
    source = tmp_path / "missing.tar.gz" if kind == "missing" else archive(sign=kind != "unsigned")
    if kind == "wrong-key":
        private = tmp_path / "wrong-private.pem"
        public = tmp_path / "wrong-public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
        settings.data_update_verify_key = str(public)
    with pytest.raises(DataUpdateError):
        bootstrap_module.bootstrap(source, settings=settings,
                                    session_factory=lambda: pytest.fail("untrusted bootstrap touched the database"))
    assert not settings.grype_db_dir.parent.parent.exists()


def test_legacy_current_is_never_overwritten_by_automatic_bootstrap(unified):
    db, _, _, _, settings, archive = unified
    root = settings.grype_db_dir.parent.parent
    old = root / "releases/legacy"
    old.mkdir(parents=True)
    (old / "original.json").write_text("preserved source")
    (root / "current").symlink_to("releases/legacy")
    before = _snapshot(root)
    with pytest.raises(DataUpdateError, match="Existing unapproved data was preserved"):
        bootstrap_module.bootstrap(archive(), settings=settings, session_factory=lambda: db)
    assert _snapshot(root) == before


def test_reference_database_failure_compensates_approval_instead_of_reporting_success(unified, monkeypatch):
    db, _, _, _, settings, archive = unified
    def fail_projection(*args, **kwargs):
        raise RuntimeError("reference projection failed")
    monkeypatch.setattr(bootstrap_module, "sync_reference_bundle", fail_projection)
    with pytest.raises(RuntimeError, match="reference projection failed"):
        bootstrap_module.bootstrap(archive(), settings=settings, session_factory=lambda: db)
    root = settings.grype_db_dir.parent.parent
    assert not (root / "current").exists()
    assert json.loads((root / ".managed.json").read_text())["state"] == "unavailable"
    assert db.scalar(select(func.count()).select_from(OfflineReferenceSnapshot)) == 0


def test_installer_cli_does_not_report_success_for_preserved_unavailable_data(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["bootstrap-vuln-data.py", "/unused/unified-update.tar.gz"])
    monkeypatch.setattr(bootstrap_module, "bootstrap", lambda archive: {
        "status": "preserved", "state": "unavailable", "approvalChecked": False,
    })
    assert bootstrap_module.main() == 1
    output = capsys.readouterr()
    assert "Existing unavailable data was preserved" in output.err
    assert not output.out
