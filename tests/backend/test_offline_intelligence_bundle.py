import importlib.util
import json
import shutil
import subprocess
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from koda_tracker.config import Settings
from koda_tracker.data_updates import DataUpdateEngine, DataUpdateError, _metadata, validate_package
from koda_tracker.offline_intelligence import load_intelligence
from test_offline_intelligence_formats import AT, DATE, fixtures

ROOT = Path(__file__).parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def source_bundle(tmp_path):
    sources = tmp_path / "approved"
    sources.mkdir()
    descriptors = []
    for kind, raw in fixtures().items():
        (sources / f"{kind}.bin").write_bytes(raw)
        descriptors.append({"id": kind, "kind": kind, "path": f"{kind}.bin", "sourceUrl": f"https://vendor.test/{kind}", "dataDate": DATE, "fetchedAt": AT.isoformat()})
    output = tmp_path / "source"
    module("collector", "collect-offline-intelligence.py").collect({"sources": descriptors}, output, base=sources)
    (output / "nvd.json").write_text('{"vulnerabilities":{}}')
    (output / "kev.json").write_text('{"vulnerabilities":[],"dateReleased":"2026-10-19"}')
    (output / "epss.csv").write_bytes(fixtures()["epss"])
    return output


def runner(command, **kwargs):
    if command[1] == "db":
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"valid": True, "schemaVersion": "6", "path": kwargs["env"]["GRYPE_DB_CACHE_DIR"] + "/6/vulnerability.db"}))
    return SimpleNamespace(returncode=0, stderr="", stdout='{"matches":[]}')


def engine(tmp_path):
    settings = Settings(grype_db_dir=tmp_path / "runtime/current/grype-db")
    current = settings.grype_db_dir.parent
    (current / "grype-db/6").mkdir(parents=True)
    (current / "grype-db/6/vulnerability.db").write_bytes(b"fixture database")
    (current / "grype-db/6/import.json").write_text("{}")
    (current / "nvd.json").write_text('{"vulnerabilities":{}}')
    (current / "kev.json").write_text('{"vulnerabilities":[]}')
    (current / "metadata.env").write_text("BUNDLE_VERSION=legacy\nGRYPE_DB_SCHEMA=6\nNVD_INDEX=nvd.json\nKEV_CATALOG=kev.json\nDATASET_DATE=2026-10-19\n")
    value = DataUpdateEngine(settings, runner=runner)
    value.migrate_legacy(version="base")
    return value


def test_collection_typed_build_validation_activation_removal_and_rollback(tmp_path):
    source = source_bundle(tmp_path)
    builder = module("builder", "build-data-update.py")
    archive = builder.build("vuln-data", source, tmp_path / "one.tar.gz", "one", DATE)
    assert validate_package(archive, "vuln-data").metadata["INTELLIGENCE_INDEX"] == "intelligence.json"
    lifecycle = engine(tmp_path)
    staged = lifecycle.stage(archive, "vuln-data", expected_base_version="base")
    active = lifecycle.apply(staged, expected_base_version="base")
    assert set(load_intelligence(active.path)["datasets"]) == set(fixtures())
    assert (active.path / "epss.csv").read_bytes() == fixtures()["epss"]
    missing = tmp_path / "without-optional"
    missing.mkdir()
    for name in ("nvd.json", "kev.json"):
        shutil.copy2(source / name, missing / name)
    second = builder.build("vuln-data", missing, tmp_path / "two.tar.gz", "two", DATE)
    lifecycle.apply(lifecycle.stage(second, "vuln-data", expected_base_version="one"), expected_base_version="one")
    assert not (lifecycle.current().path / "intelligence.json").exists()
    assert "INTELLIGENCE_INDEX" not in _metadata(lifecycle.current().path / "metadata.env")
    restored = lifecycle.rollback("vuln-data", version="one")
    assert load_intelligence(restored.path)["datasets"]["epss"]["records"][0]["date"] == DATE
    assert (restored.path / "epss.csv").read_bytes() == fixtures()["epss"]


def test_legacy_builder_sidecars_are_manifest_bound_and_tampering_refused(tmp_path):
    source = source_bundle(tmp_path)
    grype = tmp_path / "grype/6"
    grype.mkdir(parents=True)
    (grype / "vulnerability.db").write_bytes(b"fixture")
    (grype / "import.json").write_text("{}")
    output = tmp_path / "legacy-bundle"
    subprocess.run(["bash", str(ROOT / "scripts/build-vuln-bundle.sh"), str(output), "--grype-db", str(grype.parent), "--data-date", DATE,
                    "--nvd-index", str(source / "nvd.json"), "--kev", str(source / "kev.json"), "--epss", str(source / "epss.csv"),
                    "--intelligence-index", str(source / "intelligence.json")], check=True, capture_output=True)
    subprocess.run(["bash", str(ROOT / "scripts/verify-vuln-bundle.sh"), str(output)], check=True, capture_output=True)
    assert "INTELLIGENCE_INDEX=intelligence.json" in (output / "metadata.env").read_text()
    raw = next((output / "intelligence-sources").iterdir())
    raw.write_bytes(b"corrupt")
    result = subprocess.run(["bash", str(ROOT / "scripts/verify-vuln-bundle.sh"), str(output)], capture_output=True)
    assert result.returncode != 0


def test_unsafe_normalized_record_change_rejected_before_package_activation(tmp_path):
    source = source_bundle(tmp_path)
    index = json.loads((source / "intelligence.json").read_text())
    index["datasets"]["vulnrichment"]["records"][0]["exploitation"] = "none"
    (source / "intelligence.json").write_text(json.dumps(index))
    with pytest.raises(ValueError, match="differ"):
        module("builder", "build-data-update.py").build("vuln-data", source, tmp_path / "bad.tar.gz", "bad", DATE)
    assert not (tmp_path / "bad.tar.gz").exists()


def test_projection_failure_compensation_restores_exact_pointers_and_respects_newer_job(tmp_path):
    source = source_bundle(tmp_path)
    builder = module("builder", "build-data-update.py")
    lifecycle = engine(tmp_path)
    def apply(version, expected, job):
        archive = builder.build("vuln-data", source, tmp_path / f"{version}.tar.gz", version, DATE)
        return lifecycle.apply(lifecycle.stage(archive, "vuln-data", expected_base_version=expected), expected_base_version=expected, job_id=job)
    first = apply("one", "base", "job-one")
    assert lifecycle.compensate_activation(release_version=first.version, job_id="other-job") is False
    assert lifecycle.compensate_activation(release_version=first.version, job_id="job-one") is True
    assert lifecycle.status() == {"current": "base", "previous": None}
    second = apply("two", "base", "job-two")
    third = apply("three", "two", "job-three")
    assert lifecycle.compensate_activation(release_version=second.version, job_id="job-two") is False
    assert lifecycle.status()["current"] == "three"
    assert lifecycle.compensate_activation(release_version=third.version, job_id="job-three") is True
    assert lifecycle.status() == {"current": "two", "previous": "base"}


def test_distribution_explicitly_ships_parser_and_helpers_run_without_apps(tmp_path):
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "apps/api/koda_tracker").mkdir(parents=True)
    for name in ("build-airgap-release.sh", "lib.sh", "release-images.sh", "stage-intelligence.py", "collect-offline-intelligence.py"):
        shutil.copy2(ROOT / "scripts" / name, repo / "scripts" / name)
    shutil.copy2(ROOT / "apps/api/koda_tracker/offline_intelligence.py", repo / "apps/api/koda_tracker/offline_intelligence.py")
    for directory in ("docs", "deploy/manifests"):
        (repo / directory).mkdir(parents=True)
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "compose.yaml", "compose.airgap.yaml", "deploy/manifests/images.lock"):
        (repo / name).write_text("fixture\n")
    shutil.copy2(ROOT / "compose.data-key.yaml", repo / "compose.data-key.yaml")
    (repo / ".env.example").write_text("\n".join(f"{key}={value}" for key, value in {
        "POSTGRES_IMAGE": "postgres:fixture", "NGINX_IMAGE": "nginx:fixture", "GRYPE_IMAGE": "grype:fixture", "CYCLONEDX_CLI_IMAGE": "cdx:fixture", "ALPINE_BASE_IMAGE": "alpine:fixture",
        "PORTAL_WEB_IMAGE": "web", "PORTAL_API_IMAGE": "api", "PORTAL_WORKER_IMAGE": "worker", "PORTAL_IMAGE_TAG": "fixture"}.items()) + "\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "git").write_text('#!/bin/sh\ncase "$*" in *"rev-parse --short=12 HEAD"*) echo 0123456789ab;; *"rev-parse HEAD"*) echo fixture-commit;; esac\nexit 0\n')
    (bin_dir / "docker").write_text('''#!/usr/bin/env python3
import sys
from pathlib import Path
args=sys.argv[1:]
if args[:2]==["image","inspect"]: print("amd64")
if args and args[0]=="save": Path(args[args.index("-o")+1]).write_bytes(b"image fixture")
''')
    for file in bin_dir.iterdir():
        file.chmod(0o755)
    output = tmp_path / "release.tar.gz"
    environment = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "KODA_ALLOW_UNSIGNED_ARTIFACTS": "1", "TRACKER_RELEASE_MODE": "development"}
    result = subprocess.run(["bash", str(repo / "scripts/build-airgap-release.sh"), str(output)], env=environment, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    installed = tmp_path / "installed"
    with tarfile.open(output) as archive:
        archive.extractall(installed, filter="data")
    assert (installed / "compose.data-key.yaml").read_bytes() == (ROOT / "compose.data-key.yaml").read_bytes()
    identity = (installed / "config/release-images.env").read_text()
    assert "PORTAL_IMAGE_TAG=" in identity and "0123456789ab" in identity
    assert "PORTAL_IMAGE_TAG=fixture" not in (installed / "config/.env.example").read_text()
    assert "IMAGE_BUILT_AT=" in (installed / "metadata.env").read_text()
    assert not (installed / "apps").exists() and not (installed / "source/apps").exists()
    assert (installed / "scripts/offline_intelligence.py").read_bytes() == (ROOT / "apps/api/koda_tracker/offline_intelligence.py").read_bytes()
    epss = tmp_path / "epss.csv"
    epss.write_bytes(fixtures()["epss"])
    stage = tmp_path / "stage"
    stage.mkdir()
    staged = subprocess.run(["python3", str(installed / "scripts/stage-intelligence.py"), "--destination", str(stage), "--epss", str(epss)], check=True, capture_output=True, text=True)
    assert "EPSS_DATASET_DATE=2026-10-19" in staged.stdout
