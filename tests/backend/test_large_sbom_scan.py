import json
import os
import sys
from pathlib import Path

import pytest

from koda_tracker import large_sbom_scan as scan
from koda_tracker.sbom import iter_components


def component(ref: str, *, purl: str | None = None, kind: str = "library", **extra) -> dict:
    return {"type": kind, "name": ref, "version": "1", "bom-ref": ref, **({"purl": purl} if purl else {}), **extra}


@pytest.mark.parametrize("spec_version", ["1.6", "1.7"])
def test_batches_share_distro_and_scan_components_once(tmp_path: Path, monkeypatch, spec_version):
    monkeypatch.setattr(scan, "_MAX_BATCH_COMPONENTS", 1)
    distro = component("os", kind="operating-system", properties=[{"name": "versionID", "value": "20.04"}])
    packages = [
        component(
            "first", purl="pkg:deb/ubuntu/first@1?distro=ubuntu-20.04",
            evidence={"occurrences": [{"location": "/first"}]},
            properties=[{"name": "syft:location:0:path", "value": "/first"}],
        ),
        {**distro, "components": [component("nested")]},
        component("last"),
    ]
    base = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "metadata": {"component": component("root", kind="file", components=[component("inside-root")])},
    }
    scanned = []
    files = []

    def fake_grype(binary, document, output, env, deadline):
        actual = json.loads(document.read_bytes())
        files.append(actual)
        records = [actual["metadata"]["component"], *actual["components"]]
        output.write_text(json.dumps({
            "descriptor": {"version": "0.109.1"},
            "matches": [{"artifact": {"id": value["bom-ref"]}, "vulnerability": {"id": "CVE-MATCH"}}
                        for value in iter_components(records) if value["type"] == "library"],
        }))

    monkeypatch.setattr(scan, "_run_batch", fake_grype)
    version = scan.scan_large_sbom(base, lambda: iter(packages), binary="grype", env={}, spool=tmp_path,
                                   on_match=lambda match: scanned.append(match["artifact"]["id"]))

    assert version == "0.109.1"
    assert scanned == ["inside-root", "first", "nested", "last"]
    assert len(files) == 3
    assert all(data["specVersion"] == "1.6" for data in files)
    assert base["specVersion"] == spec_version
    assert all(data["components"][0] == distro for data in files)
    assert all(data["metadata"]["component"]["type"] == "file" for data in files)
    assert "evidence" not in files[0]["components"][-1]
    assert files[0]["components"][-1]["properties"] == packages[0]["properties"]
    assert packages[0]["evidence"]["occurrences"][0]["location"] == "/first"
    assert not list(tmp_path.iterdir())


def test_grype_scanner_output_is_bounded_and_temp_files_are_removed(tmp_path: Path, monkeypatch):
    fake = tmp_path / "grype"
    fake.write_text(f"#!{sys.executable}\nimport sys\nsys.stdout.write('x' * 131072)\n")
    fake.chmod(0o700)
    monkeypatch.setattr(scan, "_MAX_RESULT_BYTES", 1024)
    base = {"bomFormat": "CycloneDX", "specVersion": "1.6"}

    with pytest.raises(ValueError, match="결과 크기 한도"):
        scan.scan_large_sbom(base, lambda: iter([component("project")]), binary=str(fake),
                             env=os.environ.copy(), spool=tmp_path, on_match=lambda _: pytest.fail())

    assert list(tmp_path.iterdir()) == [fake]
