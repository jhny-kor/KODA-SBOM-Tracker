from __future__ import annotations

import gzip
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).parents[2] / "scripts" / "nvd-alias-index.py"

def _module():
    spec = importlib.util.spec_from_file_location("nvd_alias_index", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_nvd_feed_is_reduced_to_cve_and_reference_aliases(tmp_path: Path) -> None:
    feed = tmp_path / "nvdcve-2.0-test.json"
    feed.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-12345",
                            "references": [
                                {"url": "https://github.com/advisories/GHSA-abcd-1234-efgh"},
                                {"url": "https://example.test/CVE-2024-12345"},
                            ],
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    aliases, records = _module().build_index([feed])

    assert records == 1
    assert aliases["CVE-2024-12345"] == "CVE-2024-12345"
    assert aliases["GHSA-ABCD-1234-EFGH"] == "CVE-2024-12345"


def test_nvd_metadata_keeps_offline_cvss_description_and_cpe(tmp_path: Path) -> None:
    feed = tmp_path / "nvdcve-2.0-test.json"
    feed.write_text(json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2024-12345",
        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:example:thing:*:*:*:*:*:*:*:*"}]}]}],
        "references": [{"url": "https://example.test/advisory"}],
    }}]}), encoding="utf-8")

    aliases, details, records = _module().build_metadata([feed])

    assert records == 1
    assert aliases["CVE-2024-12345"] == "CVE-2024-12345"
    assert details["CVE-2024-12345"]["description"] == "Example vulnerability"
    assert details["CVE-2024-12345"]["cvss"]["cvssV3"]["baseScore"] == 8.8
    assert details["CVE-2024-12345"]["cpe"] == ["cpe:2.3:a:example:thing:*:*:*:*:*:*:*:*"]


def test_nvd_metadata_keeps_latest_revision_when_feeds_overlap(tmp_path: Path) -> None:
    identifier = "CVE-2024-12345"
    feeds = []
    for name, timestamp in [("modified", "2026-11-09T10:00:00.123"), ("recent", "2026-11-08T10:00:00.123")]:
        feed = tmp_path / f"nvdcve-2.0-{name}.json"
        feed.write_text(json.dumps({"vulnerabilities": [{"cve": {
            "id": identifier,
            "lastModified": timestamp,
            "descriptions": [{"lang": "en", "value": name}],
        }}]}), encoding="utf-8")
        feeds.append(feed)

    _, details, records = _module().build_metadata(feeds)

    assert records == 2
    assert details[identifier]["description"] == "modified"


def test_streamed_index_keeps_canonical_priority_and_latest_revision(tmp_path: Path) -> None:
    module = _module()
    first_id = "CVE-2024-12345"
    second_id = "CVE-2024-23456"
    discarded_id = "CVE-2024-34567"
    shared_alias = "GHSA-ABCD-1234-EFGH"
    old_alias = "GHSA-QRST-5678-UVWX"
    long_description = ("한글" + '\\\"') * 40_000

    def record(cve_id, modified=None, *, description="", references=()):
        return {"cve": {"id": cve_id, "lastModified": modified,
                        "descriptions": [{"lang": "ko", "value": description}],
                        "references": [{"url": f"https://example.test/{alias}"} for alias in references]}}

    first = record(first_id, "2026-11-09", description="same timestamp, earlier record",
                   references=(second_id, shared_alias))
    second = record(second_id, description="second", references=(shared_alias,))
    latest = record(first_id, "2026-11-09", description=long_description)
    stale = record(first_id, "2026-11-08", description="stale", references=(old_alias,))
    annual = tmp_path / "nvdcve-2.0-2024.json.gz"
    with gzip.open(annual, "wt", encoding="utf-8") as file:
        file.write(json.dumps({"timestamp": "2026-11-09", "vulnerabilities": [first, second]}))
    modified = tmp_path / "nvdcve-2.0-modified.json"
    modified.write_text(
        '{"vulnerabilities": ' + json.dumps([record(discarded_id)]) +
        ', "vulnerabilities": ' + json.dumps([latest, stale, record(first_id), False], ensure_ascii=False) + "}",
        encoding="utf-8",
    )
    output = tmp_path / "out" / "index.json"
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--output", str(output), str(annual), str(modified)],
                            text=True, capture_output=True, check=True)

    expected = {
        "aliases": {first_id: first_id, second_id: second_id, shared_alias: first_id, old_alias: first_id},
        "vulnerabilities": {first_id: module._cve_record(latest), second_id: module._cve_record(second)},
    }
    assert "5 CVE records, 4 identifiers" in result.stdout
    assert output.read_text(encoding="utf-8") == json.dumps(expected, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    assert list(output.parent.iterdir()) == [output]


@pytest.mark.parametrize("source", ['[{"id": "CVE-2026-12345"}] trailing', '{"vulnerabilities": ['])
def test_bad_feed_leaves_previous_output_and_removes_staging_files(tmp_path: Path, source: str) -> None:
    feed = tmp_path / "bad.json"
    feed.write_text(source, encoding="utf-8")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    output = output_dir / "nvd.json"
    output.write_bytes(b"previous index")
    result = subprocess.run([sys.executable, "-I", str(SCRIPT), "--output", str(output), str(feed)],
                            text=True, capture_output=True)
    assert result.returncode == 1
    assert "NVD index build failed" in result.stderr
    assert feed.name in result.stderr
    assert output.read_bytes() == b"previous index"
    assert list(output_dir.iterdir()) == [output]


def test_external_tools_indexer_loads_reader_from_scheduled_package_source(tmp_path: Path) -> None:
    scripts = tmp_path / "external-tools" / "scripts"
    backend = tmp_path / "source" / "tracker" / "koda_tracker"
    scripts.mkdir(parents=True)
    backend.mkdir(parents=True)
    installed_script = shutil.copy2(SCRIPT, scripts)
    shutil.copy2(SCRIPT.parents[1] / "apps/api/koda_tracker/streaming_nvd.py", backend)
    feed = tmp_path / "feed.json"
    feed.write_text('[{"id":"CVE-2026-12345"}]', encoding="utf-8")
    output = tmp_path / "nvd.json"

    subprocess.run([sys.executable, "-I", installed_script, "--output", str(output), str(feed)],
                   capture_output=True, check=True)

    assert json.loads(output.read_text(encoding="utf-8"))["aliases"] == {"CVE-2026-12345": "CVE-2026-12345"}
