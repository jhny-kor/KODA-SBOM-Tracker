from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _module():
    path = Path(__file__).parents[2] / "scripts" / "nvd-alias-index.py"
    spec = importlib.util.spec_from_file_location("nvd_alias_index", path)
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
