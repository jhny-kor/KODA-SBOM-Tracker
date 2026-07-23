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
