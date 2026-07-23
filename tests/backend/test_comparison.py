from __future__ import annotations

from koda_tracker.comparison import compare_components
from koda_tracker.models import RunComponent


def component(key: str, version: str, sha: str = "") -> RunComponent:
    return RunComponent(identity_key=key, name=key, version=version, sha256=sha, licenses=[])


def test_compare_components_reports_add_remove_and_change() -> None:
    result = compare_components(
        [component("a", "1"), component("b", "1")],
        [component("a", "2"), component("c", "1")],
    )
    assert {(item["identityKey"], item["change"]) for item in result} == {
        ("a", "changed"),
        ("b", "removed"),
        ("c", "added"),
    }

