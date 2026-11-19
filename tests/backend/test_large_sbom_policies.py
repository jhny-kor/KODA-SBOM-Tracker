from types import SimpleNamespace

import pytest

from koda_tracker import large_sbom, policies
from koda_tracker.cel_executor import CelPolicyError


@pytest.fixture
def split_run(monkeypatch):
    nested = {"bom-ref": "b", "type": "library", "name": "nested"}
    component = {"bom-ref": "a", "type": "library", "name": "application", "components": [nested]}
    run = SimpleNamespace(id="split-run", split_document=True,
                          normalized_bom={"metadata": {"component": {"bom-ref": "root"}},
                                          "dependencies": [{"ref": "root", "dependsOn": ["a"]}],
                                          "components": [component]})
    original = {**component, "components": [{**nested, "properties": [{"name": "wanted", "value": "nested"}]}],
                "properties": [{"name": "unrelated", "value": "x" * 2048},
                               {"name": "wanted", "value": "first"}, {"name": "wanted", "value": "last"}]}
    monkeypatch.setattr(large_sbom, "iter_large_records", lambda db, run_id, section: iter([original]))
    return run


@pytest.mark.parametrize("expression", [
    'component.properties["wanted"] == "last"',
    "component.properties.wanted == 'last'",
    "component['properties']['wanted'] == 'last'",
])
def test_literal_property_selectors_preserve_nested_order_and_duplicate_values(split_run, monkeypatch, expression):
    monkeypatch.setattr(policies, "_MAX_SPLIT_POLICY_PROPERTY_BYTES", 200)
    records = policies.policy_components_for_run(None, split_run, [expression])
    assert [item["isDirectDependency"] for item in records] == [True, False]
    assert policies.preview_expression(expression, "component", records, []) == {
        "valid": True, "target": "component", "evaluatedCount": 2, "matchCount": 1,
        "matchedIndexes": [0], "truncated": False,
    }


@pytest.mark.parametrize("expression", [
    'component["proper" + "ties"]["wanted"] == "last"',
    'component.properties.exists(k, k == "wanted")',
    'size(component.properties) == 1',
    'component.properties.size // comment\n() == 1',
])
def test_dynamic_and_whole_map_reads_fail_explicitly_if_over_budget(split_run, monkeypatch, expression):
    monkeypatch.setattr(policies, "_MAX_SPLIT_POLICY_PROPERTY_BYTES", 200)
    with pytest.raises(CelPolicyError, match="속성 데이터가 처리 한도"):
        policies.policy_components_for_run(None, split_run, [expression])


def test_policy_without_property_reads_does_not_load_full_records(split_run, monkeypatch):
    def unexpected_read(*args, **kwargs):
        pytest.fail("A policy without property lookups should use the indexed component view")

    monkeypatch.setattr(large_sbom, "iter_large_records", unexpected_read)
    components = policies.policy_components_for_run(None, split_run, ['component.name == "application"'])
    assert [item["name"] for item in components] == ["application", "nested"]
