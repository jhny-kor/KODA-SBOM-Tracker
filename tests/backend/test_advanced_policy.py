from __future__ import annotations

import copy
from datetime import UTC, datetime
from types import SimpleNamespace
import subprocess

import pytest
from pydantic import ValidationError

from koda_tracker import cel_executor
from koda_tracker.cel_executor import CelPolicyError, execute_cel, validate_expression
from koda_tracker.policies import (
    PolicyDocument, build_cel_contexts, evaluate_document, evaluate_revision,
    policy_context_for_run, preview_expression, validate_policy_expressions,
)
from koda_tracker.models import JobState

AT = datetime(2026, 10, 18, tzinfo=UTC)
SCOPE = {"project": {"id": "service-a", "slug": "orders", "name": "Orders"}, "environment": {"id": "prod", "slug": "production"}, "release": {"version": "1.0"}, "run": {"id": "run-a", "source": "manual", "roundNumber": 1}}
COMPONENT = {"name": "unsafe", "version": "1", "purl": "pkg:pypi/unsafe@1", "licenses": [{"license": {"id": "MIT"}}], "properties": [{"name": "koda:ageDays", "value": "400"}, {"name": "koda:latestVersion", "value": "3"}, {"name": "koda:versionDistance", "value": "2"}]}
FINDING = {"id": "GHSA-1234", "canonicalId": "CVE-2026-10000", "severity": "High", "component": "pkg:pypi/unsafe@1", "version": "1", "kev": True, "cvssScore": 9.2, "fixedIn": ["2", "3"]}


def cel_rule(expression="true", target="vulnerability", **kwargs):
    return {"id": "advanced", "name": "Advanced", "kind": "cel", "expression": expression, "target": target, **kwargs}


def test_real_cel_macros_strings_lists_time_and_metadata():
    expression = 'component.licenses.exists(l, l.matches("^MI.*")) && [1, 2, 3].filter(x, x > 1).map(x, x * 2).all(x, x >= 4) && size(vulnerability.fixedIn) == 2 && vulnerability.cvssScore > 9.0 && component.ageDays > 365 && now - timestamp("2026-10-01T00:00:00Z") > duration("24h")'
    document = PolicyDocument(rules=[cel_rule(expression)])
    rows, metrics = evaluate_document(document, [COMPONENT], [FINDING], evaluated_at=AT, project_context=SCOPE)
    assert len(rows) == 1
    assert rows[0]["target"] == "vulnerability"
    assert rows[0]["expression"] == expression
    assert rows[0]["component"] == COMPONENT["purl"]
    assert rows[0]["vulnerabilityId"] == FINDING["canonicalId"]
    assert metrics["policyStatus"] == "fail"


@pytest.mark.parametrize("kind", ["cel", "component_denied"])
def test_scopes_intersect_and_empty_scopes_are_global(kind):
    base = cel_rule(target="component") if kind == "cel" else {"id": "advanced", "name": "Advanced", "kind": kind, "values": ["unsafe"]}
    scoped = {**base, "serviceIds": ["service-a"], "environmentIds": ["prod"], "releaseVersions": ["1.0"]}
    doc = PolicyDocument(rules=[scoped])
    assert len(evaluate_document(doc, [COMPONENT], [], project_context=SCOPE)[0]) == 1
    for section, key, value in [("project", "id", "other"), ("environment", "id", "dev"), ("release", "version", "2.0")]:
        context = copy.deepcopy(SCOPE)
        context[section][key] = value
        assert evaluate_document(doc, [COMPONENT], [], project_context=context)[0] == []
    assert evaluate_document(doc, [COMPONENT], [])[0] == []
    assert len(evaluate_document(PolicyDocument(rules=[base]), [COMPONENT], [])[0]) == 1


def test_component_once_per_component_project_once_and_false_is_pass():
    doc = PolicyDocument(rules=[cel_rule('component.name == "unsafe"', "component"), cel_rule('project.slug == "orders" && environment.id == "prod" && release.version == "1.0"', "project", id="project"), cel_rule("false", id="false")])
    rows, metrics = evaluate_document(doc, [COMPONENT], [FINDING, FINDING], project_context=SCOPE)
    assert len(rows) == 2
    assert {row["target"] for row in rows} == {"component", "project"}
    assert metrics["policyViolationCount"] == 2


@pytest.mark.parametrize("expression", ['component.missing > 1', '1 / 0 > 0', '"string"', 'component.name +', 'os.getenv("SECRET") == "x"', '__import__("os")'])
def test_missing_data_type_compile_and_host_calls_fail_closed(expression):
    with pytest.raises(CelPolicyError):
        evaluate_document(PolicyDocument(rules=[cel_rule(expression, "component")]), [COMPONENT], [])


def test_optional_metadata_requires_explicit_source_and_has_guard():
    contexts = build_cel_contexts([{"name": "plain", "version": "1"}], [], evaluated_at=AT)
    component = contexts["component"][0]["component"]
    assert "ageDays" not in component and "latestVersion" not in component
    assert validate_expression('has(component.ageDays) && component.ageDays > 1', "component", contexts["component"][0])["result"] is False
    dated = {"name": "dated", "properties": [{"name": "koda:publishedAt", "value": "2026-10-01T00:00:00Z"}]}
    assert build_cel_contexts([dated], [], evaluated_at=AT)["component"][0]["component"]["ageDays"] == 17


def test_compile_and_preview_do_not_modify_document_or_input():
    doc = PolicyDocument(rules=[cel_rule('vulnerability.kev && component.licenses.exists(x, x == "MIT")')])
    before = doc.model_dump(mode="json")
    component, finding = copy.deepcopy(COMPONENT), copy.deepcopy(FINDING)
    validate_policy_expressions(doc)
    result = preview_expression(doc.rules[0].expression, "vulnerability", [component], [finding], SCOPE)
    assert result["matchCount"] == result["evaluatedCount"] == 1
    assert doc.model_dump(mode="json") == before
    assert component == COMPONENT and finding == FINDING
    assert validate_expression("true")["runtime"] == "cel-expr-python"


def test_policy_revision_retains_snapshot_and_marks_cel_errors_failed(monkeypatch):
    from koda_tracker import policies
    raw = {"rules": [cel_rule('component.unknown > 3', "component")], "exceptions": []}
    monkeypatch.setattr(policies, "get_policy_document", lambda db: SimpleNamespace(version=8, document=raw))
    run = SimpleNamespace(normalized_bom={"components": [COMPONENT]})
    revision = SimpleNamespace(state=JobState.COMPLETED, data_sources={}, findings=[], data_as_of=None, tool_version="test")
    evaluate_revision(None, run, revision)
    assert revision.policy_state == "failed"
    assert revision.metrics["policyStatus"] == "error"
    assert revision.policy_snapshot == raw and revision.policy_version == 8
    raw["rules"][0]["expression"] = "false"
    assert revision.policy_snapshot["rules"][0]["expression"] != "false"


def test_json_only_input_limits_and_timeout(monkeypatch):
    with pytest.raises(CelPolicyError, match="JSON"):
        execute_cel({"contexts": {"x": object()}})
    monkeypatch.setattr(cel_executor, "MAX_INPUT_BYTES", 20)
    with pytest.raises(CelPolicyError, match="32 MiB"):
        execute_cel({"x": "a" * 100})
    monkeypatch.setattr(cel_executor, "MAX_INPUT_BYTES", 1024 * 1024)
    def timeout(*args, **kwargs):
        assert kwargs["env"].keys() == {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE"}
        assert args[0][1] == "-I" and kwargs["close_fds"] is True
        raise subprocess.TimeoutExpired("CEL", 10)
    monkeypatch.setattr(cel_executor.subprocess, "run", timeout)
    with pytest.raises(CelPolicyError, match="제한시간"):
        validate_expression("true")


def test_expression_and_scope_schema_limits():
    for kwargs in ({"expression": ""}, {"expression": "x" * 8193}, {"serviceIds": [" "]}, {"environmentIds": ["a", "a"]}, {"values": ["bad"]}):
        with pytest.raises(ValidationError):
            PolicyDocument(rules=[cel_rule(**kwargs)])
    with pytest.raises(CelPolicyError, match="bool"):
        validate_expression("42")


def test_run_context_uses_actual_release_identity():
    run = SimpleNamespace(id="r", source="gitlab", round_number=3, release=SimpleNamespace(version="2", service=SimpleNamespace(id="s", slug="service", name="Service"), environment=SimpleNamespace(id="e", slug="dev", name="Dev")))
    context = policy_context_for_run(run)
    assert context["project"]["id"] == "s" and context["environment"]["id"] == "e"
    assert context["run"] == {"id": "r", "source": "gitlab", "roundNumber": 3}


def test_evaluation_budget_is_enforced_inside_child():
    with pytest.raises(CelPolicyError, match="100,000"):
        execute_cel({"expressions": [{"id": "budget", "expression": "true", "target": "project"}], "contexts": {"project": [{}] * 100001}})


def test_real_expensive_comprehension_is_terminated():
    values = "[" + ",".join(str(value) for value in range(100)) + "]"
    expression = "true"
    for depth in range(6):
        expression = f"{values}.all(x{depth}, {expression})"
    with pytest.raises(CelPolicyError, match="Iteration budget exceeded|제한시간"):
        validate_expression(expression, "project", {})
