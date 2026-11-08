from __future__ import annotations

import json
from pathlib import Path
import runpy

from packaging.version import Version
from pydantic import ValidationError
import pytest

from koda_tracker.upgrade_python import PythonEvidence, eval_python, python_version_key

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = "pkg:pypi/app-core"
PYTHON_ENVIRONMENT = {
    "implementation_name": "cpython",
    "implementation_version": "3.11.8",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_release": "5.15",
    "platform_system": "Linux",
    "platform_version": "#1",
    "python_full_version": "3.11.8",
    "platform_python_implementation": "CPython",
    "python_version": "3.11",
    "sys_platform": "linux",
}
TARGET = {
    "pythonVersion": "3.11.8",
    "pythonImplementation": "cpython",
    "pythonSysPlatform": "linux",
    "architecture": "amd64",
    "os": "Ubuntu 22.04",
}
OBSERVED = {CANDIDATE: {"2.8"}, "pkg:pypi/transitive-lib": {"1.1"}, "pkg:deb/zlib": {"1.2"}}


def _resolved() -> dict:
    return {
        "kind": "python",
        "outcome": "resolved",
        "source": "isolated-ci/123/pip",
        "environment": PYTHON_ENVIRONMENT.copy(),
        "pipVersion": "26.1.2",
        "reportSha256": "a" * 64,
        "packages": [
            {"name": "app_core", "version": "2.8.0", "requested": True, "wheelSha256": "b" * 64},
            {"name": "Transitive.Lib", "version": "1.1", "requested": False, "wheelSha256": "c" * 64},
        ],
    }


def test_python_version_order_matches_pep440():
    versions = [
        "2.8", "1.0.post1", "1.0.dev1", "1.0a1", "2!0.9", "1.0a1.dev2",
        "1.0.post1.dev5", "1.0RC1", "1.0b2", "1.0+abc.1", "1.0+1.abc",
        "1.0", "1.0.rev1", "1.0-2", "1.0+abc.5", "v1.0.0", "1.0+abc",
        "1.0b2.post3.dev4", "1.1.dev0", "1.0preview", "1.0.r0", "1.0.0.0.1",
    ]
    assert sorted(versions, key=python_version_key) == sorted(versions, key=Version)
    assert python_version_key(" v1.0-1 ") == python_version_key("1.0.post1")
    assert python_version_key("2.8") == python_version_key("2.8.0")
    assert python_version_key("latest") is None
    assert python_version_key("1.0+K") is None


def test_wheel_plan_checks_entire_scoped_candidate_python_sbom():
    evidence = PythonEvidence.model_validate(_resolved())
    assert eval_python(evidence, "2.8", CANDIDATE, TARGET, OBSERVED)[0] == "conditions_met"
    assert eval_python(evidence, "2.9", CANDIDATE, TARGET, OBSERVED)[0] == "unknown"
    for bad_sbom in [
        {CANDIDATE: {"2.8"}},
        {**OBSERVED, "pkg:pypi/unaccounted": {"2.4"}},
        {**OBSERVED, "pkg:pypi/transitive-lib": {"1.2"}},
        {**OBSERVED, "pkg:pypi/transitive-lib": {"1.1", "1.2"}},
    ]:
        status, reasons = eval_python(evidence, "2.8", CANDIDATE, TARGET, bad_sbom)
        assert status == "unknown"
        assert reasons


def test_candidate_must_be_explicitly_requested_and_report_must_match_target():
    payload = _resolved()
    for profile in [
        {**TARGET, "pythonVersion": "3.12.0"},
        {**TARGET, "pythonSysPlatform": "darwin"},
        {**TARGET, "architecture": "aarch64"},
        {**TARGET, "pythonEnvironment": {"platform_release": "6.8"}},
        {**TARGET, "pythonImplementation": ""},
    ]:
        status, reasons = eval_python(PythonEvidence.model_validate(payload), "2.8", CANDIDATE, profile, OBSERVED)
        assert status == "unknown"
        assert reasons
    assert eval_python(PythonEvidence.model_validate(payload), "2.8", CANDIDATE,
                       {**TARGET, "pythonEnvironment": PYTHON_ENVIRONMENT}, OBSERVED)[0] == "conditions_met"
    payload["packages"][0]["requested"] = False
    assert eval_python(PythonEvidence.model_validate(payload), "2.8", CANDIDATE, TARGET, OBSERVED)[0] == "unknown"
    payload["packages"].append(payload["packages"][1])
    assert eval_python(PythonEvidence.model_validate(payload), "2.8", CANDIDATE, TARGET, OBSERVED)[0] == "unknown"


@pytest.mark.parametrize(("outcome", "reason", "status"), [
    ("conflict", "app-core requires transitive-lib>=2.0, while gateway requires transitive-lib<2.0", "conflict"),
    ("incomplete", "wheelhouse lacks transitive-lib", "unknown"),
])
def test_only_reported_conflicts_are_classified_as_conflicts(outcome, reason, status):
    evidence = PythonEvidence.model_validate({
        "kind": "python",
        "outcome": outcome,
        "source": "isolated-ci/123/pip",
        "environment": PYTHON_ENVIRONMENT,
        "reasons": [reason],
    })
    assert eval_python(evidence, "2.8", CANDIDATE, TARGET, OBSERVED) == (status, [reason])


def test_report_fields_and_artifact_provenance_are_required():
    evidence = _resolved()
    with pytest.raises(ValidationError):
        PythonEvidence.model_validate({**evidence, "reportSha256": None})
    with pytest.raises(ValidationError):
        PythonEvidence.model_validate({**evidence, "unknownField": "unexpected"})
    with pytest.raises(ValidationError):
        PythonEvidence.model_validate({**evidence, "outcome": "conflict", "packages": []})


def test_project_native_pip_report_keeps_only_local_wheel_evidence():
    project_report = runpy.run_path(str(ROOT / "scripts/project-python-upgrade-report.py"))["project_report"]
    download = {
        "url": "file:///sealed/wheels/app_core-2.8.0-py3-none-any.whl",
        "archive_info": {"hashes": {"sha256": "d" * 64}},
    }
    report = {
        "version": "1", "pip_version": "26.1.2", "environment": PYTHON_ENVIRONMENT,
        "install": [{
            "metadata": {"name": "app-core", "version": "2.8.0", "summary": "private description"},
            "requested": True,
            "download_info": download,
        }],
    }
    projection = project_report(json.dumps(report).encode(), "isolated-ci/123/pip")
    assert "/sealed" not in json.dumps(projection)
    assert "private description" not in json.dumps(projection)
    evidence = PythonEvidence.model_validate(projection)
    assert eval_python(evidence, "2.8", CANDIDATE, TARGET, {CANDIDATE: {"2.8.0"}})[0] == "conditions_met"
    download["url"] = "https://example.invalid/pkg.whl"
    with pytest.raises(ValueError, match="local wheel"):
        project_report(json.dumps(report).encode(), "isolated-ci/123/pip")
    download["url"] = "file:///sealed/app-core.tar.gz"
    with pytest.raises(ValueError, match="local wheel"):
        project_report(json.dumps(report).encode(), "isolated-ci/123/pip")
