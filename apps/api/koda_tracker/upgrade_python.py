"""Evaluate imported pip wheel-resolution evidence against a deployment SBOM."""
from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_Text = Annotated[str, Field(min_length=1, max_length=255)]
_Marker = Annotated[str, Field(max_length=255)]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PackageName = Annotated[str, Field(max_length=255, pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")]
_Reason = Annotated[str, Field(min_length=1, max_length=500)]
_PRECEDENCE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
_VERSION = re.compile(
    r"v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre>a|alpha|b|beta|c|rc|pre|preview)[-_.]?(?P<pre_num>[0-9]+)?)?"
    r"(?:-(?P<implicit_post>[0-9]+)|[-_.]?(?P<post>post|rev|r)[-_.]?(?P<post_num>[0-9]+)?)?"
    r"(?:[-_.]?(?P<dev>dev)[-_.]?(?P<dev_num>[0-9]+)?)?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?",
    re.ASCII | re.IGNORECASE,
)
_ARCHITECTURES = {"amd64": "x86_64", "x64": "x86_64", "x86-64": "x86_64", "arm64": "aarch64"}


def python_version_key(version: str) -> tuple | None:
    """Sort and compare Python distributions using PEP 440 version ordering."""
    if len(version) > 255 or (match := _VERSION.fullmatch(version.strip())) is None:
        return None
    parts = {key: part.lower() if part else part for key, part in match.groupdict().items()}
    release = [int(number) for number in parts["release"].split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    post = parts["implicit_post"] or parts["post_num"]
    post_number = int(post or 0) if post is not None or parts["post"] else -1
    if parts["pre"]:
        pre = (_PRECEDENCE[parts["pre"]], int(parts["pre_num"] or 0))
    else:
        pre = (-1 if parts["dev"] and post_number == -1 else 3, 0)
    dev = (0, int(parts["dev_num"] or 0)) if parts["dev"] else (1, 0)
    local = tuple((1, int(part)) if part.isdigit() else (0, part)
                  for part in re.split(r"[-_.]", parts["local"])) if parts["local"] else ()
    return int(parts["epoch"] or 0), tuple(release), pre, post_number, dev, local


class _ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=False)


class PipEnvironment(_ReportModel):
    python_full_version: _Text
    implementation_name: _Text
    sys_platform: _Text
    platform_machine: _Text
    implementation_version: _Marker | None = None
    os_name: _Marker | None = None
    platform_release: _Marker | None = None
    platform_system: _Marker | None = None
    platform_version: _Marker | None = None
    python_version: _Marker | None = None
    platform_python_implementation: _Marker | None = None


class PipPackage(_ReportModel):
    name: _PackageName
    version: _Text
    requested: bool
    wheelSha256: _Sha256


class PythonEvidence(_ReportModel):
    kind: Literal["python"]
    source: _Text
    outcome: Literal["resolved", "conflict", "incomplete"]
    environment: PipEnvironment
    pipVersion: _Text | None = None
    reportSha256: _Sha256 | None = None
    packages: list[PipPackage] = Field(default_factory=list, max_length=2_000)
    reasons: list[_Reason] = Field(default_factory=list, max_length=20)

    @model_validator(mode="after")
    def check_outcome(self):
        if self.outcome == "resolved":
            if not self.packages or not self.pipVersion or not self.reportSha256:
                raise ValueError("pip 해석 성공에는 도구 버전, 보고서 해시와 wheel 목록이 필요합니다")
        elif self.packages or not self.reasons:
            raise ValueError("pip 미해결 결과에는 사유가 필요하며 wheel 선택 결과를 함께 제출할 수 없습니다")
        return self


def _pypi_coordinate(name: str) -> str:
    return "pkg:pypi/" + re.sub(r"[-_.]+", "-", name).lower()


def _arch(value: str) -> str:
    name = value.strip().lower()
    return _ARCHITECTURES.get(name, name)


def eval_python(evidence: PythonEvidence, version: str, coordinate: str, platform: dict,
                observed: dict[str, set[str]]) -> tuple[str, list[str]]:
    """Check a pip plan from the target environment without invoking pip."""
    runtime = {
        "pythonVersion": evidence.environment.python_full_version,
        "pythonImplementation": evidence.environment.implementation_name,
        "pythonSysPlatform": evidence.environment.sys_platform,
        "architecture": evidence.environment.platform_machine,
    }
    if any(not platform.get(field) for field in runtime):
        return "unknown", ["배포 기준의 Python 전체 버전·구현·운영체제·아키텍처 정보가 필요합니다"]
    mismatches = []
    for field, value in runtime.items():
        normalize = _arch if field == "architecture" else str.casefold
        if normalize(platform[field]) != normalize(value):
            mismatches.append(field)
    marker_values = evidence.environment.model_dump(exclude_none=True)
    for field, value in (platform.get("pythonEnvironment") or {}).items():
        if marker_values.get(field) != value:
            mismatches.append(field)
    if mismatches:
        return "unknown", ["대상 배포와 pip 해석 환경이 다릅니다: " + ", ".join(mismatches)]
    if evidence.outcome != "resolved":
        status = "conflict" if evidence.outcome == "conflict" else "unknown"
        return status, list(evidence.reasons)

    planned = {}
    for package in evidence.packages:
        key = _pypi_coordinate(package.name)
        parsed = python_version_key(package.version)
        if parsed is None or key in planned:
            return "unknown", [f"pip 계획에 중복 또는 해석할 수 없는 패키지 버전이 있습니다: {key}"]
        planned[key] = package, parsed
    selected = planned.get(coordinate)
    if selected is None or not selected[0].requested or selected[1] != python_version_key(version):
        return "unknown", ["pip 계획에 요청한 후보 패키지와 버전이 확인되지 않습니다"]

    python_packages = {key: values for key, values in observed.items() if key.startswith("pkg:pypi/")}
    errors = []
    for key, (_, expected) in planned.items():
        found = {python_version_key(value) for value in python_packages.get(key, ())}
        if found != {expected}:
            errors.append(f"pip 계획과 후보 SBOM의 패키지 버전이 일치하지 않습니다: {key}")
    for key in sorted(python_packages.keys() - planned.keys()):
        errors.append(f"후보 SBOM의 Python 패키지가 pip 계획에 없습니다: {key}")
    if errors:
        return "unknown", errors[:20]
    return "conditions_met", [f"pip {evidence.pipVersion} 오프라인 wheel 해석과 후보 SBOM의 Python 패키지 {len(planned)}개가 일치합니다"]
