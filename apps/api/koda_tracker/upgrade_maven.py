"""Compare an imported Maven resolution with the candidate SBOM and target JDK."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .version_ordering import MavenVersion

MavenCoordinate = Annotated[str, Field(pattern=r"^pkg:maven/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", max_length=512)]
VersionText = Annotated[str, Field(min_length=1, max_length=255)]
Reason = Annotated[str, Field(min_length=1, max_length=400)]


class MavenSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    coordinate: MavenCoordinate
    version: VersionText


class MavenEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["maven"]
    source: Annotated[str, Field(min_length=1, max_length=256)]
    outcome: Literal["resolved", "conflict", "incomplete"]
    javaMajor: int = Field(ge=6, le=99)
    mavenVersion: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    reportSha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    minimumJavaMajor: int | None = Field(default=None, ge=6, le=99)
    javaRequirementEvidence: Reason | None = None
    selected: list[MavenSelection] = Field(default_factory=list, max_length=1500)
    reasons: list[Reason] = Field(default_factory=list, max_length=12)

    @model_validator(mode="after")
    def validate_outcome(self):
        if bool(self.minimumJavaMajor) != bool(self.javaRequirementEvidence and self.javaRequirementEvidence.strip()):
            raise ValueError("최소 Java 버전과 그 근거를 함께 지정하세요")
        if self.outcome == "resolved":
            if not self.selected or not self.mavenVersion or not self.reportSha256 or self.reasons:
                raise ValueError("Maven 해석 성공에는 Maven 버전, 보고서 해시와 선택된 의존성 목록이 필요합니다")
        elif not self.reasons or self.selected or any(not reason.strip() for reason in self.reasons):
            raise ValueError("실패하거나 불완전한 Maven 결과에는 이유가 필요합니다")
        return self


def eval_maven(evidence: MavenEvidence, version: str, coordinate: str, platform: dict,
               observed: dict[str, set[str]]) -> tuple[str, list[str]]:
    target_java = platform.get("javaMajor")
    if evidence.minimumJavaMajor and target_java and target_java < evidence.minimumJavaMajor:
        return "conflict", [
            f"대상 Java {target_java}, 후보 요구 Java {evidence.minimumJavaMajor} 이상",
            f"최소 Java 버전 근거 · {evidence.javaRequirementEvidence}",
        ]
    if evidence.javaMajor != target_java:
        return "unknown", [f"Maven 해석 환경 Java {evidence.javaMajor}과 배포 기준 Java {target_java}가 다릅니다"]
    if evidence.outcome == "conflict":
        return "conflict", evidence.reasons
    if evidence.outcome == "incomplete":
        return "unknown", evidence.reasons

    selected: dict[str, set[str]] = {}
    for part in evidence.selected:
        selected.setdefault(part.coordinate, set()).add(part.version)
    actual = selected.get(coordinate, set())
    if actual != {version}:
        if actual:
            return "conflict", [f"Maven이 요청한 {version} 대신 {', '.join(sorted(actual))}을 선택했습니다"]
        return "unknown", ["Maven 의존성 해석 결과에서 검토 대상 구성요소를 확인하지 못했습니다"]
    if not evidence.minimumJavaMajor:
        return "unknown", ["후보 의존성 조합의 최소 Java 버전 근거가 없습니다"]
    if not observed:
        return "unknown", ["해석 결과와 대조할 후보 SBOM이 없습니다"]
    different = sorted(key for key in selected.keys() | observed.keys() if selected.get(key) != observed.get(key))
    if different:
        return "unknown", [f"후보 SBOM과 Maven 해석 결과의 버전 집합이 다릅니다 · {', '.join(different[:5])} ({len(different)}개)"]
    return "conditions_met", [f"Maven 해석 결과가 후보 SBOM과 일치하고 Java {target_java}가 최소 요구 버전을 충족합니다"]


def maven_version_key(version: str) -> MavenVersion | None:
    try:
        return MavenVersion(version)
    except ValueError:
        return None
