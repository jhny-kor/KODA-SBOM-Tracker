"""Compare imported ELF facts for a scoped set of existing Linux consumers."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

_Name = Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[^/\\\x00-\x20\x7f]+$")]
_ARCHITECTURE = {"amd64": "x86_64", "arm64": "aarch64"}
_PLATFORM = {"x86_64": (64, "little"), "aarch64": (64, "little")}
_MAX_REASONS = 8


class _EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Symbol(_EvidenceModel):
    name: _Name
    version: _Name | None = None


class _Import(_Symbol):
    definite: bool = True


class _Export(_Symbol):
    defaultVersion: bool = False


class _Needed(_EvidenceModel):
    soname: _Name
    symbols: list[_Import] = Field(max_length=4096)
    versions: list[_Name] = Field(default_factory=list, max_length=256)


class _ElfObject(_EvidenceModel):
    architecture: _Name
    elfClass: Literal[32, 64]
    byteOrder: Literal["little", "big"]


class _Consumer(_ElfObject):
    name: _Name
    needed: list[_Needed] = Field(max_length=64)


class _Provider(_ElfObject):
    soname: _Name
    symbols: list[_Export] = Field(max_length=4096)
    versions: list[_Name] = Field(default_factory=list, max_length=256)


class ElfEvidence(_EvidenceModel):
    kind: Literal["elf"]
    source: Literal["readelf"]
    complete: bool
    consumers: list[_Consumer] = Field(max_length=32)
    providers: list[_Provider] = Field(max_length=32)


def _architecture(value: str) -> str:
    value = value.strip().lower()
    return _ARCHITECTURE.get(value, value)


def _matches_platform(item: _ElfObject, architecture: str) -> bool:
    return _architecture(item.architecture) == architecture and (item.elfClass, item.byteOrder) == _PLATFORM[architecture]


def eval_elf(evidence: ElfEvidence, architecture: str) -> tuple[str, list[str]]:
    """Evaluate SONAME and dynamic symbols. Build and runtime results are separate."""
    architecture = _architecture(architecture)
    if architecture not in _PLATFORM:
        return "unknown", ["이 배포 아키텍처의 ELF 조건은 아직 판정할 수 없습니다."]
    if not any(consumer.needed for consumer in evidence.consumers):
        return "unknown", ["검토할 실행 파일의 대상 SONAME 요구 근거가 없습니다."]

    conflicts: list[str] = []
    uncertain: list[str] = []
    providers: dict[str, list[_Provider]] = {}
    for provider in evidence.providers:
        providers.setdefault(provider.soname, []).append(provider)

    def record(messages: list[str], reason: str) -> None:
        if len(messages) < _MAX_REASONS and reason not in messages:
            messages.append(reason)

    if not evidence.complete:
        record(uncertain, "선택한 실행 파일·공유 라이브러리의 근거가 일부만 반입되었습니다.")

    for consumer in evidence.consumers:
        if not consumer.needed:
            continue
        if not _matches_platform(consumer, architecture):
            record(uncertain, f"{consumer.name}의 ELF 아키텍처·비트 수·바이트 순서가 배포 기준과 다릅니다.")
            continue
        for requirement in consumer.needed:
            selected = providers.get(requirement.soname, [])
            target = f"{consumer.name} → {requirement.soname}"
            definite = conflicts if evidence.complete else uncertain
            if not selected:
                record(definite, f"{target}에 필요한 SONAME을 후보가 제공하지 않습니다.")
                continue
            if len(selected) != 1:
                record(uncertain, f"{target}에 후보 라이브러리가 여러 개여서 실제 로딩 대상을 확인해야 합니다.")
                continue
            provider = selected[0]
            if not _matches_platform(provider, architecture):
                record(definite, f"{target} 후보의 ELF 아키텍처·비트 수·바이트 순서가 배포 기준과 다릅니다.")
                continue

            provided_versions = set(provider.versions)
            provided_versions.update(item.version for item in provider.symbols if item.version is not None)
            for version in requirement.versions:
                if version not in provided_versions:
                    record(definite, f"{target}에 필요한 ELF 심볼 버전 {version}을 후보가 제공하지 않습니다.")
            exported = {(item.name, item.version) for item in provider.symbols}
            unversioned = {item.name for item in provider.symbols if item.version is None or item.defaultVersion}
            names = {item.name for item in provider.symbols}
            for symbol in requirement.symbols:
                if symbol.version is not None:
                    if (symbol.name, symbol.version) not in exported:
                        record(definite if symbol.definite else uncertain,
                               f"{target}에 필요한 심볼 {symbol.name}@{symbol.version}이 후보에 없습니다.")
                elif symbol.name not in unversioned:
                    if symbol.name in names:
                        record(uncertain, f"{target}의 {symbol.name}은 기본 버전 심볼 연결을 확인해야 합니다.")
                    else:
                        record(definite if symbol.definite else uncertain,
                               f"{target}에 필요한 심볼 {symbol.name}이 후보에 없습니다.")

    if conflicts:
        return "conflict", conflicts
    if uncertain:
        return "unknown", uncertain
    return "conditions_met", ["반입 근거에서 SONAME·ELF 플랫폼·요구 심볼 조건을 충족합니다."]
