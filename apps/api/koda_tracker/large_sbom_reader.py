"""Read large CycloneDX JSON without decoding a whole inventory at once."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import TextIO

from .sbom import MAX_UPLOAD_DOCUMENT_DEPTH, SbomValidationError, iter_components

MAX_LARGE_SBOM_RECORD_BYTES = 8 * 1024**2
MAX_LARGE_SBOM_METADATA_BYTES = 32 * 1024**2
_CHUNK_SIZE = 256 * 1024
_MAX_FIELD_NAME_BYTES = 1024
_WHITESPACE = re.compile(r"[ \t\r\n]*")
_SCALAR = re.compile(r"[^ \t\r\n,}\]]+")
_ARRAY_FIELDS = frozenset({
    "services", "externalReferences", "compositions", "vulnerabilities", "annotations", "formulation", "citations",
    "properties",
})
_OBJECT_FIELDS = frozenset({"metadata", "declarations", "definitions", "signature"})
_STRING_FIELDS = frozenset({"$schema", "bomFormat", "specVersion", "serialNumber"})


def _unique_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise SbomValidationError("SBOM JSON 객체에 중복 필드가 있습니다")
        result[key] = value
    return result


def _finite_float(token: str) -> float:
    number = float(token)
    if not math.isfinite(number):
        raise SbomValidationError("SBOM JSON에서 범위를 벗어난 숫자를 지원하지 않습니다")
    return number


_DECODER = json.JSONDecoder(object_pairs_hook=_unique_keys, parse_float=_finite_float, parse_constant=_finite_float)


def _check_depth(value: object, depth: int = 1) -> None:
    if not isinstance(value, (dict, list)):
        return
    if depth > MAX_UPLOAD_DOCUMENT_DEPTH:
        raise SbomValidationError("SBOM JSON 문서의 중첩 깊이 제한을 초과했습니다")
    for child in value.values() if isinstance(value, dict) else value:
        if isinstance(child, (dict, list)):
            _check_depth(child, depth + 1)


class _Reader:
    def __init__(self, source: TextIO):
        self.source = source
        self.buffer = ""
        self.position = 0
        self.eof = False

    def _read_more(self, size: int) -> None:
        chunk = self.source.read(size)
        self.eof = not chunk
        self.buffer = self.buffer[self.position:] + chunk
        self.position = 0

    def peek(self) -> str:
        while True:
            self.position = _WHITESPACE.match(self.buffer, self.position).end()
            if self.position < len(self.buffer) or self.eof:
                return self.buffer[self.position:self.position + 1]
            self._read_more(_CHUNK_SIZE)

    def take(self, token: str) -> bool:
        if self.peek() != token:
            return False
        self.position += 1
        return True

    def expect(self, token: str) -> None:
        if not self.take(token):
            raise SbomValidationError(f"유효한 SBOM JSON 문서가 아닙니다 ({token} 필요)")

    def _extend_value(self, limit: int) -> None:
        buffered = len(self.buffer) - self.position
        if buffered > limit:
            raise SbomValidationError(f"SBOM JSON 항목 크기가 제한({limit:,}바이트)을 초과했습니다")
        self._read_more(min(limit + 1 - buffered, max(_CHUNK_SIZE, buffered)))

    def value(self, limit: int) -> tuple[object, int]:
        first = self.peek()
        if not first:
            raise SbomValidationError("SBOM JSON 값이 없습니다")
        if first not in '{["':
            # A scalar may continue in the next chunk, even if the visible
            # prefix already decodes as a number.
            scalar = _SCALAR.match(self.buffer, self.position)
            while scalar is not None and scalar.end() == len(self.buffer) and not self.eof:
                self._extend_value(limit)
                scalar = _SCALAR.match(self.buffer, self.position)
        while True:
            try:
                value, end = _DECODER.raw_decode(self.buffer, self.position)
            except json.JSONDecodeError:
                if self.eof:
                    raise
                self._extend_value(limit)
            except (RecursionError, ValueError) as exc:
                if isinstance(exc, SbomValidationError):
                    raise
                raise SbomValidationError("SBOM JSON 값이 숫자 또는 중첩 깊이 제한을 초과했습니다") from exc
            else:
                break
        raw = self.buffer[self.position:end]
        length = len(raw) if raw.isascii() else len(raw.encode("utf-8"))
        if length > limit:
            raise SbomValidationError(f"SBOM JSON 항목 크기가 제한({limit:,}바이트)을 초과했습니다")
        _check_depth(value)
        self.position = end
        return value, length

    def records(self) -> Iterator[dict]:
        self.expect("[")
        if self.take("]"):
            return
        while True:
            if self.peek() != "{":
                raise SbomValidationError("SBOM 구성요소와 의존 관계 항목은 객체여야 합니다")
            record, _ = self.value(MAX_LARGE_SBOM_RECORD_BYTES)
            yield record
            if self.take("]"):
                return
            self.expect(",")


def _validate_properties(properties: object) -> None:
    if not isinstance(properties, list) or any(
        not isinstance(prop, dict) or not isinstance(prop.get("name"), str)
        or ("value" in prop and not isinstance(prop["value"], str)) for prop in properties
    ):
        raise SbomValidationError("SBOM 속성은 문자열 이름을 가진 객체의 배열이어야 하며, 입력한 값은 문자열이어야 합니다")


def _validate_component(record: dict) -> None:
    for component in iter_components([record]):
        if not isinstance(component.get("type"), str) or not isinstance(component.get("name"), str):
            raise SbomValidationError("SBOM 구성요소에는 유형과 이름이 필요합니다")
        for key in ("bom-ref", "purl", "cpe", "group", "version"):
            if key in component and not isinstance(component[key], str):
                raise SbomValidationError(f"SBOM 구성요소의 {key} 값은 문자열이어야 합니다")
        if "properties" in component:
            _validate_properties(component["properties"])


def _validate_dependency(record: dict) -> None:
    if not isinstance(record.get("ref"), str) or not record["ref"]:
        raise SbomValidationError("SBOM 의존 관계에 ref 식별자가 필요합니다")
    for key in ("dependsOn", "provides"):
        references = record.get(key, [])
        if not isinstance(references, list) or any(not isinstance(ref, str) or not ref for ref in references):
            raise SbomValidationError(f"SBOM 의존 관계의 {key} 값은 식별자 배열이어야 합니다")


def _validate_metadata(metadata: dict) -> None:
    if metadata.get("bomFormat") != "CycloneDX" or metadata.get("specVersion") not in ("1.6", "1.7"):
        raise SbomValidationError("대용량 SBOM은 CycloneDX 1.6 또는 1.7 UTF-8 JSON이어야 합니다")
    for key, value in metadata.items():
        if key in _ARRAY_FIELDS and not isinstance(value, list):
            raise SbomValidationError(f"SBOM {key} 값은 배열이어야 합니다")
        if key in _OBJECT_FIELDS and not isinstance(value, dict):
            raise SbomValidationError(f"SBOM {key} 값은 객체여야 합니다")
        if key in _STRING_FIELDS and not isinstance(value, str):
            raise SbomValidationError(f"SBOM {key} 값은 문자열이어야 합니다")
        if key == "version" and (type(value) is not int or value < 1):
            raise SbomValidationError("SBOM 문서 버전은 양의 정수여야 합니다")
    if "properties" in metadata:
        _validate_properties(metadata["properties"])
    if "properties" in metadata.get("metadata", {}):
        _validate_properties(metadata["metadata"]["properties"])
    if "component" in metadata.get("metadata", {}):
        _validate_component(metadata["metadata"]["component"])


def read_large_cyclonedx(
    path: Path, on_component: Callable[[dict], None], on_dependency: Callable[[dict], None],
) -> dict:
    """Stream the two inventory arrays and return all remaining root fields.

    Callback effects are provisional until the complete document succeeds.
    Callers must stage the rows or use a transaction they can roll back.
    """
    metadata: dict = {}
    seen: set[str] = set()
    remaining = MAX_LARGE_SBOM_METADATA_BYTES
    handlers = {"components": (_validate_component, on_component), "dependencies": (_validate_dependency, on_dependency)}
    try:
        with path.open(encoding="utf-8-sig", newline="") as source:
            reader = _Reader(source)
            reader.expect("{")
            if not reader.take("}"):
                while True:
                    if reader.peek() != '"':
                        raise SbomValidationError("SBOM JSON 필드 이름은 문자열이어야 합니다")
                    key, size = reader.value(_MAX_FIELD_NAME_BYTES)
                    if key in seen:
                        raise SbomValidationError("SBOM JSON 루트에 중복 필드가 있습니다")
                    seen.add(key)
                    remaining -= size + 2
                    if remaining < 0:
                        raise SbomValidationError("SBOM JSON 메타데이터 크기 제한을 초과했습니다")
                    reader.expect(":")
                    if key in handlers:
                        validate, consume = handlers[key]
                        for record in reader.records():
                            validate(record)
                            consume(record)
                    else:
                        metadata[key], size = reader.value(remaining)
                        remaining -= size
                    if reader.take("}"):
                        break
                    reader.expect(",")
            if reader.peek():
                raise SbomValidationError("SBOM JSON 문서 뒤에 추가 데이터가 있습니다")
    except SbomValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SbomValidationError("유효한 CycloneDX UTF-8 JSON 문서가 아닙니다") from exc
    _validate_metadata(metadata)
    return metadata
