from __future__ import annotations

import hashlib
import io
import json
import os
import re
import selectors
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote
from xml.etree.ElementTree import TreeBuilder

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from .archive_formats import MEDIA_TYPES as SBOM_ARCHIVE_MEDIA_TYPES
from .oracle_evidence import oracle_listener_identity


# Large host inventories can exceed 30 seconds on offline server hardware.
# Keep validation bounded and within the upload gateway's 600-second window.
CYCLONEDX_VALIDATION_TIMEOUT_SECONDS = 300
_CYCLONEDX_DIAGNOSTIC_BYTES = 4096
_CYCLONEDX_OUT_OF_MEMORY = b"System.OutOfMemoryException"
MAX_UPLOAD_DOCUMENT_BYTES = 128 * 1024**2
MAX_UPLOAD_DOCUMENT_DEPTH = 128
MAX_UPLOAD_JSON_MARKS = 4_000_000
MAX_UPLOAD_JSON_DECODED_BYTES = 192 * 1024**2
MAX_UPLOAD_XML_NODES = 1_000_000
MAX_UPLOAD_XML_CHARS = 64 * 1024**2
_JSON_STRUCTURE = re.compile(r'["{}\[\],:]')
_JSON_STRING = re.compile(r'["\\]')
_JSON_WIDE = re.compile(r'[\u0100-\uffff]')
_JSON_ASTRAL = re.compile(r'[\U00010000-\U0010ffff]')


class SbomValidationError(ValueError):
    pass


def _check_upload_document_size(size: int) -> None:
    if size > MAX_UPLOAD_DOCUMENT_BYTES:
        raise SbomValidationError(f"SBOM 문서가 파싱 크기 제한({MAX_UPLOAD_DOCUMENT_BYTES:,}바이트)을 초과했습니다")


def _check_upload_json_structure(source, prefix: bytes) -> None:
    # Match json.loads(bytes), including the UTF-16/32 variants it already accepts.
    # The real decoder still validates JSON syntax and decodes all field values.
    reader = io.TextIOWrapper(source, encoding=json.detect_encoding(prefix), errors="surrogatepass", newline="")
    try:
        depth = marks = characters = 0
        character_width = 1
        in_string = escaped = False
        while chunk := reader.read(64 * 1024):
            # Python can widen the entire decoded source when one character
            # requires more than one byte in its internal representation.
            characters += len(chunk)
            if character_width < 4 and not chunk.isascii():
                if _JSON_ASTRAL.search(chunk):
                    character_width = 4
                elif character_width == 1 and _JSON_WIDE.search(chunk):
                    character_width = 2
            if characters * character_width > MAX_UPLOAD_JSON_DECODED_BYTES:
                raise SbomValidationError("SBOM JSON 문서의 디코딩 크기 제한을 초과했습니다")
            position = int(escaped)
            escaped = False
            while position < len(chunk):
                pattern = _JSON_STRING if in_string else _JSON_STRUCTURE
                match = pattern.search(chunk, position)
                if match is None:
                    break
                position = match.end()
                token = match[0]
                if token == '"':
                    in_string = not in_string
                elif in_string:
                    escaped = position == len(chunk)
                    position += 1
                else:
                    marks += 1
                    if token in "{[":
                        depth += 1
                    elif token in "}]":
                        depth -= 1
                        if depth < 0:
                            raise SbomValidationError("유효한 JSON 문서가 아닙니다")
                    if depth > MAX_UPLOAD_DOCUMENT_DEPTH:
                        raise SbomValidationError("SBOM JSON 문서의 중첩 깊이 제한을 초과했습니다")
                    if marks > MAX_UPLOAD_JSON_MARKS:
                        raise SbomValidationError("SBOM JSON 문서의 구조 복잡도 제한을 초과했습니다")
    finally:
        reader.detach()
    source.seek(0)


class _BudgetedXmlTreeBuilder(TreeBuilder):
    def __init__(self, max_nodes: int):
        super().__init__()
        self.depth = 0
        self.remaining_nodes = max_nodes
        self.remaining_chars = MAX_UPLOAD_XML_CHARS

    def _consume(self, nodes: int, characters: int) -> None:
        self.remaining_nodes -= nodes
        self.remaining_chars -= characters
        if self.remaining_nodes < 0 or self.remaining_chars < 0:
            raise SbomValidationError("SBOM XML 문서의 구조 복잡도 제한을 초과했습니다")

    def start_ns(self, prefix, uri) -> None:
        if len(uri) > 1024:
            raise SbomValidationError("SBOM XML 네임스페이스 길이 제한을 초과했습니다")
        self._consume(1, len(prefix) + len(uri))

    def start(self, tag, attributes):
        self.depth += 1
        if self.depth > MAX_UPLOAD_DOCUMENT_DEPTH:
            raise SbomValidationError("SBOM XML 문서의 중첩 깊이 제한을 초과했습니다")
        self._consume(1 + len(attributes), len(tag) + sum(len(key) + len(value) for key, value in attributes.items()))
        return super().start(tag, attributes)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def data(self, data):
        self._consume(0, len(data))
        return super().data(data)


def parse_bounded_xml(source, *, max_nodes: int | None = None):
    parser = SafeET.DefusedXMLParser(
        target=_BudgetedXmlTreeBuilder(MAX_UPLOAD_XML_NODES if max_nodes is None else max_nodes),
        forbid_dtd=True,
    )
    return SafeET.parse(source, parser=parser).getroot()


def sbom_upload_media_type(path: Path, document_media_type: str) -> str:
    """Describe the immutable uploaded bytes, rather than the extracted view."""
    from .archive_formats import archive_kind, archive_media_type

    kind = archive_kind(path)
    return archive_media_type(kind) if kind is not None else document_media_type


_JSON_BYTES_STRING = re.compile(rb'["\\]')
_JSON_WHITESPACE_RUN = re.compile(rb"[ \t\r\n]+")


def _compact_large_json(source, destination) -> None:
    """Collapse insignificant JSON whitespace without changing strings or syntax."""
    written = 0
    in_string = escaped = previous_space = False
    while chunk := source.read(1024 * 1024):
        output = bytearray()
        start = int(escaped)
        position = start
        escaped = False
        if start:
            output.extend(chunk[:start])
        while position < len(chunk):
            if in_string:
                match = _JSON_BYTES_STRING.search(chunk, position)
                if match is None:
                    output.extend(chunk[position:])
                    break
                end = match.end()
                position = end
                if match[0] == b"\\":
                    position += 1
                    escaped = end == len(chunk)
                else:
                    in_string = False
                output.extend(chunk[start:position])
                start = position
                continue
            quote = chunk.find(b'"', position)
            limit = len(chunk) if quote == -1 else quote
            plain = _JSON_WHITESPACE_RUN.sub(b" ", chunk[position:limit])
            output.extend(plain[1:] if previous_space and plain.startswith(b" ") else plain)
            if quote == -1:
                previous_space = (plain.endswith(b" ") if plain else previous_space)
                break
            output.append(34)
            in_string = True
            previous_space = False
            start = position = quote + 1
        written += len(output)
        _check_upload_document_size(written)
        destination.write(output)


@contextmanager
def _document_for_parsing(path: Path, spool: Path, *, keep_legacy: bool):
    if path.stat().st_size <= MAX_UPLOAD_DOCUMENT_BYTES:
        yield path
        return
    with path.open("rb") as source:
        prefix = source.read(4096)
        if not prefix.lstrip().startswith((b"{", b"[")):
            yield path
            return
        source.seek(0)
        spool.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".koda-sbom-json-", dir=spool) as temporary:
            compact = Path(temporary) / "sbom.json"
            try:
                with compact.open("wb") as destination:
                    _compact_large_json(source, destination)
            except SbomValidationError:
                if not keep_legacy:
                    raise
                yield path
            else:
                yield compact


@contextmanager
def sbom_document_path(
    path: Path, *, max_bytes: int | None = None, workbook: bool = False, keep_legacy: bool = False,
):
    """Yield one plain document; never persist or recursively unpack members."""
    from .archive_formats import ArchiveError, archive_kind, extract_archive
    from .config import get_settings

    try:
        kind = archive_kind(path)
        if workbook:
            from .sbom_workbook import MAX_WORKBOOK_BYTES
            if kind != "zip" or path.stat().st_size > MAX_WORKBOOK_BYTES:
                raise SbomValidationError("10 MiB 이하의 Excel .xlsx 파일을 선택하세요")
        settings = get_settings()
        if kind is None:
            with _document_for_parsing(path, settings.artifact_dir, keep_legacy=keep_legacy) as document:
                yield document
            return
        limit = settings.max_upload_bytes if max_bytes is None else max_bytes
        settings.artifact_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".koda-sbom-archive-", dir=settings.artifact_dir) as temporary:
            if workbook:
                from .sbom_workbook import read_workbook
                root = Path(temporary) / "workbook"
                root.mkdir(mode=0o700)
                workbook_limit = min(limit, 24 * 1024**2)
                extract_archive(path, root, max_members=256, max_unpacked_bytes=workbook_limit,
                                max_member_bytes=workbook_limit)
                document = Path(temporary) / "inventory.cdx.json"
                with document.open("w", encoding="utf-8") as output:
                    json.dump(read_workbook(root), output, ensure_ascii=False)
                if document.stat().st_size > limit:
                    raise SbomValidationError("변환된 Excel SBOM이 문서 크기 제한을 초과했습니다")
                yield document
                return
            files = extract_archive(path, Path(temporary), max_members=256,
                                    max_unpacked_bytes=limit, max_member_bytes=limit)
            if len(files) != 1:
                raise SbomValidationError("압축파일에는 디렉터리 외 SBOM 파일이 정확히 하나 있어야 합니다")
            if archive_kind(files[0]) is not None:
                raise SbomValidationError("중첩된 SBOM 압축파일은 허용되지 않습니다")
            with _document_for_parsing(files[0], settings.artifact_dir, keep_legacy=keep_legacy) as document:
                yield document
    except ArchiveError as exc:
        raise SbomValidationError(f"SBOM 압축파일이 올바르지 않습니다: {exc}") from exc


def _normalize_json(payload):
    if isinstance(payload, dict) and "spdxVersion" in payload:
        from .spdx import to_cyclonedx
        try:
            return to_cyclonedx(payload), "application/spdx+json"
        except (ValueError, TypeError, RecursionError) as exc:
            raise SbomValidationError(str(exc)) from exc
    return payload, "application/vnd.cyclonedx+json"


def iter_components(components):
    """Yield every component in stable preorder, without recursive Python calls.

    Keep the nested normalized document intact; consumers that materialize rows,
    calculate quotas or evaluate policies must share this same component scope.
    """
    if not isinstance(components, list):
        raise SbomValidationError("components는 배열이어야 합니다")
    stack = [iter(components)]
    exhausted = object()
    while stack:
        component = next(stack[-1], exhausted)
        if component is exhausted:
            stack.pop()
            continue
        if not isinstance(component, dict):
            raise SbomValidationError("구성요소는 객체여야 합니다")
        yield component
        nested = component.get("components", [])
        if not isinstance(nested, list):
            raise SbomValidationError("중첩 components는 배열이어야 합니다")
        if nested:
            stack.append(iter(nested))


def component_count(payload: dict) -> int:
    return sum(1 for _ in iter_components(payload.get("components", [])))


def validate_component_count(payload: dict, max_components: int) -> None:
    for count, _ in enumerate(iter_components(payload.get("components", [])), 1):
        if count > max_components:
            raise SbomValidationError(f"SBOM 구성요소 수가 제한({max_components})을 초과했습니다")


def _validated_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise SbomValidationError("CycloneDX SBOM이 아닙니다")
    version = str(payload.get("specVersion", ""))
    if version not in {"1.4", "1.5", "1.6", "1.7"}:
        raise SbomValidationError(f"지원하지 않는 CycloneDX 버전입니다: {version or 'unknown'}")
    # Validate nested containers as well when no external schema CLI is configured.
    for _ in iter_components(payload.get("components", [])):
        pass
    return payload


def parse_sbom(raw: bytes) -> tuple[dict, str]:
    stripped = raw.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SbomValidationError("유효한 JSON 문서가 아닙니다") from exc
        payload, media = _normalize_json(payload)
    elif stripped.startswith(b"<"):
        # Scan the complete bounded upload; a declaration after the XML prolog
        # must not bypass XXE/DTD rejection by sitting beyond a short prefix.
        upper = raw.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise SbomValidationError("DTD와 외부 엔티티는 허용되지 않습니다")
        try:
            root = SafeET.fromstring(raw)
        except Exception as exc:
            raise SbomValidationError("유효한 XML 문서가 아닙니다") from exc
        payload = _xml_payload(root)
        media = "application/vnd.cyclonedx+xml"
    else:
        raise SbomValidationError("CycloneDX JSON 또는 XML만 지원합니다")
    return _validated_payload(payload), media


def parse_sbom_file(path: Path, *, workbook: bool = False) -> tuple[dict, str]:
    with sbom_document_path(path, workbook=workbook) as document:
        return _parse_sbom_document_file(document)


def parse_sbom_upload_document(path: Path) -> tuple[dict, str]:
    """Parse the already selected document within the upload resource limits."""
    return _parse_sbom_document_file(path, bounded=True)


def _parse_sbom_document_file(path: Path, *, bounded: bool = False) -> tuple[dict, str]:
    with path.open("rb") as candidate:
        if bounded:
            _check_upload_document_size(os.fstat(candidate.fileno()).st_size)
        prefix = candidate.read(4096)
        candidate.seek(0)
        if prefix.lstrip().startswith((b"{", b"[")):
            try:
                if bounded:
                    _check_upload_json_structure(candidate, prefix)
                payload = json.load(candidate)
            except SbomValidationError:
                raise
            except (ValueError, RecursionError) as exc:
                raise SbomValidationError("유효한 JSON 문서가 아닙니다") from exc
            payload, media = _normalize_json(payload)
        elif prefix.lstrip().startswith(b"<"):
            carry = b""
            while chunk := candidate.read(1024 * 1024):
                upper = (carry + chunk).upper()
                if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
                    raise SbomValidationError("DTD와 외부 엔티티는 허용되지 않습니다")
                carry = upper[-16:]
            candidate.seek(0)
            try:
                root = parse_bounded_xml(candidate) if bounded else SafeET.parse(candidate).getroot()
            except SbomValidationError:
                raise
            except DefusedXmlException as exc:
                raise SbomValidationError("DTD와 외부 엔티티는 허용되지 않습니다") from exc
            except Exception as exc:
                raise SbomValidationError("유효한 XML 문서가 아닙니다") from exc
            payload = _xml_payload(root)
            media = "application/vnd.cyclonedx+xml"
        else:
            raise SbomValidationError("CycloneDX JSON 또는 XML만 지원합니다")
    return _validated_payload(payload), media


def validate_with_cyclonedx_cli(raw: bytes, binary: str) -> None:
    """Run the pinned CycloneDX CLI schema validator when it is configured."""
    if not binary:
        return
    is_json = raw.lstrip().startswith((b"{", b"["))
    suffix = ".json" if is_json else ".xml"
    input_format = "json" if is_json else "xml"
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix) as candidate:
            candidate.write(raw)
            candidate.flush()
            validate_file_with_cyclonedx_cli(Path(candidate.name), binary, input_format=input_format)
    except FileNotFoundError as exc:
        raise SbomValidationError("CycloneDX CLI 검증기를 찾을 수 없습니다. Tracker API 설치 상태를 확인하세요.") from exc


def validate_file_with_cyclonedx_cli(
    path: Path, binary: str, *, input_format: str | None = None,
    parsed_document: tuple[dict, str] | None = None,
) -> None:
    if not binary and parsed_document is None:
        return
    # SPDX's original file is retained as the uploaded artifact. Validate the
    # normalized CycloneDX view with this optional CycloneDX-only validator.
    normalized = None
    if parsed_document is not None:
        payload, media_type = parsed_document
        if media_type == "application/spdx+json":
            normalized = payload
    else:
        with path.open("rb") as source:
            prefix = source.read(4096).lstrip()
            if prefix.startswith((b"{", b"[")):
                source.seek(0)
                try:
                    candidate = json.load(source)
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise SbomValidationError("유효한 JSON 문서가 아닙니다") from exc
                if isinstance(candidate, dict) and "spdxVersion" in candidate:
                    normalized, _ = _normalize_json(candidate)
    if normalized is None:
        if binary:
            _validate_cyclonedx_file(path, binary, input_format)
        return

    if not binary:
        _write_bounded_spdx(normalized)
        return
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", dir=path.parent) as converted:
        if parsed_document is None:
            json.dump(normalized, converted, ensure_ascii=False)
        else:
            _write_bounded_spdx(normalized, converted)
        converted.flush()
        _validate_cyclonedx_file(Path(converted.name), binary, "json")


def _write_bounded_spdx(payload: dict, output=None) -> None:
    size = 0
    try:
        for chunk in json.JSONEncoder(ensure_ascii=False).iterencode(payload):
            size += len(chunk.encode("utf-8"))
            _check_upload_document_size(size)
            if output is not None:
                output.write(chunk)
    except UnicodeError as exc:
        raise SbomValidationError("변환된 SPDX 문서의 문자 인코딩이 올바르지 않습니다") from exc


def _run_cyclonedx(command: list[str], *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Drain both diagnostic streams within the deadline and keep only their tails."""
    tails = {"stdout": b"", "stderr": b""}
    out_of_memory = False
    with (
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process,
        selectors.DefaultSelector() as ready,
    ):
        deadline = time.monotonic() + timeout
        try:
            ready.register(process.stdout, selectors.EVENT_READ, "stdout")
            ready.register(process.stderr, selectors.EVENT_READ, "stderr")
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in ready.select(remaining):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        ready.unregister(key.fileobj)
                        continue
                    recent = tails[key.data] + chunk
                    out_of_memory = out_of_memory or _CYCLONEDX_OUT_OF_MEMORY in recent
                    tails[key.data] = recent[-_CYCLONEDX_DIAGNOSTIC_BYTES:]
            returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException:
            process.kill()
            raise
    stdout = tails["stdout"].decode("utf-8", errors="replace")
    stderr = tails["stderr"].decode("utf-8", errors="replace")
    if out_of_memory:
        stderr = _CYCLONEDX_OUT_OF_MEMORY.decode("ascii") + stderr
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def _validate_cyclonedx_file(path: Path, binary: str, input_format: str | None) -> None:
    command = [binary, "validate", "--input-file", str(path)]
    if input_format:
        command.extend(["--input-format", input_format])
    try:
        process = _run_cyclonedx(command, timeout=CYCLONEDX_VALIDATION_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise SbomValidationError(
            f"CycloneDX 스키마 검증 시간이 {CYCLONEDX_VALIDATION_TIMEOUT_SECONDS}초 제한을 초과했습니다. "
            "검증이 완료되지 않아 업로드를 저장하지 않았습니다. "
            "Tracker API 서버의 CPU·메모리와 SBOM 크기를 확인하세요."
        ) from exc
    except FileNotFoundError as exc:
        raise SbomValidationError("CycloneDX CLI 검증기를 찾을 수 없습니다. Tracker API 설치 상태를 확인하세요.") from exc
    if process.returncode != 0:
        if _CYCLONEDX_OUT_OF_MEMORY.decode("ascii") in (process.stderr or "") + (process.stdout or ""):
            raise SbomValidationError(
                "CycloneDX 검증기의 메모리가 부족해 검증을 완료하지 못했습니다. "
                "업로드를 저장하지 않았습니다. Tracker API 서버와 컨테이너의 메모리 한도를 확인하세요."
            )
        if process.returncode in {-9, 137}:
            raise SbomValidationError(
                "CycloneDX 검증기가 강제로 종료되어 검증을 완료하지 못했습니다. "
                "업로드를 저장하지 않았습니다. Tracker API 서버의 자원 상태와 종료 원인을 확인하세요."
            )
        message = (process.stderr or "").strip() or (process.stdout or "").strip() or "스키마 검증 실패"
        raise SbomValidationError(f"CycloneDX 스키마 검증에 실패했습니다: {message[-1000:]}")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_contact(node) -> dict:
    result = {"bom-ref": node.attrib["bom-ref"]} if "bom-ref" in node.attrib else {}
    for child in node:
        if _local(child.tag) in {"name", "email", "phone"}:
            result[_local(child.tag)] = child.text or ""
    return result


def _xml_entity(node) -> dict:
    result = {"bom-ref": node.attrib["bom-ref"]} if "bom-ref" in node.attrib else {}
    for child in node:
        kind = _local(child.tag)
        if kind == "name":
            result[kind] = child.text or ""
        elif kind == "url":
            result.setdefault("url", []).append(child.text or "")
        elif kind == "contact":
            result.setdefault("contact", []).append(_xml_contact(child))
    return result


def _xml_hashes(node) -> list[dict]:
    return [{"alg": value.attrib.get("alg", ""), "content": value.text or ""}
            for value in node if _local(value.tag) == "hash"]


def _xml_licenses(node) -> list[dict]:
    result = []
    for value in node:
        kind = _local(value.tag)
        if kind == "expression":
            expression = {"expression": (value.text or "").strip()}
            if "bom-ref" in value.attrib:
                expression["bom-ref"] = value.attrib["bom-ref"]
            result.append(expression)
        elif kind == "license":
            license_value = {"bom-ref": value.attrib["bom-ref"]} if "bom-ref" in value.attrib else {}
            for child in value:
                if _local(child.tag) in {"id", "name", "url"}:
                    license_value[_local(child.tag)] = child.text or ""
            # Retain an empty record as evidence rather than silently dropping it.
            result.append({"license": license_value})
    return result


def _xml_properties(node) -> list[dict]:
    return [{"name": value.attrib.get("name", ""), "value": value.text or ""}
            for value in node if _local(value.tag) == "property"]


def _xml_swid(node) -> dict:
    result = {key: value for key, value in node.attrib.items()
              if key in {"tagId", "name", "version", "tagVersion", "patch"}}
    # Match JSON field types for valid attributes, but retain invalid source
    # values for quality diagnostics when schema validation is not configured.
    if "tagVersion" in result and result["tagVersion"].isdigit():
        result["tagVersion"] = int(result["tagVersion"])
    if result.get("patch") in {"true", "false", "1", "0"}:
        result["patch"] = result["patch"] in {"true", "1"}
    for child in node:
        kind = _local(child.tag)
        if kind == "url":
            result[kind] = child.text or ""
        elif kind == "text":
            attachment = {"content": child.text or ""}
            for xml_key, json_key in (("content-type", "contentType"), ("encoding", "encoding")):
                if xml_key in child.attrib:
                    attachment[json_key] = child.attrib[xml_key]
            result[kind] = attachment
    return result


def _xml_component_fields(node) -> dict:
    result = {key: node.attrib[key] for key in ("type", "bom-ref", "mime-type") if key in node.attrib}
    for child in node:
        kind = _local(child.tag)
        if kind in {"group", "name", "version", "purl", "cpe", "description", "scope", "author", "publisher"}:
            result[kind] = child.text or ""
        elif kind in {"supplier", "manufacturer", "manufacture"}:
            result[kind] = _xml_entity(child)
        elif kind == "authors":
            result[kind] = [_xml_contact(value) for value in child if _local(value.tag) == "author"]
        elif kind == "hashes":
            result[kind] = _xml_hashes(child)
        elif kind == "licenses":
            result[kind] = _xml_licenses(child)
        elif kind == "properties":
            result[kind] = _xml_properties(child)
        elif kind == "swid":
            result[kind] = _xml_swid(child)
    return result


def _xml_components(nodes) -> list[dict]:
    result = []
    pending = [(node, result) for node in reversed(list(nodes)) if _local(node.tag) == "component"]
    while pending:
        node, destination = pending.pop()
        item = _xml_component_fields(node)
        destination.append(item)
        nested = next((child for child in node if _local(child.tag) == "components"), None)
        if nested is not None:
            item["components"] = []
            pending.extend((child, item["components"]) for child in reversed(list(nested)) if _local(child.tag) == "component")
    return result


def _xml_tools(node):
    legacy = [value for value in node if _local(value.tag) == "tool"]
    if legacy:
        result = []
        for value in legacy:
            tool = {}
            for child in value:
                kind = _local(child.tag)
                if kind in {"vendor", "name", "version"}:
                    tool[kind] = child.text or ""
                elif kind == "hashes":
                    tool[kind] = _xml_hashes(child)
            result.append(tool)
        return result
    result = {}
    for child in node:
        kind = _local(child.tag)
        if kind == "components":
            result[kind] = _xml_components(child)
        elif kind == "services":
            result[kind] = [_xml_component_fields(value) for value in child if _local(value.tag) == "service"]
    return result


def _xml_payload(root) -> dict:
    if _local(root.tag) != "bom":
        raise SbomValidationError("CycloneDX XML 루트는 bom이어야 합니다")
    namespace = root.tag.split("}", 1)[0].lstrip("{") if "}" in root.tag else ""
    version_match = re.search(r"bom/(\d+\.\d+)", namespace)
    payload: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": version_match.group(1) if version_match else root.attrib.get("version", ""),
        "components": [],
    }
    if "serialNumber" in root.attrib:
        payload["serialNumber"] = root.attrib["serialNumber"]
    if "version" in root.attrib:
        value = root.attrib["version"]
        payload["version"] = int(value) if value.isdigit() else value
    for node in root:
        kind = _local(node.tag)
        if kind == "metadata":
            metadata = {}
            for child in node:
                field = _local(child.tag)
                if field == "timestamp":
                    metadata[field] = child.text or ""
                elif field == "component":
                    metadata[field] = _xml_components([child])[0]
                elif field == "tools":
                    metadata[field] = _xml_tools(child)
                elif field == "authors":
                    metadata[field] = [_xml_contact(value) for value in child if _local(value.tag) == "author"]
                elif field in {"supplier", "manufacturer", "manufacture"}:
                    metadata[field] = _xml_entity(child)
                elif field == "licenses":
                    metadata[field] = _xml_licenses(child)
                elif field == "properties":
                    metadata[field] = _xml_properties(child)
            payload[kind] = metadata
        elif kind == "dependencies":
            payload[kind] = [{"ref": value.attrib.get("ref", ""), "dependsOn": [item.attrib.get("ref", "") for item in value if _local(item.tag) == "dependency"]}
                             for value in node if _local(value.tag) == "dependency"]
        elif kind == "components":
            payload[kind] = _xml_components(node)
    return payload


def artifact_path(base: Path, digest: str) -> Path:
    return base / "sha256" / digest[:2] / digest


def store_artifact(base: Path, raw: bytes, *, digest: str | None = None) -> tuple[str, Path]:
    digest = digest or hashlib.sha256(raw).hexdigest()
    target = artifact_path(base, digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{digest}.", delete=False) as candidate:
            candidate.write(raw)
            temp = Path(candidate.name)
        try:
            temp.replace(target)
        finally:
            temp.unlink(missing_ok=True)
    return digest, target


def store_artifact_file(base: Path, source: Path, *, digest: str) -> tuple[str, Path]:
    target = artifact_path(base, digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        with tempfile.NamedTemporaryFile(dir=target.parent, prefix=f".{digest}.", delete=False) as candidate:
            with source.open("rb") as staged:
                shutil.copyfileobj(staged, candidate, length=1024 * 1024)
            temp = Path(candidate.name)
        try:
            temp.replace(target)
        finally:
            temp.unlink(missing_ok=True)
    return digest, target


def normalized_identity(component: dict) -> tuple[str, str]:
    if oracle_listener := oracle_listener_identity(component):
        return f"oracle-listener:{oracle_listener}", "identified"
    purl = str(component.get("purl") or "")
    if purl:
        # A literal @ following the final slash separates the version. Decode
        # only afterwards: %40angular is a namespace, not a version separator.
        path, separator, qualifiers = purl.split("#", 1)[0].partition("?")
        version_separator = path.rfind("@")
        if version_separator > path.rfind("/"):
            path = path[:version_separator]
        base = unquote(path)
        if base.startswith("pkg:"):
            kind, slash, coordinate = base[4:].partition("/")
            kind = kind.lower()
            if kind in {"npm", "nuget", "pypi"}:
                coordinate = coordinate.lower()
            base = "pkg:" + kind + slash + coordinate
        if separator:
            base += "?" + unquote(qualifiers)
        return f"purl:{base}", "identified"
    ctype = str(component.get("type") or "library").lower()
    group = str(component.get("group") or "").strip().lower()
    name = str(component.get("name") or "").strip().lower()
    if name:
        return f"coord:{ctype}:{group}:{name}", "identified"
    bom_ref = str(component.get("bom-ref") or "")
    if bom_ref:
        return f"bom-ref:{bom_ref}", "review_required"
    return f"unknown:{hashlib.sha256(json.dumps(component, sort_keys=True).encode()).hexdigest()}", "review_required"


def sha256_for(component: dict) -> str:
    for digest in component.get("hashes") or []:
        if str(digest.get("alg", "")).replace("-", "").lower() == "sha256":
            return str(digest.get("content") or "").lower()
    return ""


def licenses_for(component: dict) -> list[str]:
    result: list[str] = []
    for value in component.get("licenses") or []:
        if isinstance(value, dict):
            if isinstance(value.get("expression"), str):
                result.append(value["expression"])
                continue
            license_value = value.get("license") or value
            if isinstance(license_value, dict):
                text = license_value.get("id") or license_value.get("name")
                if text:
                    result.append(str(text))
    return sorted(set(result))
