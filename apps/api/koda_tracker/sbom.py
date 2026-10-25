from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote

from defusedxml import ElementTree as SafeET


class SbomValidationError(ValueError):
    pass


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


def parse_sbom_file(path: Path) -> tuple[dict, str]:
    with path.open("rb") as candidate:
        prefix = candidate.read(4096).lstrip()
        candidate.seek(0)
        if prefix.startswith((b"{", b"[")):
            try:
                payload = json.load(candidate)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SbomValidationError("유효한 JSON 문서가 아닙니다") from exc
            payload, media = _normalize_json(payload)
        elif prefix.startswith(b"<"):
            carry = b""
            while chunk := candidate.read(1024 * 1024):
                upper = (carry + chunk).upper()
                if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
                    raise SbomValidationError("DTD와 외부 엔티티는 허용되지 않습니다")
                carry = upper[-16:]
            candidate.seek(0)
            try:
                root = SafeET.parse(candidate).getroot()
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
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SbomValidationError(f"CycloneDX CLI 검증기를 실행할 수 없습니다: {exc}") from exc


def validate_file_with_cyclonedx_cli(path: Path, binary: str, *, input_format: str | None = None) -> None:
    if not binary:
        return
    # SPDX's original file is retained as the uploaded artifact. Validate the
    # normalized CycloneDX view with this optional CycloneDX-only validator.
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
                with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8") as converted:
                    json.dump(normalized, converted, ensure_ascii=False)
                    converted.flush()
                    return validate_file_with_cyclonedx_cli(Path(converted.name), binary, input_format="json")
    command = [binary, "validate", "--input-file", str(path)]
    if input_format:
        command.extend(["--input-format", input_format])
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise SbomValidationError(f"CycloneDX CLI 검증기를 실행할 수 없습니다: {exc}") from exc
    if process.returncode != 0:
        message = (process.stderr or process.stdout or "스키마 검증 실패").strip()
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
