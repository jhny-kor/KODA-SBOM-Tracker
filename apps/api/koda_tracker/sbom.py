from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote

from defusedxml import ElementTree as SafeET


class SbomValidationError(ValueError):
    pass


def parse_sbom(raw: bytes) -> tuple[dict, str]:
    stripped = raw.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SbomValidationError("유효한 JSON 문서가 아닙니다") from exc
        media = "application/vnd.cyclonedx+json"
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
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise SbomValidationError("CycloneDX SBOM이 아닙니다")
    version = str(payload.get("specVersion", ""))
    if version not in {"1.4", "1.5", "1.6", "1.7"}:
        raise SbomValidationError(f"지원하지 않는 CycloneDX 버전입니다: {version or 'unknown'}")
    if not isinstance(payload.get("components", []), list):
        raise SbomValidationError("components는 배열이어야 합니다")
    return payload, media


def validate_with_cyclonedx_cli(raw: bytes, binary: str) -> None:
    """Run the pinned CycloneDX CLI schema validator when it is configured."""
    if not binary:
        return
    suffix = ".json" if raw.lstrip().startswith((b"{", b"[")) else ".xml"
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix) as candidate:
            candidate.write(raw)
            candidate.flush()
            process = subprocess.run(
                [binary, "validate", "--input-file", candidate.name],
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


def _text(element, child: str) -> str:
    for item in element:
        if _local(item.tag) == child:
            return item.text or ""
    return ""


def _xml_payload(root) -> dict:
    if _local(root.tag) != "bom":
        raise SbomValidationError("CycloneDX XML 루트는 bom이어야 합니다")
    namespace = root.tag.split("}", 1)[0].lstrip("{") if "}" in root.tag else ""
    version_match = re.search(r"bom/(\d+\.\d+)", namespace)
    payload: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": version_match.group(1) if version_match else root.attrib.get("version", ""),
        "serialNumber": root.attrib.get("serialNumber"),
        "components": [],
    }
    components_node = next((node for node in root if _local(node.tag) == "components"), None)
    if components_node is None:
        return payload
    for node in components_node:
        if _local(node.tag) != "component":
            continue
        item: dict = {
            "type": node.attrib.get("type", "library"),
            "bom-ref": node.attrib.get("bom-ref", ""),
            "group": _text(node, "group"),
            "name": _text(node, "name"),
            "version": _text(node, "version"),
            "purl": _text(node, "purl"),
            "hashes": [],
            "licenses": [],
            "properties": [],
        }
        for child in node:
            kind = _local(child.tag)
            if kind == "hashes":
                for digest in child:
                    item["hashes"].append({"alg": digest.attrib.get("alg", ""), "content": digest.text or ""})
            elif kind == "licenses":
                for license_node in child:
                    identifier = _text(license_node, "id") or _text(license_node, "name")
                    if identifier:
                        item["licenses"].append({"license": {"id": identifier}})
            elif kind == "properties":
                for prop in child:
                    item["properties"].append({"name": prop.attrib.get("name", ""), "value": prop.text or ""})
        payload["components"].append(item)
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


def normalized_identity(component: dict) -> tuple[str, str]:
    purl = str(component.get("purl") or "")
    if purl:
        base = unquote(purl.split("#", 1)[0])
        base = re.sub(r"@[^?]+(?=\?|$)", "", base)
        return f"purl:{base.lower()}", "identified"
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
            license_value = value.get("license") or value
            if isinstance(license_value, dict):
                text = license_value.get("id") or license_value.get("name")
                if text:
                    result.append(str(text))
    return sorted(set(result))
