"""Run offline Grype over size-bounded CycloneDX batches."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable
from itertools import chain
from pathlib import Path
from urllib.parse import parse_qsl

from .sbom import iter_components
from .streaming_nvd import read_json_sections


_MAX_BATCH_BYTES = 48 * 1024**2
_MAX_BATCH_COMPONENTS = 4096
_MAX_RESULT_BYTES = 128 * 1024**2
_MAX_MATCHES = 100_000
_MAX_DISTRO_CONTEXTS = 64
_MAX_DIAGNOSTIC_BYTES = 4096
_BATCH_TIMEOUT = 300
_SCAN_TIMEOUT = 7200
_SCANNER_PACKAGE_TYPES = {"application", "framework", "library", "machine-learning-model", "firmware"}
_RESULT_TEMPLATE = (
    '{"descriptor":{"version":{{toJson .Descriptor.Version}}},"matches":['
    '{{range $i, $match := .Matches}}{{if $i}},{{end}}'
    '{"artifact":{"id":{{toJson $match.Artifact.ID}},"name":{{toJson $match.Artifact.Name}},'
    '"purl":{{toJson $match.Artifact.PURL}},"version":{{toJson $match.Artifact.Version}}},'
    '"vulnerability":{{toJson $match.Vulnerability}},'
    '"relatedVulnerabilities":{{toJson $match.RelatedVulnerabilities}}}'
    '{{end}}]}'
)


def _encode(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def grype_cyclonedx_view(document: dict) -> dict:
    if document.get("specVersion") != "1.7":
        return document
    # The bundled Grype 0.109.1 cannot detect CycloneDX 1.7. Its 1.6 decoder
    # still consumes the package fields shared by both versions. This view is
    # exclusively for the scanner; the original and stored inventory stay 1.7.
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        **{key: value for key, value in document.items() if key not in {"$schema", "bomFormat", "specVersion"}},
    }


def _scanner_component(component: dict) -> dict:
    # Syft's CycloneDX package importer uses properties for location and
    # identity metadata. It does not consume CycloneDX evidence occurrences.
    # The original records retain both representations.
    result = {key: value for key, value in component.items() if key != "evidence"}
    if "components" in result:
        result["components"] = [_scanner_component(child) for child in result["components"]]
    return result


def _context_for_batches(bom: dict, components: Iterable[dict]) -> tuple[dict, int | None, list[dict], set[str]]:
    # Syft reads distro fields from the first top-level OS component. Keep
    # this component in every batch and scan its children only once.
    distro = None
    distro_index = None
    inferred = {}
    marker_prefix = "koda-grype-context:" + uuid.uuid4().hex

    def collect_qualifiers(items: Iterable[dict]) -> None:
        for item in items:
            if item.get("type") not in _SCANNER_PACKAGE_TYPES:
                continue
            purl = item.get("purl") or item.get("bom-ref") or ""
            if not purl.startswith("pkg:") or "?" not in purl:
                continue
            query = purl.partition("?")[2].partition("#")[0]
            qualifier = next((value for key, value in parse_qsl(query) if key.lower() == "distro"), "")
            key = (qualifier, item["type"] == "firmware")
            if qualifier and key not in inferred:
                if len(inferred) >= _MAX_DISTRO_CONTEXTS:
                    raise ValueError("대용량 SBOM 분석의 배포판 종류 한도를 초과했습니다")
                inferred[key] = {
                    "bom-ref": f"{marker_prefix}:{len(inferred)}",
                    "type": item["type"],
                    "name": item["name"],
                    "purl": purl,
                    "version": item.get("version", ""),
                }

    metadata = bom.get("metadata") or {}
    root = metadata.get("component")
    if root is not None:
        collect_qualifiers(iter_components([root]))
    for index, component in enumerate(components):
        if distro is None and component.get("type") == "operating-system":
            distro = {key: value for key, value in component.items() if key not in {"components", "evidence"}}
            distro_index = index
        collect_qualifiers(iter_components([component]))

    # Without conclusive OS metadata, Grype infers context from qualifier
    # values across the entire inventory. Keep representatives in each batch
    # so one batch cannot infer a different distro from the original SBOM.
    context = ([distro] if distro is not None else []) + list(inferred.values())
    marker_refs = {item["bom-ref"] for item in inferred.values()}
    subsequent = dict(metadata)
    if root is not None and root.get("type") in {"container", "file"}:
        subsequent["component"] = {key: value for key, value in root.items() if key != "components"}
    else:
        subsequent.pop("component", None)
    return subsequent, distro_index, context, marker_refs


def _batch_records(components: Iterable[dict], distro_index: int | None) -> Iterable[dict]:
    for index, component in enumerate(components):
        if index == distro_index:
            yield from component.get("components") or []
        else:
            yield component


def _write_batch(path: Path, prefix: bytes, records: list[bytes], context: list[bytes]) -> None:
    with path.open("wb") as stream:
        stream.write(prefix)
        for index, record in enumerate(chain(context, records)):
            if index:
                stream.write(b",")
            stream.write(record)
        stream.write(b"]}")


def _run_batch(binary: str, path: Path, output: Path, env: dict[str, str], deadline: float) -> None:
    deadline = min(deadline, time.monotonic() + _BATCH_TIMEOUT)
    read_bytes = 0
    diagnostics = b""
    with (
        output.open("wb") as result,
        subprocess.Popen([binary, f"sbom:{path}", "-o", "template", "-t", str(path.with_suffix(".tmpl"))], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env) as process,
        selectors.DefaultSelector() as ready,
    ):
        ready.register(process.stdout, selectors.EVENT_READ, "stdout")
        ready.register(process.stderr, selectors.EVENT_READ, "stderr")
        try:
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("대용량 SBOM Grype 분석 시간이 초과되었습니다")
                for key, _ in ready.select(remaining):
                    chunk = os.read(key.fd, 64 * 1024)
                    if not chunk:
                        ready.unregister(key.fileobj)
                    elif key.data == "stderr":
                        diagnostics = (diagnostics + chunk)[-_MAX_DIAGNOSTIC_BYTES:]
                    else:
                        read_bytes += len(chunk)
                        if read_bytes > _MAX_RESULT_BYTES:
                            raise ValueError("대용량 SBOM Grype 분석의 배치 결과 크기 한도를 초과했습니다")
                        result.write(chunk)
            if process.wait(timeout=max(0, deadline - time.monotonic())):
                raise ValueError(diagnostics.decode("utf-8", errors="replace").strip() or "Grype 분석 실패")
        finally:
            if process.poll() is None:
                process.kill()


def scan_large_sbom(
    bom_metadata: dict,
    components: Callable[[], Iterable[dict]],
    *,
    binary: str,
    env: dict[str, str],
    spool: Path,
    on_match: Callable[[dict], None],
) -> str:
    """Scan complete component records and emit provisional Grype matches.

    The caller must publish findings after all batches succeed. CycloneDX
    dependencies become Syft dependency edges, while Grype uses its distinct
    package-ownership edges for matching. Tracker retains the full dependency
    graph separately.
    """
    deadline = time.monotonic() + _SCAN_TIMEOUT
    root = {key: bom_metadata[key] for key in ("bomFormat", "specVersion", "version", "serialNumber", "metadata")
            if key in bom_metadata}
    root = grype_cyclonedx_view(root)
    if root.get("metadata", {}).get("component") is not None:
        metadata = root["metadata"]
        root["metadata"] = {**metadata, "component": _scanner_component(metadata["component"])}
    subsequent, distro_index, context, marker_refs = _context_for_batches(root, components())
    encoded_context = [_encode(item) for item in context]
    context_size = sum(len(item) + 1 for item in encoded_context)
    prefix = _encode(root)[:-1] + b',"components":['
    next_prefix = _encode({**root, "metadata": subsequent})[:-1] + b',"components":['
    if max(len(prefix), len(next_prefix)) + context_size + 2 > _MAX_BATCH_BYTES:
        raise ValueError("대용량 SBOM Grype 분석의 공통 메타데이터 크기 한도를 초과했습니다")
    match_count = 0
    tool_version = ""

    def emit(section: str, key: str | int, value: object) -> None:
        nonlocal match_count, tool_version
        if section == "descriptor":
            if key == "version" and isinstance(value, str):
                if tool_version and value != tool_version:
                    raise ValueError("대용량 SBOM 분석 중 Grype 버전이 변경되었습니다")
                tool_version = value
            return
        if not isinstance(value, dict) or not isinstance(value.get("artifact"), dict) or not isinstance(value.get("vulnerability"), dict):
            raise ValueError("Grype 취약점 결과가 올바르지 않습니다")
        if value["artifact"].get("id") in marker_refs:
            return
        match_count += 1
        if match_count > _MAX_MATCHES:
            raise ValueError("대용량 SBOM Grype 분석의 취약점 결과 수 한도를 초과했습니다")
        on_match(value)

    with tempfile.TemporaryDirectory(prefix=".koda-grype-batches-", dir=spool) as temporary:
        document = Path(temporary) / "sbom.cdx.json"
        output = Path(temporary) / "grype.json"
        # Findings retain the same fields as the regular Tracker scanner.
        # Grype otherwise repeats all package locations once per match.
        document.with_suffix(".tmpl").write_text(_RESULT_TEMPLATE, encoding="utf-8")
        batch = []
        size = len(prefix) + context_size + 2

        def scan_batch() -> None:
            _write_batch(document, prefix, batch, encoded_context)
            _run_batch(binary, document, output, env, deadline)
            sections = read_json_sections(output, section_names={"matches", "descriptor"}, on_entry=emit).sections
            if "matches" not in sections or sections["matches"].kind != "list":
                raise ValueError("Grype 분석 결과에 취약점 목록이 없습니다")

        for component in _batch_records(components(), distro_index):
            encoded = _encode(_scanner_component(component))
            if batch and (len(batch) >= _MAX_BATCH_COMPONENTS or size + len(encoded) + 1 > _MAX_BATCH_BYTES):
                scan_batch()
                prefix = next_prefix
                batch = []
                size = len(prefix) + context_size + 2
            size += len(encoded) + 1
            if size > _MAX_BATCH_BYTES:
                raise ValueError("대용량 SBOM 구성요소가 Grype 분석 배치 크기 한도를 초과했습니다")
            batch.append(encoded)
        scan_batch()
    return tool_version or "grype"
