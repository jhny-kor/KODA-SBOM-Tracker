"""Read the 20-field NIS-SBOM 1.0 CSV exported by KODA."""
from __future__ import annotations

import csv
import io
import re


NIS_SBOM_MEDIA_TYPE = "text/csv"
_COLUMNS = (
    "SBOM Standard", "SBOM Type", "CycloneDXNo.", "SPDX Doc. ID", "SBOM ID",
    "Product Name", "Product Version", "Component Name", "Component Alias", "Component Version",
    "Component Supplier Name", "Component Hash", "Component Path", "SBOM Author Name",
    "Unique Identifier", "Dependency Relationship", "Timestamp", "License Name·Version", "Vul. DB", "Vul. Info",
)
_DOCUMENT_FIELDS = frozenset(_COLUMNS[:7]) | {"SBOM Author Name", "Timestamp"}
_ROW_CHAR_LIMIT = 64 * 1024
_PURL = re.compile(r"pkg:[a-zA-Z][a-zA-Z0-9.+-]*/\S{1,799}")
_SHA256 = re.compile(r"(?:alg\s*:\s*SHA-?256\s+content\s*:\s*)?([a-f0-9]{64})", re.IGNORECASE)


def is_nis_csv(prefix: bytes) -> bool:
    header = prefix.split(b"\n", 1)[0]
    return b"SBOM Standard" in header and b"," in header


def _properties(fields: dict[str, str], names) -> list[dict[str, str]]:
    return [{"name": f"koda:nis:{name}", "value": value} for name, value in fields.items() if name in names and value]


def read_nis_csv(source, *, max_components: int) -> dict:
    # Bound the whole logical CSV record, including any quoted physical lines.
    # csv's field size limit only bounds each individual field.
    remaining = _ROW_CHAR_LIMIT
    text = io.TextIOWrapper(source, encoding="utf-8-sig", newline="")

    def lines():
        nonlocal remaining
        while line := text.readline(remaining + 1):
            remaining -= len(line)
            if remaining < 0 or "\x00" in line:
                raise ValueError("NIS-SBOM CSV 행이 너무 길거나 NUL 문자를 포함합니다")
            yield line

    try:
        reader = csv.reader(lines(), strict=True)
        header = next(reader, [])
        if len(header) != len(_COLUMNS) or set(header) != set(_COLUMNS):
            raise ValueError("NIS-SBOM 1.0 CSV 기본 열 20개가 필요합니다")
        components = []
        metadata = {}
        while True:
            remaining = _ROW_CHAR_LIMIT
            row_number = reader.line_num + 1
            row = next(reader, None)
            if row is None:
                break
            if not row:
                continue
            if len(row) != len(header):
                raise ValueError(f"NIS-SBOM CSV {row_number}행의 열 개수가 올바르지 않습니다")
            if len(components) >= max_components:
                raise ValueError(f"SBOM 구성요소 수가 제한({max_components})을 초과했습니다")
            fields = dict(zip(header, (cell.strip() for cell in row)))
            if fields["SBOM Standard"] != "NIS 1.0":
                raise ValueError(f"NIS-SBOM CSV {row_number}행의 SBOM Standard는 NIS 1.0이어야 합니다")
            name = fields["Component Name"]
            version = fields["Component Version"]
            if not name or len(name) > 512 or len(version) > 255:
                raise ValueError(f"NIS-SBOM CSV {row_number}행의 구성요소명 또는 버전 길이가 올바르지 않습니다")
            component = {
                "type": "library", "bom-ref": f"nis-row-{row_number}", "name": name,
                "properties": _properties(fields, set(fields) - _DOCUMENT_FIELDS),
            }
            if version:
                component["version"] = version
            identifier = fields["Unique Identifier"]
            if _PURL.fullmatch(identifier):
                component["purl"] = identifier
            if supplier := fields["Component Supplier Name"]:
                component["supplier"] = {"name": supplier}
            if digest := _SHA256.fullmatch(fields["Component Hash"]):
                component["hashes"] = [{"alg": "SHA-256", "content": digest[1].lower()}]
            if license_name := fields["License Name·Version"]:
                component["licenses"] = [{"license": {"name": license_name}}]
            if not components:
                metadata["properties"] = [
                    {"name": "koda:source-format", "value": "NIS-SBOM 1.0 CSV"},
                    *_properties(fields, _DOCUMENT_FIELDS),
                ]
                if product_name := fields["Product Name"]:
                    metadata["component"] = {"type": "application", "name": product_name}
                    if product_version := fields["Product Version"]:
                        metadata["component"]["version"] = product_version
            components.append(component)
        if not components:
            raise ValueError("NIS-SBOM CSV에 구성요소가 없습니다")
        return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                "metadata": metadata, "components": components}
    except (UnicodeError, csv.Error) as exc:
        raise ValueError("올바른 UTF-8 형식의 NIS-SBOM CSV를 선택하세요") from exc
    finally:
        text.detach()
