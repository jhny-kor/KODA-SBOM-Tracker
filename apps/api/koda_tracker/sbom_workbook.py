"""Convert the Excel inventory layout into an auditable CycloneDX document."""
from datetime import date, timedelta
from pathlib import Path
import re
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .sbom import SbomValidationError


WORKBOOK_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
MAX_WORKBOOK_BYTES = 10 * 1024**2
MAX_WORKBOOK_ROWS = 5_000
METADATA_LABELS = ("솔루션명", "기준 버전", "운영 OS Platform", "작성일자", "대상 서버")
_HEADERS = ("번호", "구분", "컴포넌트명", "버전", "라이선스 유형", "비고 / 상세 설명")
_SS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_PKG = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_CT = "{http://schemas.openxmlformats.org/package/2006/content-types}"
_WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"


def _xml(path: Path, expected: str):
    if not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise SbomValidationError("Excel 필수 파일이 없거나 XML 크기 제한(4 MiB)을 초과했습니다")
    try:
        root = SafeET.parse(path, forbid_dtd=True).getroot()
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise SbomValidationError("Excel 내부 XML이 올바르지 않습니다") from exc
    if root.tag != expected:
        raise SbomValidationError("Excel 내부 문서 형식이 올바르지 않습니다")
    return root


def _worksheet(directory: Path, workbook):
    sheet = workbook.find(f"{_SS}sheets/{_SS}sheet")
    identifier = sheet.get(f"{{{_REL}}}id") if sheet is not None else None
    relationships = _xml(directory / "xl/_rels/workbook.xml.rels", _PKG + "Relationships")
    matches = [rel for rel in relationships if identifier and rel.get("Id") == identifier]
    if len(matches) != 1:
        raise SbomValidationError("Excel 첫 번째 워크시트를 찾을 수 없습니다")
    relationship = matches[0]
    target = relationship.get("Target", "")
    target = target[1:] if target.startswith("/") else "xl/" + target
    if (
        relationship.get("TargetMode", "Internal") != "Internal"
        or relationship.get("Type") != _REL + "/worksheet"
        or not re.fullmatch(r"xl/worksheets/[A-Za-z0-9_.-]+\.xml", target)
    ):
        raise SbomValidationError("Excel 첫 번째 워크시트 경로가 올바르지 않습니다")
    return _xml(directory / target, _SS + "worksheet")


def _rich_text(element):
    if element is None:
        return ""
    return "".join(
        node.text or "" for node in element.findall(_SS + "t") + element.findall(f"{_SS}r/{_SS}t")
    )


def _cell_value(cell, strings, row):
    kind = cell.get("t", "n")
    if cell.find(_SS + "f") is not None or kind in {"b", "e"}:
        raise SbomValidationError(f"Excel {row}행에 수식, 논리값 또는 오류 값이 있습니다. 값을 직접 입력하세요")
    value = cell.findtext(_SS + "v", "")
    if kind == "s":
        if not re.fullmatch(r"[0-9]{1,8}", value) or int(value) >= len(strings):
            raise SbomValidationError(f"Excel {row}행의 공유 문자열이 올바르지 않습니다")
        return strings[int(value)].strip()
    if kind == "inlineStr":
        return _rich_text(cell.find(_SS + "is")).strip()
    if kind not in {"n", "str", "d"}:
        raise SbomValidationError(f"Excel {row}행의 셀 형식을 지원하지 않습니다")
    return value.strip()


def _rows(worksheet, strings):
    sheet_data = worksheet.find(_SS + "sheetData")
    if sheet_data is None:
        return
    previous = 0
    total_text_bytes = 0
    for row in sheet_data.findall(_SS + "row"):
        reference = row.get("r", "")
        if not re.fullmatch(r"[1-9][0-9]{0,6}", reference) or not previous < int(reference) <= 1_048_576:
            raise SbomValidationError("Excel 행 번호가 올바르지 않습니다")
        previous = int(reference)
        values = {}
        for cell in row.findall(_SS + "c"):
            match = re.fullmatch(r"([A-Z]{1,3})([1-9][0-9]{0,6})", cell.get("r", ""))
            if not match or match[2] != reference:
                raise SbomValidationError(f"Excel {reference}행의 셀 위치가 올바르지 않습니다")
            column = match[1]
            if len(column) != 1 or column > "F":
                continue
            if column in values:
                raise SbomValidationError(f"Excel {reference}행에 중복 셀이 있습니다")
            value = _cell_value(cell, strings, reference)
            if len(value) > 4096:
                raise SbomValidationError(f"Excel {reference}행의 셀은 4096자까지 입력할 수 있습니다")
            total_text_bytes += len(value.encode("utf-8"))
            if total_text_bytes > 2 * 1024**2:
                raise SbomValidationError("Excel 입력 내용이 2 MiB를 초과했습니다")
            values[column] = value, cell.get("t", "n")
        yield previous, values


def _text(values, column):
    return values.get(column, ("", ""))[0]


def _date_value(value, kind, workbook):
    # Excel commonly stores the 작성일자 cell as a day number.
    if not value or kind != "n":
        return value
    if not re.fullmatch(r"[0-9]{1,7}(?:\.[0-9]{1,16})?", value):
        raise SbomValidationError("Excel 작성일자를 날짜 또는 텍스트로 입력하세요")
    days = int(value.split(".")[0])
    properties = workbook.find(_SS + "workbookPr")
    year_1904 = properties is not None and properties.get("date1904") in {"1", "true"}
    if not year_1904 and days == 60:
        raise SbomValidationError("Excel 작성일자가 올바르지 않습니다")
    origin = date(1904, 1, 1) if year_1904 else date(1899, 12, 31)
    try:
        return (origin + timedelta(days=days - int(not year_1904 and days > 60))).isoformat()
    except OverflowError as exc:
        raise SbomValidationError("Excel 작성일자가 올바르지 않습니다") from exc


def _label(value):
    return "".join(value.split()).casefold()


def read_workbook(directory: Path) -> dict:
    content_types = _xml(directory / "[Content_Types].xml", _CT + "Types")
    if not any(part.get("PartName") == "/xl/workbook.xml" and part.get("ContentType") == _WORKBOOK_TYPE
               for part in content_types.findall(_CT + "Override")):
        raise SbomValidationError("매크로가 없는 Excel .xlsx 통합 문서를 선택하세요")
    workbook = _xml(directory / "xl/workbook.xml", _SS + "workbook")
    worksheet = _worksheet(directory, workbook)
    shared_strings = directory / "xl/sharedStrings.xml"
    strings = []
    if shared_strings.is_file():
        strings = [_rich_text(item) for item in _xml(shared_strings, _SS + "sst").findall(_SS + "si")]
    metadata, components = {}, []
    has_header = False
    for row, values in _rows(worksheet, strings):
        if row <= 5:
            label = METADATA_LABELS[row - 1]
            if _label(_text(values, "A") or _text(values, "B")) != _label(label):
                raise SbomValidationError(f"Excel {row}행에 '{label}' 항목을 입력하세요")
            value, kind = values.get("C", ("", ""))
            metadata[label] = _date_value(value, kind, workbook) if row == 4 else value
        elif row == 6:
            has_header = all(_label(_text(values, col)) == _label(label) for col, label in zip("ABCDEF", _HEADERS))
            if not has_header:
                raise SbomValidationError("Excel 6행에 번호, 구분, 컴포넌트명, 버전, 라이선스 유형, 비고 / 상세 설명 열이 필요합니다")
        elif any(value for value, _ in values.values()):
            number, category, name, version, license_name, description = (_text(values, col) for col in "ABCDEF")
            if not name or not version or len(name) > 255 or len(version) > 255:
                raise SbomValidationError(f"Excel {row}행의 컴포넌트명과 버전은 각각 1~255자여야 합니다")
            if len(components) >= MAX_WORKBOOK_ROWS:
                raise SbomValidationError(f"Excel 구성요소는 최대 {MAX_WORKBOOK_ROWS:,}개까지 등록할 수 있습니다")
            component = {"type": "library", "bom-ref": f"xlsx-row-{row}", "name": name, "version": version}
            if license_name:
                component["licenses"] = [{"license": {"name": license_name}}]
            if description:
                component["description"] = description
            component["properties"] = [
                {"name": f"koda:xlsx:{key}", "value": value}
                for key, value in (("row", number), ("category", category), ("description", description)) if value
            ]
            components.append(component)
    if len(metadata) != 5 or not has_header or not components:
        raise SbomValidationError("Excel 첫 시트에 솔루션 정보 5행, 열 제목 1행과 구성요소가 필요합니다")
    solution, version = (metadata[key] for key in METADATA_LABELS[:2])
    if not solution or not version or len(solution) > 255 or len(version) > 255:
        raise SbomValidationError("Excel 솔루션명과 기준 버전은 각각 1~255자여야 합니다")
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": solution, "version": version},
            "properties": [{"name": f"koda:xlsx:{key}", "value": value} for key, value in metadata.items() if value],
        },
        "components": components,
    }
