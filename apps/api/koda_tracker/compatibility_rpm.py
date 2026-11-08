"""Read bounded Oracle Linux RPM header evidence without loading its payload.

The package declares capabilities and requirements. These fields alone do not
describe the installed ABI or establish that an application's build succeeded.
"""

from bisect import bisect_right
import re
import struct
from typing import NamedTuple

_LEAD_MAGIC = b"\xed\xab\xee\xdb"
_HEADER_MAGIC = b"\x8e\xad\xe8\x01\x00\x00\x00\x00"
_LEAD_SIZE = 96
_HEADER_INTRO = struct.Struct(">8sII")
_INDEX = struct.Struct(">IIiI")
_MAX_TAGS = 16_384
_MAX_HEADER_BYTES = 8 * 1024 * 1024
_MAX_DEPENDENCIES = 4096
_MAX_VISIBLE_DEPENDENCIES = 128
_FIXED_WIDTH = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}
_EVR = re.compile(r"(?:(?P<epoch>[0-9]{1,10}):)?(?P<version>[A-Za-z0-9._+~^]+)-(?P<release>[A-Za-z0-9._+~^]+)")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_OPERATORS = {2: "<", 4: ">", 8: "=", 10: "<=", 12: ">="}


class _Entry(NamedTuple):
    kind: int
    offset: int
    count: int


class _Header(NamedTuple):
    store: bytes
    tags: dict[int, _Entry]
    offsets: list[int]
    end: int

    def tag_limit(self, offset: int) -> int:
        index = bisect_right(self.offsets, offset)
        return self.offsets[index] if index < len(self.offsets) else len(self.store)

    def strings(self, tag: int, kind: int) -> list[str]:
        entry = self.tags.get(tag)
        if entry is None:
            return []
        if entry.kind != kind or entry.count > _MAX_DEPENDENCIES:
            raise ValueError("잘못된 RPM 문자열 태그 형식입니다")
        cursor = entry.offset
        limit = self.tag_limit(cursor)
        values = []
        for _ in range(entry.count):
            end = self.store.find(b"\x00", cursor, min(limit, cursor + 513))
            if end < 0:
                raise ValueError("RPM 문자열 태그가 잘렸거나 너무 깁니다")
            value = self.store[cursor:end].decode("utf-8")
            if _CONTROL.search(value):
                raise ValueError("RPM 메타데이터에 잘못된 문자가 있습니다")
            values.append(value)
            cursor = end + 1
        return values

    def required_string(self, tag: int) -> str:
        values = self.strings(tag, 6)
        if not values or not values[0]:
            raise ValueError("필수 RPM 패키지 식별 정보가 없습니다")
        return values[0]

    def integers(self, tag: int) -> tuple[int, ...]:
        entry = self.tags.get(tag)
        if entry is None:
            return ()
        if (entry.kind != 4 or entry.count > _MAX_DEPENDENCIES
                or entry.offset + entry.count * 4 > self.tag_limit(entry.offset)):
            raise ValueError("잘못된 RPM 정수 태그 형식입니다")
        return struct.unpack_from(f">{entry.count}I", self.store, entry.offset)


def _read_header(raw: bytes, start: int, region_tag: int) -> _Header:
    if len(raw) - start < _HEADER_INTRO.size:
        raise ValueError("RPM 헤더가 잘렸습니다")
    magic, count, size = _HEADER_INTRO.unpack_from(raw, start)
    if magic != _HEADER_MAGIC or not 1 <= count <= _MAX_TAGS or not 16 <= size <= _MAX_HEADER_BYTES:
        raise ValueError("지원 범위를 벗어난 RPM 헤더 형식입니다")
    index_start = start + _HEADER_INTRO.size
    store_start = index_start + count * _INDEX.size
    end = store_start + size
    if end > len(raw):
        raise ValueError("RPM 헤더가 잘렸습니다")

    tags = {}
    for tag, kind, offset, value_count in _INDEX.iter_unpack(memoryview(raw)[index_start:store_start]):
        width = _FIXED_WIDTH.get(kind)
        if (tag in tags or not 0 <= offset < size or not value_count
                or (width is None and kind not in {6, 8, 9})
                or (kind == 6 and value_count != 1)
                or (width is not None and (offset % width or value_count * width > size - offset))):
            raise ValueError("잘못된 RPM 헤더 색인입니다")
        tags[tag] = _Entry(kind, offset, value_count)
    # Support original immutable v4 headers as published by Oracle Linux.
    # A trailing 16-byte region record identifies the signed header entries.
    store = raw[store_start:end]
    region = tags.get(region_tag)
    if (next(iter(tags)) != region_tag or region != _Entry(7, size - 16, 16)
            or _INDEX.unpack_from(store, size - 16) != (region_tag, 7, -count * _INDEX.size, 16)
            or any(entry.offset >= size - 16 for tag, entry in tags.items() if tag != region_tag)):
        raise ValueError("원본 RPM v4 헤더 영역을 확인할 수 없습니다")
    return _Header(store, tags, sorted({entry.offset for entry in tags.values()}), end)


def _dependencies(header: _Header, name_tag: int, version_tag: int, flags_tag: int) -> tuple[list[dict], int]:
    names = header.strings(name_tag, 8)
    versions = header.strings(version_tag, 8)
    flags = header.integers(flags_tag)
    if len(names) != len(versions) or len(names) != len(flags) or any(not name.strip() for name in names):
        raise ValueError("RPM 제공·요구 태그 수가 일치하지 않습니다")
    entries = []
    for name, version, flag in zip(names, versions, flags, strict=True):
        item = {"name": name, "flags": flag}
        if version:
            item["version"] = version
        if operator := _OPERATORS.get(flag & 14):
            item["operator"] = operator
        entries.append(item)
    return entries[:_MAX_VISIBLE_DEPENDENCIES], len(entries)


def parse_rpm(raw: bytes, *, package: str, version: str, architecture: str) -> dict:
    """Return declared requirements and provides from a matching binary RPM."""
    if (len(raw) <= _LEAD_SIZE or raw[:4] != _LEAD_MAGIC or raw[4:6] != b"\x03\x00"
            or raw[6:8] != b"\x00\x00" or raw[78:80] != b"\x00\x05"):
        raise ValueError("지원되는 바이너리 RPM 형식이 아닙니다")
    expected = _EVR.fullmatch(version)
    if expected is None:
        raise ValueError("RPM 버전에는 버전과 릴리스가 필요합니다")

    signature = _read_header(raw, _LEAD_SIZE, 62)
    header_start = (signature.end + 7) & ~7
    if any(raw[signature.end:header_start]):
        raise ValueError("RPM 서명 영역 패딩이 올바르지 않습니다")
    header = _read_header(raw, header_start, 63)
    if header.end >= len(raw):
        raise ValueError("RPM 페이로드가 누락되었습니다")

    name = header.required_string(1000)
    upstream = header.required_string(1001)
    release = header.required_string(1002)
    epoch = header.integers(1003)
    actual_arch = header.required_string(1022)
    if (len(epoch) > 1 or name != package or upstream != expected["version"] or release != expected["release"]
            or (epoch[0] if epoch else 0) != int(expected["epoch"] or 0)
            or actual_arch != architecture or actual_arch in {"src", "nosrc"}
            or header.required_string(1021) != "linux"):
        raise ValueError("RPM 헤더의 이름, 버전 또는 아키텍처가 선언과 다릅니다")

    evr = f"{upstream}-{release}"
    if epoch and epoch[0]:
        evr = f"{epoch[0]}:{evr}"
    provides, provides_count = _dependencies(header, 1047, 1113, 1112)
    requires, requires_count = _dependencies(header, 1049, 1050, 1048)
    return {
        "package": name,
        "version": evr,
        "architecture": actual_arch,
        "provides": provides,
        "requires": requires,
        "providesCount": provides_count,
        "requiresCount": requires_count,
    }
