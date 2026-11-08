import struct

import pytest

from koda_tracker.compatibility_rpm import parse_rpm


def _header(region, values):
    """Encode only the RPM v4 header subset needed by the fixture."""
    store = bytearray()
    tags = []
    for tag, kind, value in values:
        if kind == 4:
            store.extend(b"\x00" * (-len(store) % 4))
            offset = len(store)
            store.extend(struct.pack(f">{len(value)}I", *value))
            count = len(value)
        else:
            offset = len(store)
            store.extend(b"".join(item.encode() + b"\x00" for item in value))
            count = len(value)
        tags.append((tag, kind, offset, count))
    tags.insert(0, (region, 7, len(store), 16))
    store.extend(struct.pack(">IIiI", region, 7, -16 * len(tags), 16))
    index = b"".join(struct.pack(">IIiI", *entry) for entry in tags)
    return struct.pack(">8sII", b"\x8e\xad\xe8\x01" + bytes(4), len(tags), len(store)) + index + store


def _rpm(*, epoch=None, mismatch=False, duplicate=False, long=False):
    lead = bytearray(96)
    lead[:6] = b"\xed\xab\xee\xdb\x03\x00"
    lead[76:80] = b"\x00\x01\x00\x05"
    signature = _header(62, [(269, 6, ["fixture"])])
    signature += b"\x00" * (-len(signature) % 8)
    provides = ["libz.so.1()(64bit)", "libz.so.1(ZLIB_1.2.9)(64bit)", "zlib"]
    provided_versions = ["", "", "1.2.11-13.el8"]
    if long:
        provides += [f"capability{index}" for index in range(150)]
        provided_versions += [""] * 150
    values = [
        (1000, 6, ["zlib"]), (1001, 6, ["1.2.11"]), (1002, 6, ["13.el8"]),
        (1021, 6, ["linux"]), (1022, 6, ["x86_64"]),
        (1047, 8, provides), (1048, 4, [16384, 12]),
        (1049, 8, ["libc.so.6(GLIBC_2.14)(64bit)", "setup"]),
        (1050, 8, [""] if mismatch else ["", "2.0"]),
        (1112, 4, [32768, 32768, 8] + [0] * (len(provides) - 3)),
        (1113, 8, provided_versions),
    ]
    if epoch is not None:
        values.insert(3, (1003, 4, [epoch]))
    if duplicate:
        values.insert(0, (1000, 6, ["zlib"]))
    return bytes(lead) + signature + _header(63, values) + b"payload"


def _read(raw, **overrides):
    expected = {"package": "zlib", "version": "1.2.11-13.el8", "architecture": "x86_64"}
    return parse_rpm(raw, **(expected | overrides))


def test_extracts_rpm_evr_and_declared_soname_and_dependencies():
    result = _read(_rpm(), version="0:1.2.11-13.el8")
    assert result["version"] == "1.2.11-13.el8"
    assert result["package"] == "zlib"
    assert result["architecture"] == "x86_64"
    assert result["providesCount"] == 3
    assert result["requiresCount"] == 2
    assert {"name": "libz.so.1(ZLIB_1.2.9)(64bit)", "flags": 32768} in result["provides"]
    assert {"name": "libc.so.6(GLIBC_2.14)(64bit)", "flags": 16384} in result["requires"]
    assert {"name": "setup", "flags": 12, "operator": ">=", "version": "2.0"} in result["requires"]
    assert _read(_rpm(epoch=2), version="2:1.2.11-13.el8")["version"] == "2:1.2.11-13.el8"


@pytest.mark.parametrize("overrides", [
    {"package": "unrelated"},
    {"version": "1.2.12-13.el8"},
    {"version": "1.2.11-14.el8"},
    {"version": "1:1.2.11-13.el8"},
    {"version": "1.2.11"},
    {"architecture": "aarch64"},
])
def test_rejects_a_mismatched_package_identity(overrides):
    with pytest.raises(ValueError):
        _read(_rpm(), **overrides)


@pytest.mark.parametrize("raw", [_rpm()[:97], _rpm()[:-7], _rpm(duplicate=True), _rpm(mismatch=True)])
def test_rejects_invalid_or_truncated_rpm(raw):
    with pytest.raises(ValueError):
        _read(raw)


def test_rejects_oversized_header_index():
    raw = bytearray(_rpm())
    struct.pack_into(">I", raw, 96 + 8, 2**32 - 1)
    with pytest.raises(ValueError):
        _read(raw)


def test_reports_truncation_by_returning_the_declared_count():
    result = _read(_rpm(long=True))
    assert result["providesCount"] == 153
    assert len(result["provides"]) == 128
