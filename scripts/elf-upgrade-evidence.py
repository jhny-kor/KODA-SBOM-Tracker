#!/usr/bin/env python3
"""Emit a Tracker ELF evidence object by reading local binaries with GNU readelf."""
import argparse
import json
import os
import re
import resource
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

_OUTPUT_LIMIT = 8 * 1024 * 1024
_MACHINE = {"Advanced Micro Devices X86-64": "x86_64", "AArch64": "aarch64"}
_HEADER = re.compile(r"^\s*(Class|Data|Type|Machine):\s*(.+)$", re.MULTILINE)
_DYNAMIC = re.compile(r"\((NEEDED|SONAME)\).*?\[([^\]]+)\]")
_SYMBOLS = re.compile(r"^Symbol table '\.dynsym' contains (\d+) entr(?:y|ies):$", re.MULTILINE)
_SYMBOL = re.compile(r"^\s*\d+:\s+[0-9A-Fa-f]+\s+\d+\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?(?:\s+\((\d+)\))?\s*$")
_NEED_FILE = re.compile(r"\bFile:\s+(\S+)\s+Cnt:\s*\d+")
_NEED_VERSION = re.compile(r"\bName:\s+(\S+)\s+Flags:\s+(.*?)\s+Version:\s+(\d+)\s*$")
_DEFINED_VERSION = re.compile(r"\bRev:\s+\d+\s+Flags:.*\bName:\s+(\S+)\s*$")
_NAME = re.compile(r"^[^/\\\x00-\x20\x7f]{1,255}$")


@dataclass
class Elf:
    platform: dict
    soname: str | None
    needed: set[str]
    exports: list[dict]
    imports: list[tuple[str, str | None, str | None]]
    versions: set[str]
    version_needs: dict[str, tuple[str, str, bool]]


def parse_readelf(text: str) -> Elf:
    header = dict(_HEADER.findall(text))
    try:
        platform = {
            "architecture": _MACHINE[header["Machine"]],
            "elfClass": int(header["Class"].removeprefix("ELF")),
            "byteOrder": "little" if "little endian" in header["Data"] else "big",
        }
        if header["Type"].split()[0] not in {"DYN", "EXEC"} or platform["elfClass"] not in {32, 64}:
            raise ValueError
    except (KeyError, IndexError, ValueError) as error:
        raise ValueError("지원되는 Linux ELF 실행 파일 또는 공유 라이브러리가 아닙니다") from error

    dynamic = _DYNAMIC.findall(text)
    needed = {name for tag, name in dynamic if tag == "NEEDED"}
    sonames = [name for tag, name in dynamic if tag == "SONAME"]
    if len(sonames) > 1:
        raise ValueError("공유 라이브러리 SONAME이 여러 개입니다")
    version_needs = {}
    versions = set()
    source = None
    for line in text.splitlines():
        if file := _NEED_FILE.search(line):
            source = file[1]
        if source and (item := _NEED_VERSION.search(line)):
            version_needs[item[3]] = (source, item[1], item[2].strip().lower() == "weak")
        if definition := _DEFINED_VERSION.search(line):
            versions.add(definition[1])

    table = _SYMBOLS.search(text)
    if table is None:
        raise ValueError("동적 심볼 표를 읽지 못했습니다")
    rows = text[table.end():].strip("\n").splitlines()[1:1 + int(table[1])]
    symbols = [_SYMBOL.fullmatch(row) for row in rows]
    if len(symbols) != int(table[1]) or any(symbol is None for symbol in symbols):
        raise ValueError("동적 심볼 표가 불완전합니다")

    exports = []
    imports = []
    for binding, visibility, section, value, index in (symbol.groups() for symbol in symbols):
        if not value or binding not in {"GLOBAL", "WEAK", "UNIQUE"}:
            continue
        name, default, version = value.partition("@@")
        if not default:
            name, _, version = value.partition("@")
        if section == "UND" or index in version_needs:
            if binding != "WEAK":
                imports.append((name, version or None, index))
        elif visibility in {"DEFAULT", "PROTECTED"}:
            exports.append({"name": name, "version": version or None, "defaultVersion": bool(default)})

    return Elf(platform, sonames[0] if sonames else None, needed, exports, imports, versions, version_needs)


def _cap_output():
    _, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = _OUTPUT_LIMIT if hard == resource.RLIM_INFINITY else min(_OUTPUT_LIMIT, hard)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))


def _read(path: Path) -> Elf:
    if not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError(f"{path.name}의 파일 형식 또는 크기가 지원 범위를 벗어났습니다")
    with path.open("rb") as binary:
        if binary.read(4) != b"\x7fELF":
            raise ValueError(f"{path.name}은 ELF 파일이 아닙니다")
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(
            ["readelf", "-W", "-h", "-d", "--dyn-syms", "--version-info", "--", str(path.resolve())],
            stdout=output, stderr=output, timeout=20, check=False, preexec_fn=_cap_output,
            env={**os.environ, "LC_ALL": "C", "DEBUGINFOD_URLS": ""},
        )
        if result.returncode or output.tell() >= _OUTPUT_LIMIT:
            raise ValueError(f"{path.name}의 ELF 정보를 읽지 못했거나 출력 한도를 초과했습니다")
        output.seek(0)
        text = output.read().decode("utf-8", errors="strict")
    if re.search(r"^readelf: (Warning|Error):", text, re.MULTILINE):
        raise ValueError(f"{path.name}의 ELF 정보를 완전히 읽지 못했습니다")
    return parse_readelf(text)


def build_evidence(consumers: list[tuple[str, Elf]], baseline: list[Elf], candidates: list[Elf], complete: bool) -> dict:
    baseline_names = {item.soname for item in baseline}
    if None in baseline_names or len(baseline_names) != len(baseline):
        raise ValueError("기준 라이브러리의 SONAME을 확인할 수 없거나 중복되었습니다")
    default_exports = {
        item.soname: {row["name"] for row in item.exports if row["version"] is None or row["defaultVersion"]}
        for item in baseline
    }

    results = []
    needed_exports: dict[str, set[str]] = {}
    needed_versions: dict[str, set[str]] = {}
    for name, consumer in consumers:
        requirements = {
            soname: {"soname": soname, "symbols": [], "versions": []}
            for soname in sorted(consumer.needed & baseline_names)
        }
        for source, version, weak in consumer.version_needs.values():
            if source in requirements and not weak:
                requirements[source]["versions"].append(version)
        for symbol, version, index in consumer.imports:
            if version:
                origin = consumer.version_needs.get(index)
                if origin is None or origin[1] != version:
                    complete = False
                elif origin[0] in requirements:
                    requirements[origin[0]]["symbols"].append({"name": symbol, "version": version})
            else:
                for soname in requirements:
                    if symbol in default_exports[soname]:
                        requirements[soname]["symbols"].append({"name": symbol, "definite": False})
        if not _NAME.fullmatch(name):
            raise ValueError("실행 파일명에 지원하지 않는 문자가 있습니다")
        for soname, requirement in requirements.items():
            needed_exports.setdefault(soname, set()).update(item["name"] for item in requirement["symbols"])
            needed_versions.setdefault(soname, set()).update(requirement["versions"])
        results.append({**consumer.platform, "name": name, "needed": list(requirements.values())})

    providers = []
    for item in candidates:
        if not item.soname:
            complete = False
            continue
        relevant_names = needed_exports.get(item.soname, set())
        providers.append({
            **item.platform, "soname": item.soname,
            "symbols": [symbol for symbol in item.exports if symbol["name"] in relevant_names],
            "versions": sorted(item.versions & needed_versions.get(item.soname, set())),
        })
    return {"kind": "elf", "source": "readelf", "complete": complete, "consumers": results, "providers": providers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--consumer", type=Path, action="append", required=True)
    parser.add_argument("--baseline-library", type=Path, action="append", required=True)
    parser.add_argument("--candidate-library", type=Path, action="append", default=[])
    parser.add_argument("--complete", action="store_true", help="declare the specified consumers and library inventories complete for the replacement scope")
    args = parser.parse_args()
    if max(len(args.consumer), len(args.baseline_library), len(args.candidate_library)) > 32:
        parser.error("입력 파일은 그룹당 최대 32개입니다")
    try:
        result = build_evidence(
            [(path.name, _read(path)) for path in args.consumer],
            [_read(path) for path in args.baseline_library],
            [_read(path) for path in args.candidate_library],
            args.complete,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
