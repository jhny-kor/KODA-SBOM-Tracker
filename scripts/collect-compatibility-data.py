#!/usr/bin/env python3
"""Collect selected public Maven, PyPI and Oracle Linux evidence into a Tracker tar.gz."""
import argparse
from datetime import UTC, datetime
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sys
import tarfile
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps/api"))

from koda_tracker.compatibility_sources import (
    FILE_LIMITS, MAX_ARCHIVE_BYTES, MAX_ITEMS, MAX_UNPACKED_BYTES, canonical_python_name,
    maven_pom_url, oracle_rpm_location, pypi_release_url, pypi_wheel_filename,
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(opener, url, kind):
    request = Request(url, headers={"User-Agent": "KODA-Compatibility-Collector/1", "Accept-Encoding": "identity"})
    with opener.open(request, timeout=25) as response:
        if response.geturl() != url:
            raise ValueError("공식 저장소 원본 주소가 변경되었습니다")
        limit = FILE_LIMITS[kind]
        body = response.read(limit + 1)
        if not body or len(body) > limit:
            raise ValueError(f"원본 파일 크기가 허용 범위를 벗어났습니다 · {kind}")
        return body


def collect(args) -> tuple[bytes, dict]:
    total = sum(len(rows) for rows in (args.maven, args.python, args.oracle_rpm))
    if not 1 <= total <= MAX_ITEMS:
        raise ValueError(f"한 압축에 대상 1~{MAX_ITEMS}개를 지정하세요")
    opener = build_opener(NoRedirect())
    items, originals = [], {}
    original_bytes = 0

    def add(item, kind, url, raw):
        nonlocal original_bytes
        original_bytes += len(raw)
        if original_bytes > MAX_UNPACKED_BYTES - 512 * 1024:
            raise ValueError("원본 자료의 합계가 압축 해제 한도를 넘습니다. 수집 대상을 나누세요")
        extension = {"pom": "pom", "pypi_release": "json", "wheel": "whl", "rpm": "rpm"}[kind]
        path = f"files/{len(items):02d}-{kind}.{extension}"
        originals[path] = raw
        item["files"].append({"kind": kind, "path": path, "url": url, "size": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest()})

    for package, version in args.maven:
        item = {"ecosystem": "maven", "package": package, "version": version, "files": []}
        url = maven_pom_url(package, version)
        add(item, "pom", url, fetch(opener, url, "pom"))
        items.append(item)

    for package, version, filename in args.python:
        package = canonical_python_name(package)
        item = {"ecosystem": "python", "package": package, "version": version, "files": []}
        url = pypi_release_url(package, version)
        release_raw = fetch(opener, url, "pypi_release")
        release = json.loads(release_raw)
        info = release["info"]
        if canonical_python_name(info["name"]) != package or info["version"] != version:
            raise ValueError("PyPI 응답의 패키지 또는 버전이 요청과 다릅니다")
        selected = [row for row in release["urls"] if row["filename"] == filename and row["packagetype"] == "bdist_wheel"]
        if len(selected) != 1 or pypi_wheel_filename(selected[0]["url"]) != filename:
            raise ValueError(f"지정 PyPI 릴리스에서 정확한 wheel을 찾을 수 없습니다 · {filename}")
        wheel = selected[0]
        wheel_raw = fetch(opener, wheel["url"], "wheel")
        if len(wheel_raw) != wheel["size"] or hashlib.sha256(wheel_raw).hexdigest() != wheel["digests"]["sha256"]:
            raise ValueError("공식 PyPI 배포 정보의 SHA-256 또는 크기가 다운로드와 일치하지 않습니다")
        add(item, "pypi_release", url, release_raw)
        add(item, "wheel", wheel["url"], wheel_raw)
        items.append(item)

    for package, version, url in args.oracle_rpm:
        architecture, filename = oracle_rpm_location(url)
        if filename != f"{package}-{version.split(':', 1)[-1]}.{architecture}.rpm":
            raise ValueError("Oracle Linux RPM 주소의 파일명이 지정 패키지·버전과 다릅니다")
        item = {"ecosystem": "elf", "package": package, "version": version, "architecture": architecture, "files": []}
        add(item, "rpm", url, fetch(opener, url, "rpm"))
        items.append(item)

    identities = {(item["ecosystem"], item["package"], item["version"], item.get("architecture")) for item in items}
    if len(identities) != len(items):
        raise ValueError("같은 패키지·버전·아키텍처를 중복 지정할 수 없습니다")
    manifest = {"schemaVersion": 1, "profile": "official-v1", "collectedAt": datetime.now(UTC).isoformat(),
                "items": items}
    data = BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for path, raw in [("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode()), *originals.items()]:
            entry = tarfile.TarInfo(path)
            entry.size = len(raw)
            entry.mode = 0o644
            archive.addfile(entry, BytesIO(raw))
    if data.tell() > MAX_ARCHIVE_BYTES:
        raise ValueError("결과 압축 크기가 16 MiB를 넘습니다. 수집 대상을 나누세요")
    return data.getvalue(), manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maven", nargs=2, action="append", default=[], metavar=("GROUP:ARTIFACT", "VERSION"))
    parser.add_argument("--python", nargs=3, action="append", default=[], metavar=("PROJECT", "VERSION", "WHEEL_FILENAME"))
    parser.add_argument("--oracle-rpm", nargs=3, action="append", default=[], metavar=("PACKAGE", "EVR", "RPM_URL"))
    args = parser.parse_args()
    try:
        if not args.output.name.endswith(".tar.gz"):
            raise ValueError("출력 파일명은 .tar.gz로 끝나야 합니다")
        checksum = args.output.with_name(args.output.name + ".sha256")
        if args.output.exists() or checksum.exists():
            raise ValueError("이미 출력 파일 또는 체크섬 파일이 있습니다")
        raw, manifest = collect(args)
        digest = hashlib.sha256(raw).hexdigest()
        with args.output.open("xb") as output:
            output.write(raw)
        with checksum.open("x", encoding="utf-8") as output:
            output.write(f"{digest}  {args.output.name}\n")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(1, f"수집 실패 · {exc}\n")
    print(f"{args.output} · 공식 원본 {sum(len(item['files']) for item in manifest['items'])}개 · SHA-256 {digest}")


if __name__ == "__main__":
    main()
