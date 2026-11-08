#!/usr/bin/env python3
"""Collect full public package catalogs and split supported evidence for Tracker."""
import argparse
from collections import OrderedDict
from contextlib import closing
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
import bz2
import fcntl
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import re
import sqlite3
import sys
import tarfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from compatibility_collection import NoRedirect, encode_bundle
from compatibility_catalog_sources import (
    MAVEN_INDEX, MIB, ORACLE_YUM, PYPI_INDEX, PYPI_SIMPLE_JSON, SOURCES,
    maven_index_records, maven_metadata_url, maven_record, maven_versions,
    oracle_links, oracle_primary, oracle_records, oracle_repo_url,
    pypi_name, pypi_project_url, pypi_records,
)
from koda_tracker.compatibility_bundle import parse_compatibility_bundle
from koda_tracker.compatibility_sources import FILE_LIMITS, MAX_ITEMS, MAX_UNPACKED_BYTES, pypi_release_url

_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, SyntaxError)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS units (
    source TEXT NOT NULL, name TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, error TEXT,
    PRIMARY KEY (source, name)
);
CREATE TABLE IF NOT EXISTS source_errors (source TEXT PRIMARY KEY, error TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS receipts (
    url TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL, collected TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL,
    artifact TEXT NOT NULL, url TEXT NOT NULL, origin TEXT NOT NULL, metadata TEXT NOT NULL,
    status TEXT NOT NULL, error TEXT, bundle TEXT,
    UNIQUE (source, package, version, artifact)
);
CREATE INDEX IF NOT EXISTS records_pending ON records(source, status, id);
CREATE INDEX IF NOT EXISTS records_by_source ON records(source, id);
CREATE TABLE IF NOT EXISTS bundles (
    id INTEGER PRIMARY KEY, source TEXT NOT NULL, name TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL
);
"""


def stamp():
    return datetime.now(UTC).isoformat()


def atomic_bytes(path, data):
    temporary = path.with_name(path.name + ".part")
    temporary.write_bytes(data)
    os.replace(temporary, path)


class Downloader:
    def __init__(self, root, db, interval):
        self.root, self.db, self.interval = root, db, interval
        self.opener = build_opener(NoRedirect())
        self.next_request = 0

    def request(self, url, accept):
        for attempt in range(3):
            time.sleep(max(0, self.next_request - time.monotonic()))
            self.next_request = time.monotonic() + self.interval
            try:
                return self.opener.open(Request(url, headers={"User-Agent": "KODA-Compatibility-Catalog/1",
                    "Accept-Encoding": "identity", "Accept": accept}), timeout=60)
            except HTTPError as error:
                if error.code not in (429, 500, 502, 503, 504) or attempt == 2:
                    raise
                header = error.headers.get("Retry-After")
                delay = 2 ** (attempt + 1)
                if header:
                    try:
                        delay = max(delay, int(header) if header.isdecimal() else
                                    (parsedate_to_datetime(header) - datetime.now(UTC)).total_seconds())
                    except (ValueError, TypeError, OverflowError):
                        pass
                error.close()
                self.next_request = time.monotonic() + delay
            except URLError:
                if attempt == 2:
                    raise
                self.next_request = time.monotonic() + 2 ** (attempt + 1)

    def bytes(self, url, limit, accept="*/*"):
        with self.request(url, accept) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise OverflowError(f"원본 크기가 Tracker 한도를 넘습니다 · {url}")
        if not raw:
            raise ValueError(f"원본이 비어 있습니다 · {url}")
        return raw

    def record(self, url, digest, size):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO receipts VALUES (?, ?, ?, ?)", (url, digest, size, stamp()))

    def index(self, url, limit, *, accept="*/*", expected=None):
        path = self.root / hashlib.sha256(url.encode()).hexdigest()
        prior = self.db.execute("SELECT size, sha256 FROM receipts WHERE url=?", (url,)).fetchone()
        if prior and path.exists() and path.stat().st_size == prior["size"]:
            if not expected:
                return path
            if expected[2] in (0, prior["size"]):
                with path.open("rb") as stream:
                    cached_hash = prior["sha256"] if expected[0] == "sha256" else hashlib.file_digest(stream, expected[0]).hexdigest()
                if cached_hash == expected[1]:
                    return path
        sha = hashlib.sha256()
        verify = hashlib.new(expected[0]) if expected else None
        temporary = path.with_suffix(".part")
        total = 0
        with self.request(url, accept) as stream, temporary.open("wb") as output:
            length = stream.headers.get("Content-Length")
            while block := stream.read(MIB):
                total += len(block)
                if total > limit:
                    raise ValueError(f"색인 크기가 허용 범위를 벗어났습니다 · {url}")
                sha.update(block)
                if verify:
                    verify.update(block)
                output.write(block)
                if total // (256 * MIB) != (total - len(block)) // (256 * MIB):
                    print(f"{url} · {total // MIB} MiB 다운로드", flush=True)
        if (not total or length and length.isdecimal() and total != int(length)
                or expected and (verify.hexdigest() != expected[1] or expected[2] not in (0, total))):
            raise ValueError(f"색인의 체크섬 또는 크기가 다릅니다 · {url}")
        os.replace(temporary, path)
        self.record(url, sha.hexdigest(), total)
        return path


def oracle_repositories(net):
    home = net.index(ORACLE_YUM, 4 * MIB).read_bytes()
    pages = sorted(link for link in oracle_links(ORACLE_YUM, home)
                   if re.fullmatch(re.escape(ORACLE_YUM) + r"oracle-linux-(?:[0-9]+|java|nodejs|python|golang|php)\.html", link))
    repositories = set()
    for page in pages:
        for link in oracle_links(page, net.index(page, 8 * MIB).read_bytes()):
            if re.fullmatch(re.escape(ORACLE_YUM) + r"repo/(?:[A-Za-z0-9_.+-]+/)+index(?:_src)?\.html", link):
                repositories.add(oracle_repo_url(link.rsplit("/", 1)[0] + "/"))
    if not repositories:
        raise ValueError("Oracle Linux 저장소 목록을 찾을 수 없습니다")
    return sorted(repositories)


def units_for(source, args, net):
    if source == "maven":
        return sorted(set(args.package)) if args.package else [MAVEN_INDEX]
    if source == "pypi":
        if args.package:
            return sorted({pypi_name(package) for package in args.package})
        with net.index(PYPI_INDEX, 256 * MIB, accept=PYPI_SIMPLE_JSON).open("rb") as stream:
            return [pypi_name(item["name"]) for item in json.load(stream)["projects"]]
    return sorted({oracle_repo_url(url) for url in args.oracle_repo}) if args.oracle_repo else oracle_repositories(net)


def records_for(source, unit, args, net):
    if source == "maven":
        if unit == MAVEN_INDEX:
            path = args.maven_index or net.index(MAVEN_INDEX, 16 * 1024 * MIB)
            if args.maven_index:
                with path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                net.record(MAVEN_INDEX, digest, path.stat().st_size)
            yield from maven_index_records(path)
        else:
            url = maven_metadata_url(unit)
            for version in maven_versions(net.index(url, 8 * MIB).read_bytes(), unit):
                yield maven_record(unit, version, url)
    elif source == "pypi":
        url = pypi_project_url(unit)
        with net.index(url, 128 * MIB, accept="application/json").open("rb") as stream:
            yield from pypi_records(json.load(stream), unit)
    else:
        receipt = unit + "repodata/repomd.xml"
        primary, algorithm, digest, size = oracle_primary(unit, net.index(receipt, 2 * MIB).read_bytes())
        path = net.index(primary, 1024 * MIB, expected=(algorithm, digest, size))
        opener = {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}.get(Path(primary).suffix, open)
        with opener(path, "rb") as stream:
            yield from oracle_records(stream, unit, primary)


def discover(source, args, net, db):
    units = units_for(source, args, net)
    with db:
        db.executemany("INSERT OR IGNORE INTO units(source,name) VALUES (?,?)", ((source, unit) for unit in units))
    for number, unit in enumerate(pending_units(db, source), 1):
        if number % 500 == 0:
            print(f"{SOURCES[source]} · 이번 실행에서 색인 {number:,}개 확인 중", flush=True)
        try:
            buffer = []
            for record in records_for(source, unit, args, net):
                if (args.version and record.version not in args.version
                        or source == "oracle" and args.package and record.package not in args.package):
                    continue
                buffer.append((source, record.package, record.version, record.artifact, record.url, record.origin,
                               json.dumps(record.metadata, ensure_ascii=False), "pending" if record.collectable else "catalog_only"))
                if len(buffer) == 2000:
                    insert_records(db, buffer)
                    buffer.clear()
            insert_records(db, buffer)
            with db:
                db.execute("UPDATE units SET done=1,error=NULL WHERE source=? AND name=?", (source, unit))
        except _ERRORS as error:
            with db:
                db.execute("UPDATE units SET error=? WHERE source=? AND name=?", (str(error)[:400], source, unit))
            if isinstance(error, HTTPError) and error.code in (403, 429):
                break


def pending_units(db, source):
    last = ""
    while page := db.execute(
        "SELECT name FROM units WHERE source=? AND done=0 AND name>? ORDER BY name LIMIT 128", (source, last),
    ).fetchall():
        for (name,) in page:
            yield name
        last = page[-1][0]


def insert_records(db, buffer):
    with db:
        db.executemany("INSERT OR IGNORE INTO records(source,package,version,artifact,url,origin,metadata,status) "
                       "VALUES (?,?,?,?,?,?,?,?)", buffer)


def check_bytes(raw, size, algorithm, digest):
    if len(raw) != size or hashlib.new(algorithm, raw).hexdigest() != digest:
        raise ValueError("공식 저장소의 원본 크기 또는 체크섬과 다릅니다")


def evidence(row, net, releases):
    package, version, url = row["package"], row["version"], row["url"]
    item = {"ecosystem": {"maven": "maven", "pypi": "python", "oracle": "elf"}[row["source"]],
            "package": package, "version": version}
    meta = json.loads(row["metadata"])
    if row["source"] == "maven":
        return item, [("pom", url, net.bytes(url, FILE_LIMITS["pom"]))]
    if row["source"] == "oracle":
        if meta["size"] > FILE_LIMITS["rpm"]:
            raise OverflowError("RPM이 Tracker 원본 크기 한도를 넘습니다")
        raw = net.bytes(url, FILE_LIMITS["rpm"])
        check_bytes(raw, meta["size"], meta["checksumType"], meta["checksum"])
        item["architecture"] = meta["architecture"]
        return item, [("rpm", url, raw)]

    if meta["size"] > FILE_LIMITS["wheel"]:
        raise OverflowError("wheel이 Tracker 원본 크기 한도를 넘습니다")
    release_url = pypi_release_url(package, version)
    if release_url not in releases:
        releases[release_url] = net.bytes(release_url, FILE_LIMITS["pypi_release"], "application/json")
        if len(releases) > 4:
            releases.popitem(last=False)
    raw = net.bytes(url, FILE_LIMITS["wheel"])
    check_bytes(raw, meta["size"], "sha256", meta["digests"]["sha256"])
    return item, [("pypi_release", release_url, releases[release_url]), ("wheel", url, raw)]


def archive_data(batch):
    items, originals = [], {}
    suffixes = {"pom": "pom", "rpm": "rpm", "wheel": "whl", "pypi_release": "json"}
    for index, (_, item, files) in enumerate(batch):
        descriptors = []
        for kind, url, raw in files:
            path = f"files/{index:02d}-{kind}.{suffixes[kind]}"
            originals[path] = raw
            descriptors.append({"kind": kind, "url": url, "path": path, "size": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest()})
        items.append({**item, "files": descriptors})
    raw, _ = encode_bundle(items, originals)
    parse_compatibility_bundle(raw)
    return raw


def publish_last(db, output):
    staged = output / ".tracker-bundle.pending"
    row = db.execute("SELECT source,name,sha256 FROM bundles ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        dest = output / SOURCES[row["source"]] / row["name"]
        if not dest.exists():
            if not staged.exists() or hashlib.sha256(staged.read_bytes()).hexdigest() != row["sha256"]:
                raise OSError(f"저장 대기 중인 반입 파일을 찾을 수 없습니다 · {dest}")
            os.replace(staged, dest)
        checksum = dest.with_name(dest.name + ".sha256")
        if not checksum.exists():
            atomic_bytes(checksum, f"{row['sha256']}  {dest.name}\n".encode())


def store_batch(batch, source, output, db):
    try:
        raw = archive_data(batch)
    except ValueError as error:
        if len(batch) == 1:
            mark(db, batch[0][0], "catalog_only", f"Tracker v1 형식 · {error}")
            return
        middle = len(batch) // 2
        store_batch(batch[:middle], source, output, db)
        store_batch(batch[middle:], source, output, db)
        return
    digest = hashlib.sha256(raw).hexdigest()
    sequence = db.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM bundles").fetchone()[0]
    name = f"tracker-{SOURCES[source]}-{sequence:08d}.tar.gz"
    atomic_bytes(output / ".tracker-bundle.pending", raw)
    with db:
        db.execute("INSERT INTO bundles(source,name,sha256) VALUES (?,?,?)", (source, name, digest))
        db.executemany("UPDATE records SET status='packed',error=NULL,bundle=? WHERE id=?",
                       ((name, row_id) for row_id, _, _ in batch))
    publish_last(db, output)


def mark(db, row_id, status, message):
    with db:
        db.execute("UPDATE records SET status=?,error=? WHERE id=?", (status, str(message)[:400], row_id))


def collect(source, limit, output, db, net):
    batch, identities, size = [], set(), 0
    releases = OrderedDict()
    for row in pending_records(db, source, limit):
        try:
            item, files = evidence(row, net, releases)
        except OverflowError as error:
            mark(db, row["id"], "catalog_only", error)
            continue
        except _ERRORS as error:
            if isinstance(error, HTTPError) and error.code in (404, 410):
                mark(db, row["id"], "catalog_only", "공식 목록에 기록됐으나 원본에 접근할 수 없습니다")
            else:
                mark(db, row["id"], "error", error)
            if isinstance(error, HTTPError) and error.code in (403, 429):
                break
            continue
        key = (item["package"], item["version"], item.get("architecture"))
        count = sum(len(raw) for _, _, raw in files)
        if batch and (len(batch) == MAX_ITEMS or key in identities or size + count > MAX_UNPACKED_BYTES - MIB):
            store_batch(batch, source, output, db)
            batch, identities, size = [], set(), 0
        batch.append((row["id"], item, files))
        identities.add(key)
        size += count
    if batch:
        store_batch(batch, source, output, db)


def pending_records(db, source, limit):
    last = tried = 0
    while limit is None or tried < limit:
        count = 128 if limit is None else min(128, limit - tried)
        page = db.execute("SELECT * FROM records INDEXED BY records_by_source WHERE source=? AND id>? "
                          "AND status IN ('pending','error') ORDER BY id LIMIT ?", (source, last, count)).fetchall()
        if not page:
            return
        for row in page:
            yield row
        last = page[-1]["id"]
        tried += len(page)


def catalog(source, output, db, *, include_evidence=False):
    row = db.execute("SELECT error FROM source_errors WHERE source=?", (source,)).fetchone()
    discovery_error = row["error"] if row else None
    folder = output / SOURCES[source]
    counts = dict(db.execute("SELECT status,COUNT(*) FROM records WHERE source=? GROUP BY status", (source,)))
    unresolved = db.execute("SELECT COUNT(*) FROM units WHERE source=? AND done=0", (source,)).fetchone()[0]
    incomplete = bool(discovery_error or unresolved or counts.get("error") or include_evidence and counts.get("pending"))
    manifest = {"source": SOURCES[source], "createdAt": stamp(), "counts": counts, "unresolvedIndexes": unresolved,
                "discoveryError": discovery_error, "pendingEvidence": counts.get("pending", 0)}
    scope = output / "scope.json"
    if scope.exists():
        recorded_scope = json.loads(scope.read_text())
        recorded_scope["localMavenIndex"] = bool(recorded_scope.pop("maven_index"))
        manifest["scope"] = recorded_scope
    files = {
        "packages.jsonl.gz": ("SELECT package,version,artifact,url,origin,metadata,status,error,bundle "
                             "FROM records WHERE source=? ORDER BY id", (source,)),
        "indexes.jsonl.gz": ("SELECT name,done,error FROM units WHERE source=? ORDER BY name", (source,)),
        "source-receipts.jsonl.gz": ("SELECT * FROM receipts WHERE url LIKE ? ORDER BY url",
                                    ({"maven": "https://repo.maven.apache.org/%", "pypi": "https://pypi.org/%",
                                      "oracle": "https://yum.oracle.com/%"}[source],)),
    }
    for name, (query, params) in files.items():
        with gzip.open(folder / ("." + name), "wt", encoding="utf-8") as stream:
            for row in db.execute(query, params):
                entry = dict(row)
                if "metadata" in entry:
                    entry["metadata"] = json.loads(entry["metadata"])
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
    path = folder / f"catalog-{SOURCES[source]}.tar.gz"
    atomic_bytes(folder / ".catalog-summary.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
    with tarfile.open(path.with_suffix(".gz.part"), "w:gz") as archive:
        archive.add(folder / ".catalog-summary.json", arcname="summary.json")
        for name in files:
            archive.add(folder / ("." + name), arcname=name)
    os.replace(path.with_suffix(".gz.part"), path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    atomic_bytes(path.with_name(path.name + ".sha256"), f"{digest}  {path.name}\n".encode())
    for name in files:
        (folder / ("." + name)).unlink()
    (folder / ".catalog-summary.json").unlink()
    print(f"{path} · {counts} · 미완료 색인 {unresolved}", flush=True)
    return incomplete


def main():
    parser = argparse.ArgumentParser(
        description="Maven Central, PyPI, Oracle Linux Yum의 공개 목록과 Tracker 호환성 근거를 수집합니다.",
        epilog="catalog-*.tar.gz는 전체 목록과 수집 상태를 보관합니다. Tracker에는 tracker-*.tar.gz만 반입합니다. "
               "같은 작업 경로로 다시 실행하면 이어받습니다. 전체 범위는 공개 색인의 시점을 기준으로 합니다.",
    )
    parser.add_argument("--source", choices=[*SOURCES, "all"], default="all")
    parser.add_argument("--output-dir", type=Path, required=True, help="계속 수집하려면 같은 작업 경로를 사용합니다")
    parser.add_argument("--catalog-only", action="store_true", help="공식 색인만 수집하고 원본 증거 다운로드를 건너뜁니다")
    parser.add_argument("--export-only", action="store_true", help="현재까지 확보한 목록을 네트워크 요청 없이 다시 압축합니다")
    parser.add_argument("--package", action="append", default=[], help="소규모 검증용 패키지 필터 · Maven group:artifact")
    parser.add_argument("--version", action="append", default=[], help="소규모 검증용 버전 필터")
    parser.add_argument("--maven-index", type=Path, help="미리 내려받은 공식 Maven Central 전체 색인")
    parser.add_argument("--oracle-repo", action="append", default=[], help="Oracle Yum 저장소 URL · 지정하지 않으면 공개 목록 탐색")
    parser.add_argument("--limit", type=int, help="기관별 한 번의 실행에서 시도할 원본 항목 수")
    parser.add_argument("--request-interval", type=float, default=0.5, help="공식 요청 사이의 최소 간격(초)")
    args = parser.parse_args()
    if args.limit is not None and args.limit <= 0 or not 0.1 <= args.request_interval <= 60:
        parser.error("limit은 양수, request-interval은 0.1~60초입니다")
    if args.package and args.source == "all" or args.maven_index and args.package:
        parser.error("패키지 필터는 기관을 하나 지정하고 전체 Maven 색인 옵션과 따로 사용하세요")
    output = args.output_dir
    output.mkdir(parents=True, exist_ok=True)
    if args.export_only and not (output / "catalog.sqlite3").is_file():
        parser.error("기존 수집 작업 디렉터리를 지정하세요")
    scope = {name: sorted(set(getattr(args, name))) for name in ("package", "version", "oracle_repo")}
    scope["maven_index"] = str(args.maven_index.resolve()) if args.maven_index else None
    state = output / "scope.json"
    sources = list(SOURCES) if args.source == "all" else [args.source]
    try:
        with (output / ".collector.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not args.export_only:
                if state.exists() and json.loads(state.read_text()) != scope:
                    parser.error("이 디렉터리에는 다른 범위의 작업이 있습니다. 새 경로를 사용하세요")
                if not state.exists():
                    atomic_bytes(state, json.dumps(scope).encode())
            with closing(sqlite3.connect(output / "catalog.sqlite3")) as db:
                db.row_factory = sqlite3.Row
                db.executescript(_SCHEMA)
                cache = output / "indexes"
                cache.mkdir(exist_ok=True)
                net = Downloader(cache, db, args.request_interval)
                publish_last(db, output)
                partial = False
                for source in sources:
                    print(f"{SOURCES[source]} · {'목록 압축' if args.export_only else '공식 목록 확인'}", flush=True)
                    (output / SOURCES[source]).mkdir(exist_ok=True)
                    failure = None
                    if not args.export_only:
                        try:
                            discover(source, args, net, db)
                        except _ERRORS as error:
                            failure = str(error)[:400]
                            print(f"{SOURCES[source]} · 공식 목록 확인 실패 · {failure}", file=sys.stderr)
                        with db:
                            if failure:
                                db.execute("INSERT OR REPLACE INTO source_errors VALUES (?, ?)", (source, failure))
                            else:
                                db.execute("DELETE FROM source_errors WHERE source=?", (source,))
                        if not failure and not args.catalog_only:
                            collect(source, args.limit, output, db, net)
                    partial |= catalog(source, output, db, include_evidence=not (args.catalog_only or args.export_only))
                return 3 if partial else 0
    except KeyboardInterrupt:
        print("수집을 중단했습니다. 같은 경로로 다시 실행하면 완료 항목부터 이어받습니다.", file=sys.stderr)
        return 130
    except (*_ERRORS, sqlite3.Error) as error:
        print(f"수집 실패 · {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
