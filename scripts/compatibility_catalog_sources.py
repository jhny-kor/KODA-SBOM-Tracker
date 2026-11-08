"""Discover package/version records from the designated public catalogs."""
from dataclasses import dataclass
import gzip
from html.parser import HTMLParser
import re
import struct
from urllib.parse import quote, urljoin, urlsplit

from defusedxml import ElementTree

from compatibility_collection import (
    canonical_python_name, maven_pom_url, oracle_rpm_location, pypi_release_url, pypi_wheel_filename,
)

MAVEN_INDEX = "https://repo.maven.apache.org/maven2/.index/nexus-maven-repository-index.gz"
PYPI_INDEX = "https://pypi.org/simple/"
PYPI_SIMPLE_JSON = "application/vnd.pypi.simple.v1+json"
ORACLE_YUM = "https://yum.oracle.com/"
SOURCES = {"maven": "maven-central", "pypi": "pypi", "oracle": "oracle-linux"}
MIB = 1024 * 1024
_SHA256 = re.compile(r"[a-f0-9]{64}")


@dataclass(frozen=True)
class Record:
    package: str
    version: str
    artifact: str
    url: str
    origin: str
    metadata: dict
    collectable: bool


def maven_metadata_url(package):
    return maven_pom_url(package, "1").rsplit("/", 2)[0] + "/maven-metadata.xml"


def maven_record(package, version, origin):
    try:
        url = maven_pom_url(package, version)
    except ValueError:
        url = ""
    return Record(package, version, "pom", url, origin, {}, bool(url))


def maven_versions(xml, package):
    root = ElementTree.fromstring(xml)
    root_group = root.findtext("{*}groupId")
    root_artifact = root.findtext("{*}artifactId")
    if f"{root_group}:{root_artifact}" != package:
        raise ValueError("Maven 좌표가 색인과 다릅니다")
    for version in root.findall("{*}versioning/{*}versions/{*}version"):
        if version.text:
            yield version.text


def read_exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("Maven 색인이 잘렸습니다")
    return data


def maven_index_records(path):
    # Apache Maven Indexer ChunkReader wire format. Only the GAV field is read
    # as text; class lists and descriptions can be skipped.
    with gzip.open(path, "rb") as stream:
        if read_exact(stream, 9)[0] != 1:
            raise ValueError("지원되지 않는 Maven 색인 버전입니다")
        while first := stream.read(1):
            count = int.from_bytes(first + read_exact(stream, 3))
            if count > 1024:
                raise ValueError("Maven 색인의 필드 개수가 올바르지 않습니다")
            coordinate = None
            deleted = False
            for _ in range(count):
                _, name_length = struct.unpack(">BH", read_exact(stream, 3))
                field = read_exact(stream, name_length)
                length = int.from_bytes(read_exact(stream, 4))
                if length > 64 * MIB:
                    raise ValueError("Maven 색인 필드가 너무 큽니다")
                if field == b"del":
                    deleted = True
                if field == b"u":
                    # Java modified UTF-8 stores U+0000 as C0 80 and astral
                    # characters as surrogate pairs.
                    value = read_exact(stream, length).replace(b"\xc0\x80", b"\x00")
                    coordinate = value.decode("utf-8", "surrogatepass").encode("utf-16", "surrogatepass").decode("utf-16")
                else:
                    while length:
                        step = min(length, 128 * 1024)
                        read_exact(stream, step)
                        length -= step
            if coordinate and not deleted:
                group, artifact, version, *_ = coordinate.split("|")
                yield maven_record(f"{group}:{artifact}", version, MAVEN_INDEX)


def pypi_name(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", name):
        raise ValueError("PyPI 프로젝트 이름이 올바르지 않습니다")
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_project_url(package):
    return f"https://pypi.org/pypi/{quote(pypi_name(package), safe='')}/json"


def pypi_records(data, package):
    if pypi_name(data["info"]["name"]) != package:
        raise ValueError("PyPI 프로젝트가 목록과 다릅니다")
    origin = pypi_project_url(package)
    for version, files in data["releases"].items():
        if not files:
            yield Record(package, version, "", "", origin, {}, False)
        for row in files:
            kind, name, url = row["packagetype"], row["filename"], row["url"]
            meta = {key: row[key] for key in ("size", "digests", "requires_python", "yanked", "upload_time_iso_8601")
                    if key in row}
            meta["kind"] = kind
            try:
                pypi_release_url(canonical_python_name(package), version)
                supported = kind == "bdist_wheel" and pypi_wheel_filename(url) == name
            except ValueError:
                supported = False
            yield Record(package, version, name, url, origin, meta, supported)


class Links(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.page = page
        self.urls = set()

    def handle_starttag(self, tag, attrs):
        if tag == "a" and (href := dict(attrs).get("href")):
            url = urljoin(self.page, href)
            parts = urlsplit(url)
            if (parts.scheme == "https" and parts.netloc == "yum.oracle.com"
                    and not parts.query and not parts.fragment and ".." not in parts.path.split("/")):
                self.urls.add(url)


def oracle_links(page, raw):
    parser = Links(page)
    parser.feed(raw.decode("utf-8", errors="replace"))
    return parser.urls


def oracle_repo_url(url):
    path = urlsplit(url)
    if (path.scheme != "https" or path.netloc != "yum.oracle.com" or path.query or path.fragment
            or not re.fullmatch(r"/repo/(?:[A-Za-z0-9_+.-]+/)+", path.path)
            or ".." in path.path.split("/") or "." in path.path.split("/")):
        raise ValueError("Oracle Linux Yum의 공식 저장소 주소를 입력하세요")
    return url


def oracle_primary(repo, raw):
    entry = ElementTree.fromstring(raw).find("{*}data[@type='primary']")
    if entry is None:
        raise ValueError("Oracle repomd.xml에 primary 색인이 없습니다")
    path = entry.find("{*}location").get("href")
    if not re.fullmatch(r"repodata/[A-Za-z0-9_-]+\.xml(?:\.gz|\.bz2|\.xz)?", path):
        raise ValueError("Oracle primary 색인 경로가 올바르지 않습니다")
    checksum = entry.find("{*}checksum")
    algorithm, digest = checksum.get("type"), checksum.text
    if algorithm == "sha":
        algorithm = "sha1"
    if algorithm not in {"sha1", "sha256", "sha512", "md5"} or not re.fullmatch("[a-f0-9]+", digest or ""):
        raise ValueError("Oracle primary 색인 체크섬을 확인할 수 없습니다")
    return repo + path, algorithm, digest, int(entry.findtext("{*}size", "0"))


def oracle_records(stream, repo, origin):
    iterator = ElementTree.iterparse(stream, events=("start", "end"))
    _, root = next(iterator)
    for event, entry in iterator:
        if event != "end" or not entry.tag.endswith("}package"):
            continue
        version = entry.find("{*}version").attrib
        epoch = version.get("epoch", "0")
        evr = (f"{epoch}:" if int(epoch) else "") + f"{version['ver']}-{version['rel']}"
        name = entry.findtext("{*}name")
        arch = entry.findtext("{*}arch")
        href = entry.find("{*}location").get("href")
        url = urljoin(repo, href)
        checksum = entry.find("{*}checksum")
        kind = checksum.get("type")
        meta = {"architecture": arch, "size": int(entry.find("{*}size").get("package")),
                "checksum": checksum.text, "checksumType": "sha1" if kind == "sha" else kind,
                "repository": repo}
        try:
            url_arch, filename = oracle_rpm_location(url)
            supported = url.startswith(repo) and url_arch == arch and filename == f"{name}-{evr.split(':', 1)[-1]}.{arch}.rpm"
        except ValueError:
            supported = False
        yield Record(name, evr, url, url, origin, meta, supported)
        root.remove(entry)
