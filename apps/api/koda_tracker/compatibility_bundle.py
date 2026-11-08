"""Validate and project an offline compatibility bundle without contacting its sources."""
import gzip
import hashlib
from io import BytesIO
import json
import re
import tarfile
from email import policy
from email.parser import BytesParser
from typing import Annotated, Literal
from zipfile import BadZipFile, ZipFile
import zlib

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError
from xml.etree.ElementTree import ParseError

from .compatibility_rpm import parse_rpm
from .compatibility_sources import (
    AUTHORITIES, FILE_LIMITS, MAX_ARCHIVE_BYTES, MAX_ITEMS, MAX_MANIFEST_BYTES, MAX_UNPACKED_BYTES,
    REQUIRED_FILES, canonical_python_name, maven_pom_url, oracle_rpm_location, pypi_release_url, pypi_wheel_filename,
)

Ecosystem = Literal["maven", "python", "elf"]
FileKind = Literal["pom", "pypi_release", "wheel", "rpm"]
PathText = Annotated[str, Field(pattern=r"^files/[A-Za-z0-9][A-Za-z0-9._-]{0,169}$")]
Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^\S+$")]
_ARCHIVE_PATH = re.compile(r"files/[A-Za-z0-9][A-Za-z0-9._-]{0,169}")
_MAX_FIELDS = 100
_MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


class EvidenceFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: FileKind
    path: PathText
    url: Annotated[str, Field(min_length=1, max_length=600)]
    sha256: Sha256
    size: int = Field(ge=1, le=MAX_ARCHIVE_BYTES)


class EvidenceItem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ecosystem: Ecosystem
    package: ShortText
    version: ShortText
    architecture: Literal["x86_64", "aarch64"] | None = None
    files: list[EvidenceFile] = Field(min_length=1, max_length=2)


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schemaVersion: Literal[1]
    profile: Literal["official-v1"]
    collectedAt: AwareDatetime
    items: list[EvidenceItem] = Field(min_length=1, max_length=MAX_ITEMS)


def _tar_files(raw: bytes) -> dict[str, bytes]:
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError("호환성 자료 압축은 최대 16 MiB입니다")
    with gzip.GzipFile(fileobj=BytesIO(raw)) as stream:
        content = stream.read(MAX_UNPACKED_BYTES + 1)
    if len(content) > MAX_UNPACKED_BYTES:
        raise ValueError("압축 해제 크기가 32 MiB를 넘습니다")
    files = {}
    with tarfile.open(fileobj=BytesIO(content), mode="r:", ignore_zeros=True) as archive:
        for entry in archive:
            if (entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or entry.sparse is not None or entry.pax_headers
                    or entry.name in files or (entry.name != "manifest.json" and not _ARCHIVE_PATH.fullmatch(entry.name))):
                raise ValueError("허용되지 않는 압축 경로, 파일 종류 또는 중복 항목이 있습니다")
            limit = MAX_MANIFEST_BYTES if entry.name == "manifest.json" else max(FILE_LIMITS.values())
            if not 1 <= entry.size <= limit or len(files) >= 1 + MAX_ITEMS * 2:
                raise ValueError("압축 안의 파일 크기 또는 수가 허용 범위를 벗어났습니다")
            stream = archive.extractfile(entry)
            files[entry.name] = stream.read()
    return files


def _maven(item: EvidenceItem, pom: bytes) -> dict:
    root = ElementTree.fromstring(pom)
    if root.tag not in ("project", f"{_MAVEN_NS}project"):
        raise ValueError("Maven POM 프로젝트 형식을 확인할 수 없습니다")
    ns = _MAVEN_NS if root.tag.startswith("{") else ""

    def text(parent, key):
        value = parent.findtext(ns + key, default="").strip() if parent is not None else ""
        return value[:512] or None

    parent = root.find(ns + "parent")
    group = text(root, "groupId") or text(parent, "groupId")
    version = text(root, "version") or text(parent, "version")
    if f"{group}:{text(root, 'artifactId')}" != item.package or version != item.version:
        raise ValueError("Maven POM의 패키지 또는 버전이 선언과 다릅니다")
    properties = root.find(ns + "properties")
    compiler = {key: value for key in ("java.version", "maven.compiler.release", "maven.compiler.source", "maven.compiler.target")
                if (value := text(properties, key))}
    dependencies = root.findall(f"{ns}dependencies/{ns}dependency")
    managed = root.findall(f"{ns}dependencyManagement/{ns}dependencies/{ns}dependency")

    def project(entries):
        return [{"package": f"{text(node, 'groupId')}:{text(node, 'artifactId')}",
                 "version": text(node, "version"), "scope": text(node, "scope"),
                 "type": text(node, "type")} for node in entries[:_MAX_FIELDS]]

    return {"compiler": compiler, "dependencies": project(dependencies), "dependencyCount": len(dependencies),
            "managedDependencies": project(managed), "managedDependencyCount": len(managed),
            "parent": {"group": text(parent, "groupId"), "artifact": text(parent, "artifactId"),
                       "version": text(parent, "version")} if parent is not None else None,
            "publisher": text(root.find(ns + "organization"), "name"),
            "hasProfiles": root.find(ns + "profiles") is not None}


def _wheel_metadata(wheel: bytes, filename: str, item: EvidenceItem) -> dict:
    with ZipFile(BytesIO(wheel)) as archive:
        entries = [entry for entry in archive.infolist()
                   if re.fullmatch(r"[A-Za-z0-9_.+-]+\.dist-info/(?:METADATA|WHEEL)", entry.filename)]
        metadata = [entry for entry in entries if entry.filename.endswith("/METADATA")]
        tags_file = [entry for entry in entries if entry.filename.endswith("/WHEEL")]
        if (len(metadata) != 1 or len(tags_file) != 1 or metadata[0].filename.rsplit("/", 1)[0] != tags_file[0].filename.rsplit("/", 1)[0]
                or metadata[0].file_size > 1024 * 1024 or tags_file[0].file_size > 64 * 1024):
            raise ValueError("wheel의 메타데이터 파일이 없거나 크기가 올바르지 않습니다")
        metadata_headers = BytesParser(policy=policy.default).parsebytes(archive.read(metadata[0]), headersonly=True)
        wheel_headers = BytesParser(policy=policy.default).parsebytes(archive.read(tags_file[0]), headersonly=True)
    names = metadata_headers.get_all("Name", [])
    versions = metadata_headers.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1 or canonical_python_name(str(names[0])) != item.package or str(versions[0]) != item.version:
        raise ValueError("wheel의 패키지 또는 버전이 선언과 다릅니다")
    python = metadata_headers.get_all("Requires-Python", [])
    if len(python) > 1:
        raise ValueError("wheel의 Requires-Python 선언이 중복됩니다")
    dependencies = metadata_headers.get_all("Requires-Dist", [])
    return {"wheel": filename, "requiresPython": str(python[0])[:512] if python else None,
            "requiresDist": [str(value)[:1024] for value in dependencies[:_MAX_FIELDS]],
            "requiresDistCount": len(dependencies), "tags": [str(value)[:128] for value in wheel_headers.get_all("Tag", [])[:_MAX_FIELDS]]}


def _python(item, release_raw, wheel, wheel_descriptor):
    release = json.loads(release_raw)
    info = release["info"]
    if canonical_python_name(info["name"]) != item.package or info["version"] != item.version:
        raise ValueError("PyPI 응답의 패키지 또는 버전이 선언과 다릅니다")
    filename = pypi_wheel_filename(wheel_descriptor.url)
    matches = [entry for entry in release["urls"] if entry.get("url") == wheel_descriptor.url and entry.get("filename") == filename]
    if (len(matches) != 1 or matches[0].get("packagetype") != "bdist_wheel"
            or matches[0]["digests"]["sha256"] != wheel_descriptor.sha256 or matches[0]["size"] != len(wheel)):
        raise ValueError("wheel의 URL·크기·SHA-256이 PyPI 배포 정보와 일치하지 않습니다")
    return {**_wheel_metadata(wheel, filename, item), "yanked": matches[0].get("yanked") is True}


def _item_projection(item: EvidenceItem, files: dict[str, bytes]) -> dict:
    roles = {row.kind: row for row in item.files}
    if len(roles) != len(item.files) or roles.keys() != REQUIRED_FILES[item.ecosystem]:
        raise ValueError("자료 종류별 원본 파일 구성이 맞지 않습니다")
    for row in item.files:
        data = files[row.path]
        if row.size != len(data) or len(data) > FILE_LIMITS[row.kind] or hashlib.sha256(data).hexdigest() != row.sha256:
            raise ValueError("원본 파일의 크기 또는 SHA-256이 일치하지 않습니다")
    if item.ecosystem != "elf" and item.architecture is not None:
        raise ValueError("RPM에서만 아키텍처를 별도로 지정합니다")
    if item.ecosystem == "maven":
        pom = roles["pom"]
        if pom.url != maven_pom_url(item.package, item.version):
            raise ValueError("Maven Central의 지정 좌표 URL만 사용할 수 있습니다")
        evidence = _maven(item, files[pom.path])
    elif item.ecosystem == "python":
        release, wheel = roles["pypi_release"], roles["wheel"]
        if release.url != pypi_release_url(item.package, item.version) or canonical_python_name(item.package) != item.package:
            raise ValueError("공식 PyPI 릴리스 URL과 정규 패키지 이름이 필요합니다")
        evidence = _python(item, files[release.path], files[wheel.path], wheel)
    else:
        rpm = roles["rpm"]
        architecture, filename = oracle_rpm_location(rpm.url)
        if architecture != item.architecture or filename != f"{item.package}-{item.version.split(':', 1)[-1]}.{architecture}.rpm":
            raise ValueError("Oracle Linux RPM의 파일명·아키텍처가 선언과 다릅니다")
        evidence = parse_rpm(files[rpm.path], package=item.package, version=item.version, architecture=architecture)
    return {**item.model_dump(), "authority": AUTHORITIES[item.ecosystem], "evidence": evidence}


def parse_compatibility_bundle(raw: bytes) -> dict:
    try:
        files = _tar_files(raw)
        manifest = Manifest.model_validate_json(files.pop("manifest.json"))
        paths = [row.path for item in manifest.items for row in item.files]
        if len(paths) != len(set(paths)) or set(paths) != files.keys():
            raise ValueError("목록의 원본 파일 경로가 압축 내용과 일치하지 않습니다")
        identities = [(item.ecosystem, item.package, item.version, item.architecture) for item in manifest.items]
        if len(identities) != len(set(identities)):
            raise ValueError("같은 패키지·버전의 자료가 중복됩니다")
        return {"profile": manifest.profile, "collectedAt": manifest.collectedAt.isoformat(),
                "items": [_item_projection(item, files) for item in manifest.items]}
    except ValidationError as exc:
        field = ".".join(str(part) for part in exc.errors()[0]["loc"])
        raise ValueError(f"자료 목록 형식을 확인하세요 · {field}") from exc
    except (OSError, EOFError, TypeError, KeyError, AttributeError, RuntimeError, NotImplementedError, tarfile.TarError, BadZipFile,
            zlib.error, ParseError, DefusedXmlException, json.JSONDecodeError) as exc:
        raise ValueError("압축 또는 공식 원본 자료 형식을 확인할 수 없습니다") from exc
