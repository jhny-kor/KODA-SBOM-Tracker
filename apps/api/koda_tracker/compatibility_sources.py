"""The designated public repositories for compatibility evidence format v1."""
import re
from urllib.parse import urlsplit

MAX_ARCHIVE_MB = 64
MAX_ARCHIVE_BYTES = MAX_ARCHIVE_MB * 1_000_000
MAX_UNPACKED_MIB = 128
MAX_UNPACKED_BYTES = MAX_UNPACKED_MIB * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024
MAX_ITEMS = 20
FILE_LIMITS = {"pom": 512 * 1024, "pypi_release": 1024 * 1024, "wheel": 12 * 1024 * 1024, "rpm": 12 * 1024 * 1024}

AUTHORITIES = {
    "maven": {"id": "maven-central", "ecosystem": "maven", "organization": "Sonatype",
              "name": "Maven Central", "url": "https://central.sonatype.org/pages/about/"},
    "python": {"id": "pypi", "ecosystem": "python", "organization": "Python Software Foundation",
               "name": "Python Package Index (PyPI)", "url": "https://pypi.org/"},
    "elf": {"id": "oracle-linux-yum", "ecosystem": "elf", "organization": "Oracle",
            "name": "Oracle Linux Yum Server", "url": "https://yum.oracle.com/"},
}
REQUIRED_FILES = {"maven": {"pom"}, "python": {"pypi_release", "wheel"}, "elf": {"rpm"}}
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+!~:^-]{0,127}")
_ORACLE_RPM = re.compile(
    r"/repo/OracleLinux/OL(?:8|9|10)/(?:[0-9]{1,2}/)?(?:baseos/(?:base|latest)|appstream)"
    r"/(x86_64|aarch64)/getPackage/([A-Za-z0-9][A-Za-z0-9._+~-]{1,200}\.rpm)"
)


def canonical_python_name(name: str) -> str:
    if not _PART.fullmatch(name):
        raise ValueError("PyPI 패키지 이름이 올바르지 않습니다")
    return re.sub(r"[-_.]+", "-", name).lower()


def maven_pom_url(package: str, version: str) -> str:
    group, separator, artifact = package.partition(":")
    if (not separator or not _PART.fullmatch(group) or not _PART.fullmatch(artifact)
            or not _VERSION.fullmatch(version) or ":" in version or any(not part for part in group.split("."))):
        raise ValueError("Maven groupId:artifactId 또는 버전이 올바르지 않습니다")
    return f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.pom"


def pypi_release_url(package: str, version: str) -> str:
    from urllib.parse import quote

    if not _VERSION.fullmatch(version) or ":" in version:
        raise ValueError("PyPI 버전이 올바르지 않습니다")
    return f"https://pypi.org/pypi/{canonical_python_name(package)}/{quote(version, safe='')}/json"


def _official_path(url: str, host: str) -> str:
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.netloc != host or parts.query or parts.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in url)):
        raise ValueError("지정 공식 저장소 HTTPS 주소만 사용할 수 있습니다")
    return parts.path


def pypi_wheel_filename(url: str) -> str:
    path = _official_path(url, "files.pythonhosted.org")
    match = re.fullmatch(r"/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/([A-Za-z0-9][A-Za-z0-9_.+-]{0,200}\.whl)", path)
    if not match:
        raise ValueError("공식 PyPI wheel 파일 주소가 올바르지 않습니다")
    return match[1]


def oracle_rpm_location(url: str) -> tuple[str, str]:
    match = _ORACLE_RPM.fullmatch(_official_path(url, "yum.oracle.com"))
    if not match:
        raise ValueError("Oracle Linux BaseOS/AppStream의 지정 RPM 주소만 사용할 수 있습니다")
    return match[1], match[2]
