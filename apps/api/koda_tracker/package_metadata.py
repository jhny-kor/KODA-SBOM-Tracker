"""Bounded public-registry collector. Analysis only reads this optional cache.

No registry-supplied URL, artifact, script, or redirect is executed. Publication
dates come from release records, never from a parent metadata modification date.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

import httpx
from defusedxml import ElementTree
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .network_policy import offline_mode
from .db import SessionLocal
from .models import RunComponent
from .package_metadata_models import PackageMetadataCache, PackageMetadataCursor
from .version_ordering import MavenVersion, maven_distance, maven_is_stable, numeric_version_distance

SUPPORTED_ECOSYSTEMS = ("npm", "pypi", "maven", "nuget", "golang", "cargo")
ALLOWED_HOSTS = frozenset({"registry.npmjs.org", "pypi.org", "repo.maven.apache.org", "search.maven.org", "central.sonatype.com", "api.nuget.org", "proxy.golang.org", "crates.io"})
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_QUEUE = 10000
BACKFILL_BATCH = 100
MAX_CACHE_IMPORT = 1000
MAX_NUGET_PAGES = 4096
MAX_NUGET_RECORDS = 100000
_SEMVER = re.compile(r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[-0-9A-Za-z.]+)?$")
_PYPI_FINAL = re.compile(r"^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(?:post|rev|r)[-_.]?(\d*)|-(\d+))?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$", re.I)


def utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value and value.tzinfo is None else value


def iso(value: datetime | None) -> str | None:
    value = utc(value)
    return value.isoformat() if value else None


def parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(UTC) if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def setting(name: str, default: Any) -> Any:
    if name == "enabled" and offline_mode():
        return False
    return getattr(get_settings(), f"package_metadata_{name}", default)


@dataclass(frozen=True)
class PackageTarget:
    ecosystem: str
    namespace: str
    name: str
    version: str
    package_key: str
    purl: str

    @property
    def id(self) -> str:
        return hashlib.sha256(f"{self.package_key}\0{self.version}".encode()).hexdigest()


def parse_purl(purl: str, version: str = "") -> PackageTarget:
    if not isinstance(purl, str) or len(purl) > 2048 or not purl.startswith("pkg:"):
        raise ValueError("버전이 있는 package URL(PURL)이 필요합니다")
    if any(ord(character) < 32 for character in purl) or "\\" in purl:
        raise ValueError("PURL에 허용되지 않는 문자가 있습니다")
    path = purl[4:].split("#", 1)[0]
    path, _, query = path.partition("?")
    qualifiers = dict(parse_qsl(query, keep_blank_values=True))
    if any(key.lower() in {"repository_url", "download_url", "vcs_url"} for key in qualifiers):
        raise ValueError("사용자 정의 저장소 PURL은 공개 registry에서 조회하지 않습니다")
    package_path, marker, package_version = path.rpartition("@")
    if not marker:
        package_path, package_version = path, version
    ecosystem, slash, rest = package_path.partition("/")
    parts = [unquote(part) for part in rest.split("/")] if slash else []
    if not parts or any(not part or part in {".", ".."} or any(character in part for character in ("?", "#", "\\")) for part in parts):
        raise ValueError("PURL 패키지 경로가 올바르지 않습니다")
    package_version = unquote(package_version or version)
    if not package_version or len(package_version) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_~-]*", package_version):
        raise ValueError("정확한 패키지 버전이 필요합니다")
    ecosystem = ecosystem.lower()
    name, namespace = parts[-1], "/".join(parts[:-1])
    if ecosystem == "pypi":
        if namespace or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
            raise ValueError("PyPI 패키지 이름이 올바르지 않습니다")
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif ecosystem == "npm":
        if namespace and not re.fullmatch(r"@[A-Za-z0-9._-]+", namespace):
            raise ValueError("npm scope가 올바르지 않습니다")
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            raise ValueError("npm 패키지 이름이 올바르지 않습니다")
        name, namespace = name.lower(), namespace.lower()
    elif ecosystem == "maven":
        if not namespace or "/" in namespace or not re.fullmatch(r"[A-Za-z0-9_.-]+", namespace) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("Maven group/artifact가 올바르지 않습니다")
    elif ecosystem in {"nuget", "cargo"}:
        if namespace or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("패키지 이름이 올바르지 않습니다")
        if ecosystem == "nuget":
            name = name.lower()
    elif ecosystem == "golang":
        if not namespace or not re.fullmatch(r"[A-Za-z0-9._~/-]+", f"{namespace}/{name}"):
            raise ValueError("Go module 경로가 올바르지 않습니다")
    key = f"{ecosystem}/{namespace + '/' if namespace else ''}{name}"
    if len(key) > 1024:
        raise ValueError("패키지 경로가 너무 깁니다")
    return PackageTarget(ecosystem, namespace, name, package_version, key, purl)


class RegistryError(Exception):
    def __init__(self, message: str, *, retryable: bool = True, retry_after: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


def allowed_registry_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS and parsed.port in {None, 443} and not parsed.username and not parsed.password
    except (ValueError, TypeError):
        return False


class RegistryClient:
    def __init__(self, transport: httpx.BaseTransport | None = None):
        self.client = httpx.Client(timeout=float(setting("request_timeout_seconds", 10)), follow_redirects=False,
                                   trust_env=False, transport=transport, headers={"User-Agent": "KODA-SBOM-Tracker/package-metadata", "Accept": "application/json"})
        self.urls: list[str] = []
        self.last_request_at = 0.0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.client.close()

    def get(self, url: str, *, as_json: bool = True) -> Any:
        if offline_mode():
            raise RegistryError("폐쇄망 모드에서 공개 저장소 호출이 차단되었습니다", retryable=False)
        if not allowed_registry_url(url):
            raise RegistryError("허용된 HTTPS registry가 아닙니다", retryable=False)
        self.urls.append(url)
        wait = float(setting("min_interval_seconds", 1)) - (time.monotonic() - self.last_request_at)
        if wait > 0:
            time.sleep(min(wait, 60))
        self.last_request_at = time.monotonic()
        try:
            with self.client.stream("GET", url) as response:
                if response.status_code == 429:
                    raw = response.headers.get("retry-after", "")
                    raise RegistryError("registry 요청 제한(HTTP 429)", retry_after=min(int(raw), 3600) if raw.isdigit() else 60)
                if response.status_code != 200:
                    raise RegistryError(f"registry HTTP {response.status_code}", retryable=response.status_code >= 500)
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise RegistryError("registry 응답 크기 한도 초과", retryable=False)
            if as_json:
                return json.loads(body)
            return bytes(body)
        except RegistryError:
            raise
        except (httpx.HTTPError, ValueError, RecursionError) as exc:
            raise RegistryError(f"registry 응답 오류: {type(exc).__name__}") from exc

    def last_modified(self, url: str) -> str | None:
        """Observe an immutable version artifact's repository timestamp only."""
        if offline_mode():
            raise RegistryError("폐쇄망 모드에서 공개 저장소 호출이 차단되었습니다", retryable=False)
        if not allowed_registry_url(url):
            raise RegistryError("허용된 HTTPS registry가 아닙니다", retryable=False)
        self.urls.append(url)
        wait = float(setting("min_interval_seconds", 1)) - (time.monotonic() - self.last_request_at)
        if wait > 0:
            time.sleep(min(wait, 60))
        self.last_request_at = time.monotonic()
        try:
            response = self.client.head(url)
            if response.status_code != 200:
                raise RegistryError(f"registry artifact HTTP {response.status_code}", retryable=response.status_code >= 500)
            raw = response.headers.get("last-modified")
            if not raw:
                return None
            parsed = parsedate_to_datetime(raw)
            return iso(parsed.astimezone(UTC)) if parsed.tzinfo else None
        except RegistryError:
            raise
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise RegistryError(f"registry artifact timestamp 오류: {type(exc).__name__}") from exc


def _semver(version: str) -> tuple[int, int, int] | None:
    match = _SEMVER.fullmatch(version)
    return tuple(int(value) for value in match.groups()) if match else None


def _pypi_final(version: str) -> tuple | None:
    match = _PYPI_FINAL.fullmatch(version)
    if not match:
        return None
    epoch, release, post, implicit_post = match.groups()
    numbers = [int(number) for number in release.split(".")]
    while len(numbers) > 1 and numbers[-1] == 0:
        numbers.pop()
    has_post = bool(re.search(r"(?:post|rev|r|-)\d*", version.split("+", 1)[0], re.I))
    return int(epoch or 0), tuple(numbers), int(post or implicit_post or 0) if has_post else -1


def _distance(versions: list[str], current: str, latest: str, parser=_semver) -> int | None:
    current_key, latest_key = parser(current), parser(latest)
    if current_key is None or latest_key is None:
        return None
    return len({parsed for value in versions if (parsed := parser(value)) is not None and current_key < parsed <= latest_key})


def _publication(files: Any) -> str | None:
    if not isinstance(files, list):
        return None
    dates = [parsed for entry in files if isinstance(entry, dict) and (parsed := parse_date(entry.get("upload_time_iso_8601")))]
    return iso(min(dates)) if dates else None


def _npm(target: PackageTarget, client: RegistryClient) -> dict:
    name = f"{target.namespace}/{target.name}" if target.namespace else target.name
    payload = client.get("https://registry.npmjs.org/" + quote(name, safe=""))
    versions, times = payload.get("versions", {}), payload.get("time", {})
    latest = payload.get("dist-tags", {}).get("latest")
    if not isinstance(latest, str) or latest not in versions:
        raise RegistryError("npm latest dist-tag가 없습니다", retryable=False)
    stable = [version for version in versions if _semver(version) is not None]
    # A publisher may tag a prerelease as latest. Preserve the tag but use a
    # verified stable version for ordinary ageing/upgrade policy conditions.
    registry_latest = latest
    if _semver(latest) is None:
        latest = max(stable, key=_semver, default=None)
        if latest is None:
            raise RegistryError("npm에 정식 SemVer 릴리스가 없습니다", retryable=False)
    return {"latestVersion": latest, "latestSelection": "npm_dist_tag_latest" if latest == registry_latest else "npm_highest_stable_semver",
            "latestIsPrerelease": False, "registryLatestVersion": registry_latest, "registryLatestIsPrerelease": _semver(registry_latest) is None,
            "currentVersionPublishedAt": iso(parse_date(times.get(target.version))), "latestPublishedAt": iso(parse_date(times.get(latest))),
            "versionDistance": _distance(stable, target.version, latest), "versionDistanceBasis": "stable_semver_release_count",
            "currentVersionMissing": target.version not in versions, "currentVersionYanked": None, "publicationBasis": "registry_version_time"}


def _pypi(target: PackageTarget, client: RegistryClient) -> dict:
    payload = client.get(f"https://pypi.org/pypi/{quote(target.name, safe='')}/json")
    releases = payload.get("releases")
    if not isinstance(releases, dict):
        raise RegistryError("PyPI release 목록이 없습니다", retryable=False)
    eligible = {version: files for version, files in releases.items() if _pypi_final(version) is not None and isinstance(files, list) and files and any(not file.get("yanked", False) for file in files if isinstance(file, dict))}
    latest = payload.get("info", {}).get("version")
    if latest not in eligible:
        latest = max(eligible, key=_pypi_final, default=None)
    if latest is None:
        raise RegistryError("PyPI에 철회되지 않은 정식 릴리스가 없습니다", retryable=False)
    current_files = releases.get(target.version, [])
    return {"latestVersion": latest, "latestSelection": "pypi_latest_non_yanked_final_post", "latestIsPrerelease": False,
            "currentVersionPublishedAt": _publication(current_files), "latestPublishedAt": _publication(eligible[latest]),
            "versionDistance": _distance(list(eligible), target.version, latest, _pypi_final), "versionDistanceBasis": "pep440_final_post_release_count",
            "currentVersionMissing": not bool(current_files), "currentVersionYanked": all(file.get("yanked", False) for file in current_files if isinstance(file, dict)) if current_files else None, "publicationBasis": "earliest_distribution_upload"}


def _maven_date(target: PackageTarget, version: str, client: RegistryClient) -> tuple[str | None, str | None]:
    query = f'g:"{target.namespace}" AND a:"{target.name}" AND v:"{version}"'
    # The official Central search moved to central.sonatype.com. Retain the
    # published classic search endpoint as a bounded fallback for older data.
    for host in ("central.sonatype.com", "search.maven.org"):
        try:
            payload = client.get(f"https://{host}/solrsearch/select?" + urlencode({"q": query, "rows": 1, "wt": "json", "core": "gav"}))
            records = payload.get("response", {}).get("docs", [])
            for record in records:
                if record.get("g") == target.namespace and record.get("a") == target.name and record.get("v") == version:
                    timestamp = record.get("timestamp")
                    if isinstance(timestamp, (int, float)) and timestamp > 0:
                        return iso(datetime.fromtimestamp(timestamp / 1000, UTC)), "maven_central_index_version_timestamp"
        except RegistryError:
            continue
    return None, None


def _maven(target: PackageTarget, client: RegistryClient) -> dict:
    path = "/".join(quote(part, safe="") for part in [*target.namespace.split("."), target.name])
    xml = client.get(f"https://repo.maven.apache.org/maven2/{path}/maven-metadata.xml", as_json=False)
    try:
        root = ElementTree.fromstring(xml)
    except Exception as exc:
        raise RegistryError("Maven metadata XML 오류", retryable=False) from exc
    declared = root.findtext("./versioning/release")
    if not declared or len(declared) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+!_~-]*", declared):
        raise RegistryError("Maven release metadata가 없습니다", retryable=False)
    versions = [node.text for node in root.findall("./versioning/versions/version") if node.text]
    if len(versions) > 20000:
        raise RegistryError("Maven 버전 목록 한도 초과", retryable=False)
    # A release marker can point to a prerelease. Use Maven ComparableVersion,
    # including qualifiers/aliases/numeric transitions, rather than lexical or
    # numeric-only ordering. Unknown vendor qualifiers remain valid releases.
    stable = [value for value in versions if maven_is_stable(value)]
    if maven_is_stable(declared):
        latest, selection = declared, "maven_release_metadata"
    else:
        latest = max(stable, key=MavenVersion, default=None)
        if latest is None:
            raise RegistryError("Maven 정식 버전 metadata가 없습니다", retryable=False)
        selection = "maven_highest_stable_comparable_version"
    warnings = []
    if latest != declared:
        warnings.append("Maven release가 사전 출시 버전이므로 ComparableVersion 순서의 최신 정식 버전을 선택했습니다")
    distance = maven_distance(versions, target.version, latest) if versions else None
    result = {"latestVersion": latest, "latestSelection": selection, "latestIsPrerelease": False,
              "registryLatestVersion": declared, "registryLatestIsPrerelease": not maven_is_stable(declared),
              "currentVersionPublishedAt": None, "latestPublishedAt": None, "versionDistance": distance,
              "versionDistanceBasis": "maven_comparable_version_stable_release_count" if distance is not None else "unavailable_version_list",
              "currentVersionMissing": target.version not in versions if versions else None,
              "publicationBasis": "maven_central_index_version_timestamp", "warnings": warnings}
    # Parent <lastUpdated> belongs to metadata, never an individual version.
    for field, version in (("currentVersionPublishedAt", target.version), ("latestPublishedAt", latest)):
        result[field], result[field + "Basis"] = _maven_date(target, version, client)
        if result[field] is None:
            artifact = f"https://repo.maven.apache.org/maven2/{path}/{quote(version, safe='')}/{quote(target.name, safe='')}-{quote(version, safe='')}.pom"
            try:
                result[field] = client.last_modified(artifact)
                if result[field]:
                    result[field + "Basis"] = "artifact_last_modified"
                    result["warnings"].append(f"{field}는 버전별 POM 저장소 Last-Modified입니다. 최초 공개일과 다를 수 있습니다")
            except RegistryError as exc:
                result["warnings"].append(f"{field} artifact: {exc}")
    return result


def _cargo(target: PackageTarget, client: RegistryClient) -> dict:
    payload = client.get(f"https://crates.io/api/v1/crates/{quote(target.name, safe='')}")
    versions = payload.get("versions", [])
    eligible = {entry["num"]: entry for entry in versions if isinstance(entry, dict) and isinstance(entry.get("num"), str) and _semver(entry["num"]) is not None and not entry.get("yanked", False)}
    latest = payload.get("crate", {}).get("max_stable_version")
    if latest not in eligible:
        latest = max(eligible, key=_semver, default=None)
    if latest is None:
        raise RegistryError("crates.io에 철회되지 않은 정식 릴리스가 없습니다", retryable=False)
    current = next((entry for entry in versions if isinstance(entry, dict) and entry.get("num") == target.version), {})
    return {"latestVersion": latest, "latestSelection": "crates_max_stable_non_yanked", "latestIsPrerelease": False,
            "currentVersionPublishedAt": iso(parse_date(current.get("created_at"))), "latestPublishedAt": iso(parse_date(eligible[latest].get("created_at"))),
            "versionDistance": _distance(list(eligible), target.version, latest), "versionDistanceBasis": "stable_semver_release_count",
            "currentVersionYanked": current.get("yanked"), "publicationBasis": "registry_created_at"}


def _go_escape(value: str) -> str:
    return "".join("!" + char.lower() if char.isupper() else char for char in value)


def _go_version(version: str) -> tuple | None:
    match = re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", version)
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    pre = []
    if prerelease:
        for part in prerelease.split("."):
            if not part or part.isdigit() and len(part) > 1 and part.startswith("0"):
                return None
            pre.append((0, int(part)) if part.isdigit() else (1, part))
    return int(major), int(minor), int(patch), 0 if prerelease else 1, tuple(pre)


def _go_retractions(document: bytes) -> list[tuple[tuple, tuple]]:
    # Tokenize go.mod strings/comments before reading retract directives; words
    # in comments or a quoted module path cannot become executable directives.
    text = document.decode("utf-8")
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|`[^`]*`|//[^\n]*|\n|[()\[\],]|[^\s()\[\],]+', text)
    lines, line = [], []
    for token in tokens:
        if token.startswith("//"):
            continue
        if token == "\n":
            lines.append(line); line = []
        else:
            if token.startswith('"'):
                token = json.loads(token)
            elif token.startswith("`"):
                token = token[1:-1]
            line.append(token)
    lines.append(line)
    intervals, block = [], False
    for line in lines:
        if not line:
            continue
        if block:
            if line == [")"]:
                block = False
                continue
            entry = line
        elif line[0] == "retract":
            entry = line[1:]
            if entry == ["("]:
                block = True
                continue
        else:
            continue
        if len(entry) == 1:
            lower = upper = _go_version(entry[0])
        elif len(entry) == 5 and entry[0] == "[" and entry[2] == "," and entry[4] == "]":
            lower, upper = _go_version(entry[1]), _go_version(entry[3])
        else:
            raise RegistryError("Go retract 구문을 해석할 수 없습니다", retryable=False)
        if lower is None or upper is None or lower > upper:
            raise RegistryError("Go retract 버전 범위가 올바르지 않습니다", retryable=False)
        intervals.append((lower, upper))
        if len(intervals) > 1000:
            raise RegistryError("Go retract 범위 한도 초과", retryable=False)
    if block:
        raise RegistryError("Go retract 블록이 끝나지 않았습니다", retryable=False)
    return intervals


def _golang(target: PackageTarget, client: RegistryClient) -> dict:
    module = _go_escape(f"{target.namespace}/{target.name}")
    path = quote(module, safe="/!")
    base = f"https://proxy.golang.org/{path}"
    listed = client.get(base + "/@v/list", as_json=False).decode("utf-8").splitlines()
    if len(listed) > 20000:
        raise RegistryError("Go 버전 목록 한도 초과", retryable=False)
    valid = {version: key for version in listed if (key := _go_version(version)) is not None}
    releases = {version: key for version, key in valid.items() if key[3] == 1}
    registry_latest_info = client.get(base + "/@latest")
    registry_latest = registry_latest_info.get("Version")
    registry_latest_key = _go_version(registry_latest) if isinstance(registry_latest, str) else None
    if registry_latest_key is None:
        raise RegistryError("Go proxy latest 버전이 없습니다", retryable=False)
    valid[registry_latest] = registry_latest_key
    if registry_latest_key[3] == 1:
        releases[registry_latest] = registry_latest_key
    # Go loads retractions from the highest release (or prerelease if there is
    # no release), including a version that retracts itself.
    authority = max(releases or valid, key=(releases or valid).get, default=None)
    if not isinstance(authority, str) or _go_version(authority) is None:
        raise RegistryError("Go proxy latest 버전이 없습니다", retryable=False)
    retractions = _go_retractions(client.get(base + f"/@v/{quote(_go_escape(authority), safe='!')}.mod", as_json=False))
    def retracted(version):
        key = _go_version(version)
        return key is not None and any(lower <= key <= upper for lower, upper in retractions)
    eligible = {version: key for version, key in releases.items() if not retracted(version)}
    latest = max(eligible, key=eligible.get, default=None)
    if latest is None:
        candidates = {version: key for version, key in valid.items() if not retracted(version)}
        latest = max(candidates, key=candidates.get, default=None)
    if latest is None:
        fallback = registry_latest_info.get("Version")
        if not isinstance(fallback, str) or _go_version(fallback) is None or retracted(fallback):
            raise RegistryError("Go에 철회되지 않은 버전이 없습니다", retryable=False)
        latest = fallback
    def info(version):
        payload = registry_latest_info if registry_latest_info.get("Version") == version else client.get(base + f"/@v/{quote(_go_escape(version), safe='!')}.info")
        if payload.get("Version") != version:
            raise RegistryError("Go proxy 버전별 응답 식별자가 일치하지 않습니다", retryable=False)
        return payload
    latest_info = info(latest)
    current = latest_info if latest == target.version else info(target.version)
    distance = _distance(list(eligible), target.version, latest, _go_version) if eligible else None
    return {"latestVersion": latest, "latestSelection": "go_highest_non_retracted_release" if latest in eligible else "go_highest_non_retracted_prerelease",
            "latestIsPrerelease": _go_version(latest)[3] == 0,
            "registryLatestVersion": registry_latest_info.get("Version"), "retractionSourceVersion": authority,
            "retractedVersionCount": sum(retracted(version) for version in releases), "currentVersionYanked": retracted(target.version),
            "currentVersionPublishedAt": iso(parse_date(current.get("Time"))), "latestPublishedAt": iso(parse_date(latest_info.get("Time"))),
            "currentVersionPublishedAtBasis": "go_module_revision_time", "latestPublishedAtBasis": "go_module_revision_time",
            "versionDistance": distance, "versionDistanceBasis": "go_non_retracted_stable_release_count" if distance is not None else "unavailable_stable_release_list",
            "publicationBasis": "go_module_revision_time", "warnings": ["Go 버전 시각은 소스 리비전 생성 시각이며 최초 registry 공개 시각과 다를 수 있습니다"]}


def _nuget_version(version: str) -> tuple | None:
    """NuGet identity/order: up to four release parts; build metadata is ignored.

    NuGet compares prerelease labels case-insensitively and numeric labels by
    value. Stable releases sort after prereleases with the same release parts.
    https://learn.microsoft.com/nuget/concepts/package-versioning
    """
    if not isinstance(version, str) or len(version) > 255:
        return None
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+){0,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", version)
    if not match:
        return None
    release, prerelease, _build = match.groups()
    parts = tuple(int(part) for part in release.split("."))
    parts += (0,) * (4 - len(parts))
    labels = tuple((0, int(part)) if part.isdigit() else (1, part.lower()) for part in prerelease.split(".")) if prerelease else ()
    return parts, 0 if prerelease else 1, labels


def _nuget(target: PackageTarget, client: RegistryClient) -> dict:
    # Discover the SemVer2 hive; older hives deliberately omit SemVer2 packages.
    service = client.get("https://api.nuget.org/v3/index.json")
    resources = service.get("resources")
    if not isinstance(resources, list):
        raise RegistryError("NuGet service index resources가 없습니다", retryable=False)
    bases = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        types = resource.get("@type")
        if "RegistrationsBaseUrl/3.6.0" not in (types if isinstance(types, list) else [types]):
            continue
        base = resource.get("@id")
        if not isinstance(base, str) or not allowed_registry_url(base):
            raise RegistryError("NuGet SemVer2 등록 주소가 허용되지 않습니다", retryable=False)
        parsed = urlsplit(base)
        if parsed.hostname != "api.nuget.org" or parsed.query or parsed.fragment or not parsed.path.endswith("/"):
            raise RegistryError("NuGet SemVer2 등록 주소가 올바르지 않습니다", retryable=False)
        bases.append(base)
    if not bases:
        raise RegistryError("NuGet SemVer2 등록 서비스를 찾을 수 없습니다", retryable=False)
    base = sorted(set(bases))[0]
    package_base = base + quote(target.name, safe="") + "/"
    payload = client.get(package_base + "index.json")
    pages = payload.get("items")
    if not isinstance(pages, list) or not pages:
        raise RegistryError("NuGet 등록 페이지가 없습니다", retryable=False)
    if len(pages) > MAX_NUGET_PAGES:
        raise RegistryError("NuGet 등록 페이지 안전 한도 초과; 부분 결과를 사용하지 않습니다", retryable=False)
    if "count" in payload and (type(payload["count"]) is not int or payload["count"] != len(pages)):
        raise RegistryError("NuGet 등록 페이지 개수가 일치하지 않습니다", retryable=False)
    records = {}
    record_count = 0
    for page in pages:
        if not isinstance(page, dict):
            raise RegistryError("NuGet 등록 페이지 형식 미지원", retryable=False)
        entries = page.get("items")
        if entries is None:
            page_url = page.get("@id")
            if not isinstance(page_url, str) or not page_url.startswith(package_base) or not allowed_registry_url(page_url):
                raise RegistryError("NuGet 등록 페이지 주소가 패키지 범위를 벗어났습니다", retryable=False)
            detail = client.get(page_url)
            entries = detail.get("items")
            if "count" in detail and (type(detail["count"]) is not int or not isinstance(entries, list) or detail["count"] != len(entries)):
                raise RegistryError("NuGet 상세 페이지 항목 개수가 일치하지 않습니다", retryable=False)
        if not isinstance(entries, list) or not entries:
            raise RegistryError("NuGet 등록 페이지 항목이 없습니다", retryable=False)
        if "count" in page and (type(page["count"]) is not int or page["count"] != len(entries)):
            raise RegistryError("NuGet 페이지 항목 개수가 일치하지 않습니다", retryable=False)
        record_count += len(entries)
        if record_count > MAX_NUGET_RECORDS:
            raise RegistryError("NuGet 버전 목록 안전 한도 초과; 부분 결과를 사용하지 않습니다", retryable=False)
        for entry in entries:
            record = entry.get("catalogEntry") if isinstance(entry, dict) else None
            if not isinstance(record, dict) or _nuget_version(record.get("version")) is None:
                raise RegistryError("NuGet catalog entry 형식 미지원", retryable=False)
            if record.get("id") is not None and str(record["id"]).lower() != target.name:
                raise RegistryError("NuGet 응답의 패키지 식별자가 일치하지 않습니다", retryable=False)
            if type(record.get("listed", True)) is not bool:
                raise RegistryError("NuGet listed 값이 올바르지 않습니다", retryable=False)
            # Keep only fields used by analysis rather than retaining the full
            # dependency/license metadata of every historical version.
            value = {key: record.get(key) for key in ("version", "published")}
            published = parse_date(value["published"])
            value["listed"] = record.get("listed", True) and not (published and published.year <= 1900)
            key = _nuget_version(value["version"])
            previous = records.get(key)
            if previous is not None and (previous["listed"] != value["listed"] or previous["published"] != value["published"]):
                raise RegistryError("NuGet 동일 버전의 등록 정보가 모순됩니다", retryable=False)
            records[key] = value
    eligible = {key: record for key, record in records.items() if key[1] == 1 and record["listed"]}
    latest_key = max(eligible, default=None)
    if latest_key is None:
        raise RegistryError("NuGet에 listed 정식 버전이 없습니다", retryable=False)
    current_key = _nuget_version(target.version)
    if current_key is None:
        raise RegistryError("NuGet 현재 버전 형식이 올바르지 않습니다", retryable=False)
    current = records.get(current_key)
    published = parse_date(current["published"]) if current else None
    return {"latestVersion": eligible[latest_key]["version"], "latestSelection": "nuget_listed_stable_registration", "latestIsPrerelease": False,
            "currentVersionPublishedAt": iso(published) if published and published.year > 1900 else None,
            "latestPublishedAt": iso(parse_date(eligible[latest_key]["published"])),
            "versionDistance": sum(current_key < key <= latest_key for key in eligible), "versionDistanceBasis": "nuget_listed_stable_release_count",
            "currentVersionMissing": current is None, "currentVersionYanked": not current["listed"] if current else None,
            "nugetRegistrationApi": "RegistrationsBaseUrl/3.6.0", "registrationPageCount": len(pages), "registrationVersionCount": len(records),
            "publicationBasis": "nuget_registration_published"}


def fetch_metadata(target: PackageTarget, client: RegistryClient, *, at: datetime | None = None) -> dict:
    at = at or datetime.now(UTC)
    source_start = len(client.urls)
    handler = {"npm": _npm, "pypi": _pypi, "maven": _maven, "cargo": _cargo, "golang": _golang, "nuget": _nuget}.get(target.ecosystem)
    if handler is None:
        raise RegistryError("지원하지 않는 package ecosystem입니다", retryable=False)
    try:
        result = handler(target, client)
    except RegistryError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError) as exc:
        raise RegistryError(f"registry metadata 형식 오류: {type(exc).__name__}", retryable=False) from exc
    result["versionDistanceParts"] = numeric_version_distance(target.version, result["latestVersion"])
    result["versionDistancePartsBasis"] = "first_numeric_difference_absolute"
    fields = ("latestVersion", "currentVersionPublishedAt", "latestPublishedAt", "versionDistance", "versionDistanceParts")
    result["fieldStatus"] = {field: "available" if result.get(field) is not None else "unavailable" for field in fields}
    for field in ("currentVersionPublishedAt", "latestPublishedAt"):
        basis = result.get(field + "Basis", result.get("publicationBasis"))
        result[field + "Basis"] = basis if result.get(field) else None
        if basis == "artifact_last_modified":
            result["fieldStatus"][field] = "repository_timestamp"
        elif basis == "go_module_revision_time":
            result["fieldStatus"][field] = "revision_timestamp"
        elif result.get(field):
            result["fieldStatus"][field] = "publication_timestamp"
    result.update({"sourceUrls": list(client.urls[source_start:]), "sourceKind": "public_registry", "fetchedAt": iso(at),
                   "expiresAt": iso(at + timedelta(seconds=int(setting("ttl_seconds", 86400))))})
    return result


def enqueue_components(db: Session, components: list[dict], *, force: bool = False, at: datetime | None = None) -> dict:
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError: return {"queued":0,"cached":0,"unsupported":0,"invalid":0,"deferred":len(components)}
    at = at or datetime.now(UTC)
    counts = {"queued": 0, "cached": 0, "unsupported": 0, "invalid": 0, "deferred": 0}
    pending = int(db.scalar(select(func.count()).select_from(PackageMetadataCache).where(PackageMetadataCache.state.in_(("queued", "running")))) or 0)
    seen = set()
    for component in components:
        try:
            target = parse_purl(component.get("purl", ""), str(component.get("version") or ""))
        except ValueError:
            counts["invalid"] += 1
            continue
        if target.id in seen:
            continue
        seen.add(target.id)
        row = db.get(PackageMetadataCache, target.id)
        if row is None:
            if pending >= MAX_QUEUE and target.ecosystem in SUPPORTED_ECOSYSTEMS:
                counts["deferred"] += 1
                continue
            row = PackageMetadataCache(id=target.id, package_key=target.package_key, current_version=target.version,
                                       purl=target.purl, ecosystem=target.ecosystem, next_attempt_at=at,
                                       state="queued" if target.ecosystem in SUPPORTED_ECOSYSTEMS else "unsupported")
            try:
                with db.begin_nested():
                    db.add(row)
                    db.flush()
            except IntegrityError:
                counts["cached"] += 1
                continue
            pending += row.state == "queued"
            counts["queued" if row.state == "queued" else "unsupported"] += 1
        elif row.state == "unsupported":
            counts["unsupported"] += 1
        elif row.state == "running":
            counts["cached"] += 1
        elif force or (row.expires_at and utc(row.expires_at) <= at):
            if pending >= MAX_QUEUE and row.state != "queued":
                counts["deferred"] += 1
                continue
            pending += row.state != "queued"
            row.state, row.attempts, row.next_attempt_at = "queued", 0, at
            counts["queued"] += 1
        else:
            counts["cached"] += 1
    return counts


queue_components = enqueue_components


def metadata_payload(row: PackageMetadataCache | None, *, at: datetime | None = None) -> dict:
    at = at or datetime.now(UTC)
    if row is None:
        return {"status": "missing", "error": "아직 수집되지 않은 패키지입니다"}
    document = copy.deepcopy(row.document or {})
    if row.state == "unsupported":
        status = "unsupported"
    elif row.state in {"queued", "running"}:
        status = "stale" if row.fetched_at else "pending"
    elif row.state == "failed":
        status = "stale" if row.fetched_at else "error"
    else:
        status = "fresh" if row.expires_at and utc(row.expires_at) > at else "stale"
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError:
        status = "stale"
        document["disabledReason"] = "승인된 통합 데이터가 없어 현재 정책 입력에서 제외했습니다"
    published = parse_date(document.get("currentVersionPublishedAt"))
    document.update({"packageKey": row.package_key, "purl": row.purl, "ecosystem": row.ecosystem, "currentVersion": row.current_version,
                     "status": status, "fetchedAt": iso(row.fetched_at), "expiresAt": iso(row.expires_at),
                     "ageDays": max(0, (at - published).days) if published else None,
                     "error": row.error, "attempts": row.attempts})
    if status == "unsupported":
        document["error"] = "이 ecosystem의 공개 registry 메타데이터는 지원하지 않습니다"
    return document


def enrich_components(db: Session, components: list[dict], *, at: datetime | None = None) -> list[dict]:
    at = at or datetime.now(UTC)
    result = copy.deepcopy(components)
    targets = {}
    for index, component in enumerate(result):
        try:
            targets[index] = parse_purl(component.get("purl", ""), str(component.get("version") or ""))
        except ValueError as exc:
            component.update({"metadataStatus": "invalid", "packageMetadata": {"status": "invalid", "error": str(exc)}})
    rows = {}
    ids = list({target.id for target in targets.values()})
    for offset in range(0, len(ids), 500):
        rows.update({row.id: row for row in db.scalars(select(PackageMetadataCache).where(PackageMetadataCache.id.in_(ids[offset:offset + 500])))})
    for index, target in targets.items():
        component = result[index]
        metadata = metadata_payload(rows.get(target.id), at=at)
        if target.ecosystem not in SUPPORTED_ECOSYSTEMS:
            metadata.update({"status": "unsupported", "ecosystem": target.ecosystem, "error": "이 ecosystem의 공개 registry 메타데이터는 지원하지 않습니다"})
        component.update({"metadataStatus": metadata["status"], "packageMetadata": metadata})
        if metadata["status"] == "fresh":
            properties = component.get("properties") or []
            if isinstance(properties, dict):
                properties = [{"name": key, "value": str(value)} for key, value in properties.items()]
            injected = {"koda:latestVersion": metadata.get("latestVersion"), "koda:publishedAt": metadata.get("currentVersionPublishedAt"),
                        "koda:ageDays": metadata.get("ageDays"), "koda:versionDistance": metadata.get("versionDistance")}
            properties = [entry for entry in properties if not isinstance(entry, dict) or entry.get("name") not in injected]
            properties.extend({"name": key, "value": str(value)} for key, value in injected.items() if value is not None)
            component["properties"] = properties
    return result


def metadata_summary(components: list[dict]) -> dict:
    statuses = Counter(component.get("metadataStatus", "missing") for component in components)
    return {**{status: statuses[status] for status in ("fresh", "stale", "pending", "error", "unsupported", "missing", "invalid")}, "total": len(components),
            **{label: sum(component.get("packageMetadata", {}).get(field) is not None for component in components) for label, field in (("withLatestVersion", "latestVersion"), ("withPublishedAt", "currentVersionPublishedAt"), ("withVersionDistance", "versionDistance"))}}


def backfill_components(db: Session, *, batch: int = BACKFILL_BATCH) -> int:
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError: return 0
    cursor = db.get(PackageMetadataCursor, "backfill")
    if cursor is None:
        cursor = PackageMetadataCursor(id="backfill", last_component_id="")
        db.add(cursor)
        db.flush()
    rows = list(db.scalars(select(RunComponent).where(RunComponent.id > cursor.last_component_id).order_by(RunComponent.id).limit(min(batch, BACKFILL_BATCH))))
    if not rows:
        cursor.last_component_id = ""
        return 0
    enqueue_components(db, [{"purl": row.purl, "version": row.version} for row in rows])
    cursor.last_component_id = rows[-1].id
    return len(rows)


def requeue_legacy_nuget_metadata(db: Session, *, at: datetime | None = None) -> int:
    """Once-only deployment upgrade; caller persists its FeatureUpgrade marker.

    Old permanent page-limit failures need another attempt. Old public success
    records must be refreshed against the complete SemVer2 hive. Keep imported
    offline evidence and in-progress work intact; queued old evidence is stale.
    """
    at = at or datetime.now(UTC)
    count = 0
    query = select(PackageMetadataCache).where(
        PackageMetadataCache.ecosystem == "nuget",
        PackageMetadataCache.state.in_(("completed", "failed")),
    ).with_for_update().execution_options(yield_per=100)
    for row in db.scalars(query):
        document = row.document or {}
        if document.get("sourceKind") == "offline_import" or document.get("nugetRegistrationApi") == "RegistrationsBaseUrl/3.6.0":
            continue
        row.document = {**document, "nugetCollectorUpgrade": {"requestedAt": iso(at), "previousState": row.state, "previousError": row.error}}
        row.state, row.attempts, row.next_attempt_at, row.error = "queued", 0, at, None
        count += 1
    db.flush()
    return count


def collect_one(db: Session, client: RegistryClient | None = None, *, at: datetime | None = None) -> bool:
    from .data_updates import reference_import_allowed
    try: reference_import_allowed(get_settings())
    except ValueError: return False
    if offline_mode() or not setting("enabled", True):
        return False
    at = at or datetime.now(UTC)
    max_attempts = int(setting("max_attempts", 3))
    row = db.scalar(select(PackageMetadataCache).where(
        PackageMetadataCache.next_attempt_at <= at,
        or_(PackageMetadataCache.state == "queued", and_(PackageMetadataCache.state == "completed", PackageMetadataCache.expires_at <= at),
            and_(PackageMetadataCache.state == "failed", PackageMetadataCache.attempts < max_attempts)))
        .order_by(PackageMetadataCache.next_attempt_at, PackageMetadataCache.id).limit(1).with_for_update(skip_locked=True))
    if row is None:
        return False
    row.state, row.attempts = "running", row.attempts + 1
    owned = client is None
    client = client or RegistryClient()
    try:
        target = parse_purl(row.purl, row.current_version)
        row.document = fetch_metadata(target, client, at=at)
        row.state, row.error, row.fetched_at = "completed", None, at
        row.expires_at = at + timedelta(seconds=int(setting("ttl_seconds", 86400)))
        row.next_attempt_at = row.expires_at
        row.attempts = 0
    except (RegistryError, ValueError) as exc:
        row.state, row.error = "failed", str(exc)[:1000]
        retryable = not isinstance(exc, RegistryError) or exc.retryable
        if retryable and row.attempts < max_attempts:
            seconds = (exc.retry_after if isinstance(exc, RegistryError) else None) or int(setting("retry_seconds", 60)) * 2 ** (row.attempts - 1)
            row.next_attempt_at = at + timedelta(seconds=min(seconds, 3600))
        else:
            row.attempts, row.next_attempt_at = max_attempts, None
        if row.expires_at is None:
            row.expires_at = at + timedelta(seconds=int(setting("ttl_seconds", 86400)))
    finally:
        if owned:
            client.__exit__()
    db.flush()
    return True


def run(*, once: bool = False) -> None:
    from .data_updates import release_read_lease
    # A separate process/container receives registry egress; analysis needs none.
    from . import models  # noqa: F401
    while True:
        try:
            with release_read_lease(get_settings()), SessionLocal() as db:
                if setting("enabled", True):
                    backfill_components(db)
                worked = collect_one(db)
                db.commit()
            # Intelligence has its own bounded worker tick and transaction so a
            # failed upstream feed cannot roll back a completed package cache.
            from .vulnerability_intelligence import intelligence_collector_tick
            with release_read_lease(get_settings()), SessionLocal() as db:
                worked = intelligence_collector_tick(db) or worked
                db.commit()
        except Exception as exc:
            # Never log registry payloads or environment values.
            print(f"Package metadata collector: {type(exc).__name__}", flush=True)
            worked = False
        if once:
            return
        time.sleep(max(float(setting("min_interval_seconds", 1)), 0.2) if worked else 5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    run(once=parser.parse_args().once)
