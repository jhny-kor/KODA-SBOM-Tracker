"""Pure offline keys for full RPM and Debian package versions."""
import re

_RPM_EVR = re.compile(r"(?:(?P<epoch>[0-9]+):)?(?P<version>[A-Za-z0-9._+~^]+)-(?P<release>[A-Za-z0-9._+~^]+)")
_RPM_PARTS = re.compile(r"[0-9]+|[A-Za-z]+|[~^]")
_DEB_UPSTREAM = re.compile(r"[0-9][A-Za-z0-9.+:~\-]*")
_DEB_REVISION = re.compile(r"[A-Za-z0-9.+~]+")
_DEB_PARTS = re.compile(r"([^0-9]*)([0-9]*)")
_EPOCH = re.compile(r"[0-9]+")


def _rpm_part(value: str) -> tuple:
    # rpm-version(7): tilde < end of component < caret < alpha < numeric.
    operators = {"~": (0, 0), "^": (2, 0)}
    parts = (
        operators[part] if part in operators else (4, int(part)) if part.isdigit() else (3, part)
        for part in _RPM_PARTS.findall(value)
    )
    return (*parts, (1, 0))


def rpm_version_key(value: str) -> tuple | None:
    """Order [epoch:]version-release. Require release for a package comparison."""
    if len(value) > 255 or (match := _RPM_EVR.fullmatch(value)) is None:
        return None
    version, release = match["version"], match["release"]
    if not any(character.isalnum() for character in version) or not any(character.isalnum() for character in release):
        return None
    return int(match["epoch"] or "0"), _rpm_part(version), _rpm_part(release)


def _deb_order(character: str) -> int:
    # Debian Policy 5.6.12: tilde < end < ASCII letters < other characters.
    if character == "~":
        return -1
    return ord(character) if character.isalpha() else ord(character) + 256


def _deb_part(value: str) -> tuple:
    parts = (
        ((*map(_deb_order, prefix), 0), int(digits or "0"))
        for prefix, digits in _DEB_PARTS.findall(value)
        if prefix or digits
    )
    return (*parts, ((0,), 0))


def deb_version_key(value: str) -> tuple | None:
    """Order [epoch:]upstream[-revision], with absent revision equivalent to 0."""
    if not value or len(value) > 255:
        return None
    epoch, colon, body = value.partition(":")
    if colon and (not _EPOCH.fullmatch(epoch) or int(epoch) > 2_147_483_647):
        return None
    upstream, dash, revision = (body if colon else value).rpartition("-")
    if not dash:
        upstream, revision = revision, "0"
    if not _DEB_UPSTREAM.fullmatch(upstream) or not _DEB_REVISION.fullmatch(revision):
        return None
    return int(epoch) if colon else 0, _deb_part(upstream), _deb_part(revision)
