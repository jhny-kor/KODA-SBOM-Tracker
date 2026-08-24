from __future__ import annotations

import base64
import ssl
from dataclasses import dataclass

from ldap3 import NONE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars


class LdapConfigurationError(Exception):
    pass


class LdapInvalidCredentials(Exception):
    pass


class LdapUnavailable(Exception):
    pass


@dataclass(frozen=True)
class LdapConfig:
    host: str
    port: int
    tls_mode: str
    verify_certificate: bool
    ca_cert_path: str
    bind_dn: str
    bind_password: str
    base_dn: str
    login_attribute: str
    username_attribute: str
    subject_attribute: str
    user_filter: str
    group_attribute: str


@dataclass(frozen=True)
class LdapIdentity:
    username: str
    subject: str
    groups: tuple[str, ...]


def _unbind(connection: Connection) -> None:
    try:
        connection.unbind()
    except (LDAPException, OSError):
        pass


def _attribute(entry, name: str) -> str:
    values = entry.entry_attributes_as_dict.get(name, [])
    if isinstance(values, (list, tuple)):
        value = values[0] if values else ""
    else:
        value = values
    return str(value).strip()


def _subject(entry, name: str) -> str:
    values = entry.entry_attributes_as_dict.get(name, [])
    value = values[0] if isinstance(values, (list, tuple)) and values else values
    if isinstance(value, bytes):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    return str(value).strip()


def _attributes(entry, name: str) -> tuple[str, ...]:
    values = entry.entry_attributes_as_dict.get(name, [])
    if not isinstance(values, (list, tuple)):
        values = [values]
    return tuple(str(value).strip() for value in values if str(value).strip())


def _tls(config: LdapConfig) -> Tls | None:
    if config.tls_mode == "plain":
        return None
    if config.tls_mode not in {"ldaps", "starttls"}:
        raise LdapConfigurationError("LDAP TLS 방식이 올바르지 않습니다")
    if config.ca_cert_path:
        return Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=config.ca_cert_path, valid_names=[config.host])
    return Tls(validate=ssl.CERT_REQUIRED, valid_names=[config.host])


def _bind(config: LdapConfig, user: str, password: str) -> Connection:
    connection: Connection | None = None
    try:
        server = Server(
            config.host,
            port=config.port,
            use_ssl=config.tls_mode == "ldaps",
            tls=_tls(config),
            get_info=NONE,
            connect_timeout=10,
        )
        connection = Connection(
            server,
            user=user,
            password=password,
            auto_bind=False,
            receive_timeout=10,
        )
        connection.open()
        if config.tls_mode == "starttls" and not connection.start_tls():
            raise LdapUnavailable("LDAP StartTLS 협상에 실패했습니다")
        if not connection.bind():
            if str(connection.result.get("result")) == "49":
                raise LdapInvalidCredentials
            raise LdapUnavailable("LDAP bind에 실패했습니다")
        return connection
    except LdapInvalidCredentials:
        if connection is not None:
            _unbind(connection)
        raise
    except (LDAPException, OSError, ssl.SSLError, TimeoutError) as exc:
        if connection is not None:
            _unbind(connection)
        raise LdapUnavailable("LDAP 서버에 연결할 수 없습니다") from exc


def authenticate_user(config: LdapConfig, username: str, password: str) -> LdapIdentity:
    if not config.host or not config.bind_dn or not config.bind_password or not config.base_dn:
        raise LdapConfigurationError("LDAP 연결 정보가 완전하지 않습니다")
    if "{username}" not in config.user_filter:
        raise LdapConfigurationError("LDAP 사용자 검색 필터에 {username}이 필요합니다")
    if not username or len(username) > 256:
        raise LdapInvalidCredentials
    service = _bind(config, config.bind_dn, config.bind_password)
    try:
        user_filter = config.user_filter.replace("{username}", escape_filter_chars(username))
        attributes = {config.login_attribute, config.username_attribute, config.subject_attribute, config.group_attribute}
        try:
            found = service.search(config.base_dn, user_filter, attributes=sorted(attributes), size_limit=2)
        except (LDAPException, OSError, ssl.SSLError, TimeoutError) as exc:
            raise LdapUnavailable("LDAP 사용자 검색에 실패했습니다") from exc
        if not found:
            raise LdapInvalidCredentials
        if len(service.entries) != 1:
            raise LdapInvalidCredentials
        entry = service.entries[0]
        user_dn = entry.entry_dn
        identity_username = _attribute(entry, config.username_attribute) or _attribute(entry, config.login_attribute)
        identity_subject = _subject(entry, config.subject_attribute)
        if not identity_username or len(identity_username) > 128 or not identity_subject or len(identity_subject) > 512:
            raise LdapInvalidCredentials
        groups = _attributes(entry, config.group_attribute)
    finally:
        _unbind(service)

    user_connection = _bind(config, user_dn, password)
    try:
        return LdapIdentity(username=identity_username, subject=identity_subject, groups=groups)
    finally:
        _unbind(user_connection)
