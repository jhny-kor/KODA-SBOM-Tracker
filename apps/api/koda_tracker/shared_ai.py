"""Suite AI provider. Only operator-approved private endpoints receive bounded facts."""
from collections import Counter
import http.client
import ipaddress
import json
import re
import socket
from threading import BoundedSemaphore
from typing import Any
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field, SecretStr, ValidationError
from sqlalchemy import String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from .config import get_settings
from .db import Base, get_db
from .models import AnalysisRevision, JobState, ProcessingState, SbomRun
from .security import require_admin, require_csrf, require_permission
from .services import audit

router = APIRouter(prefix="/api/v1/ai", tags=["Suite AI"])
_PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7",
))
_LIMIT = BoundedSemaphore(2)
_SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
_FACT_ID = re.compile(r"^[a-zA-Z0-9._:-]{1,100}$")


class SharedAISettings(Base):
    __tablename__ = "shared_ai_settings"
    id: Mapped[int] = mapped_column(primary_key=True)
    endpoint: Mapped[str] = mapped_column(String(512))
    model: Mapped[str] = mapped_column(String(128))
    encrypted_key: Mapped[str | None] = mapped_column(Text)


class SettingsInput(BaseModel):
    model: str = Field(pattern=r"^[A-Za-z0-9._:/-]{1,128}$")
    apiKey: SecretStr | None = None
    clearKey: bool = False


class KodaSummaryFacts(BaseModel):
    severityCounts: dict[str, int] = Field(max_length=6)
    ruleIds: list[str] = Field(max_length=25)


def _provider_url():
    try:
        value = urlsplit(get_settings().ai_base_url.strip())
        port = value.port
        if (len(value.geturl()) > 512 or value.scheme not in {"http", "https"} or not value.hostname or value.username is not None
                or value.password is not None or value.query or value.fragment or value.path.rstrip("/") != "/v1"
                or port == 0):
            raise ValueError
        return value
    except ValueError as exc:
        raise HTTPException(503, "운영자가 사내 AI의 /v1 주소를 설정해야 합니다") from exc


def _cipher():
    try:
        return Fernet(get_settings().ai_encryption_key.get_secret_value().encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(503, "운영자가 AI 비밀 저장용 암호화 키를 설정해야 합니다") from exc


def _status(row):
    try:
        base = _provider_url().geturl().rstrip("/")
    except HTTPException:
        base = None
    configured = row is not None and row.endpoint == base
    return {"endpointConfigured": bool(base), "baseUrl": base,
            "model": row.model if configured else None, "hasKey": bool(configured and row.encrypted_key)}


@router.get("/settings", dependencies=[Depends(require_admin)])
def read_settings(db: Session = Depends(get_db)):
    return _status(db.get(SharedAISettings, 1))


@router.put("/settings", dependencies=[Depends(require_admin), Depends(require_csrf)])
def save_settings(body: Any = Body(), db: Session = Depends(get_db), user=Depends(require_admin)):
    endpoint = _provider_url().geturl().rstrip("/")
    try:
        values = SettingsInput.model_validate(body)
        key = values.apiKey.get_secret_value() if values.apiKey is not None else ""
        if len(key) > 4096 or (key and not re.fullmatch(r"[!-~]+", key)) or (key and values.clearKey):
            raise ValueError
    except (ValidationError, ValueError) as exc:
        raise HTTPException(422, "모델 ID와 API 키 형식을 확인하세요") from exc
    row = db.get(SharedAISettings, 1)
    if row is None:
        row = SharedAISettings(id=1, endpoint=endpoint, model=values.model)
        db.add(row)
    if row.endpoint != endpoint:
        row.endpoint, row.encrypted_key = endpoint, None
    row.model = values.model
    if key:
        row.encrypted_key = _cipher().encrypt(key.encode()).decode("ascii")
    elif values.clearKey:
        row.encrypted_key = None
    audit(db, user.username, "ai.settings.update", "ai_settings", "1", {"model": row.model})
    db.commit()
    return _status(row)


def _private_addresses(host, port):
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses = {item[4][0] for item in records}
        if not addresses or any(not any(ipaddress.ip_address(ip) in n for n in _PRIVATE_NETWORKS) for ip in addresses):
            raise ValueError
        return sorted(addresses)
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "사내 AI 주소는 허용된 사설 네트워크로 해석되어야 합니다") from exc


def _call_model(row, facts):
    url = _provider_url()
    if row.endpoint != url.geturl().rstrip("/"):
        raise HTTPException(503, "AI 서버 주소가 변경되었습니다. 공통 AI 설정을 다시 저장하세요")
    port = url.port or (443 if url.scheme == "https" else 80)
    addresses = _private_addresses(url.hostname, port)
    key = ""
    if row.encrypted_key:
        if url.scheme == "http" and not all(ipaddress.ip_address(address).is_loopback for address in addresses):
            raise HTTPException(503, "API 키를 사용하는 사내 AI 서버에는 HTTPS가 필요합니다")
        try:
            key = _cipher().decrypt(row.encrypted_key.encode("ascii")).decode()
        except (InvalidToken, UnicodeError) as exc:
            raise HTTPException(503, "저장된 AI 키를 읽을 수 없습니다. 키를 다시 등록하세요") from exc
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(url.hostname, port, timeout=15)
    # Keep the approved hostname for TLS verification and pin the validated IP for this connection.
    def connect_pinned(_address, timeout, source_address=None):
        return socket.create_connection((addresses[0], port), timeout, source_address)

    connection._create_connection = connect_pinned
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    payload = json.dumps({"model": row.model, "max_tokens": 700, "stream": False, "messages": [
        {"role": "system", "content": "한국어로 주어진 점검 사실만 요약하고 확인할 조치를 제안하세요. "
                                     "판정이나 호환성, 미제공 사실을 추정하지 마세요."},
        {"role": "user", "content": json.dumps(facts, ensure_ascii=False)},
    ]}, ensure_ascii=False).encode()
    try:
        connection.request("POST", "/v1/chat/completions", body=payload, headers=headers)
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError
        content = json.loads(raw)["choices"][0]["message"]["content"]
        if not isinstance(content, str) or not content.strip() or len(content) > 8000:
            raise ValueError
        return content.strip()
    except (OSError, http.client.HTTPException, ValueError, TypeError, KeyError, IndexError) as exc:
        raise HTTPException(502, "사내 모델 응답을 받지 못했습니다. 연결, 모델 및 키를 확인하세요") from exc
    finally:
        connection.close()


def summarize(db: Session, facts):
    row = db.get(SharedAISettings, 1)
    if row is None:
        raise HTTPException(503, "공통 AI 모델이 설정되지 않았습니다")
    if not _LIMIT.acquire(blocking=False):
        raise HTTPException(429, "AI 요청이 처리 중입니다. 잠시 후 다시 시도하세요")
    try:
        return {"model": row.model, "summary": _call_model(row, facts), "advisory": True}
    finally:
        _LIMIT.release()


@router.post("/test", dependencies=[Depends(require_admin), Depends(require_csrf)])
def test_connection(db: Session = Depends(get_db)):
    summarize(db, {"test": "연결 시험"})
    return {"ok": True}


@router.post("/runs/{run_id}/summary", dependencies=[Depends(require_permission("runs.view")), Depends(require_csrf)])
def summarize_tracker_run(run_id: str, db: Session = Depends(get_db)):
    run = db.get(SbomRun, run_id)
    if not run or run.archived_at is not None or run.state != ProcessingState.COMPLETED:
        raise HTTPException(404, "분석 회차를 찾을 수 없습니다")
    analysis = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run_id)
                         .order_by(AnalysisRevision.sequence.desc()).limit(1))
    if not analysis or analysis.state != JobState.COMPLETED:
        raise HTTPException(409, "완료된 Tracker 분석을 선택하세요")
    if ((analysis.data_sources or {}).get("vulnerabilityDataStatus") or {}).get("status") == "unavailable":
        raise HTTPException(409, "취약점 자료를 사용할 수 없는 분석입니다")
    counts = Counter()
    ids = set()
    for row in analysis.findings or []:
        if not isinstance(row, dict):
            continue
        severity = str(row.get("severity", "")).lower()
        counts[severity if severity in _SEVERITIES else "unknown"] += 1
        identity = str(row.get("canonicalId") or row.get("id") or "").upper()
        if re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,16}", identity) and len(ids) < 25:
            ids.add(identity)
    return summarize(db, {"source": "tracker", "severityCounts": dict(counts), "cves": sorted(ids)})


def summarize_koda_facts(db, body):
    if (any(name not in _SEVERITIES or not 0 <= count <= 10**7 for name, count in body.severityCounts.items())
            or any(not _FACT_ID.fullmatch(item) for item in body.ruleIds)):
        raise HTTPException(422, "점검 요약 필드가 올바르지 않습니다")
    return summarize(db, {"source": "koda", **body.model_dump()})
