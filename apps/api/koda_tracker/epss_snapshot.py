"""Validate FIRST daily CSV snapshots and atomically project them into local evidence.

No URL is fetched. A file hash records provenance, not publisher authentication;
operators must obtain the file through their approved data-transfer process.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import re
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import insert, select, update
from sqlalchemy.orm import Session

from .config import get_settings
from .vulnerability_intelligence import MAX_CACHE, validate_epss
from .vulnerability_intelligence_models import VulnerabilityIntelligence

MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 128 * 1024 * 1024
SOURCE = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def parse_snapshot(raw: bytes) -> tuple[dict, list[dict]]:
    if not raw or len(raw) > MAX_COMPRESSED_BYTES:
        raise ValueError("EPSS 파일은 1바이트 이상 64MiB 이하여야 합니다")
    digest = hashlib.sha256(raw).hexdigest()
    try:
        if raw.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                expanded = stream.read(MAX_EXPANDED_BYTES + 1)
        else:
            expanded = raw
        if len(expanded) > MAX_EXPANDED_BYTES:
            raise ValueError("EPSS 압축 해제 크기가 128MiB 한도를 초과합니다")
        text = expanded.decode("utf-8-sig")
        header, separator, body = text.partition("\n")
        if not separator or not header.startswith("#"):
            raise ValueError("FIRST model_version·score_date 메타데이터가 필요합니다")
        parts = header[1:].strip().split(",")
        metadata = dict(part.strip().split(":", 1) for part in parts)
        if len(parts) != 2 or set(metadata) != {"model_version", "score_date"} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", metadata["model_version"]):
            raise ValueError("FIRST EPSS 메타데이터 형식이 올바르지 않습니다")
        score_date = metadata["score_date"]
        if "T" in score_date:
            parsed_date = datetime.fromisoformat(score_date.replace("Z", "+00:00"))
            if parsed_date.tzinfo is None:
                raise ValueError("EPSS 기준 시각에 시간대가 필요합니다")
            day = parsed_date.astimezone(UTC).date()
        else:
            day = date.fromisoformat(score_date)
        reader = csv.DictReader(io.StringIO(body, newline=""), strict=True)
        if reader.fieldnames != ["cve", "epss", "percentile"]:
            raise ValueError("EPSS CSV 열은 cve,epss,percentile 순서여야 합니다")
        records, seen = [], set()
        for record in reader:
            if len(records) >= MAX_CACHE:
                raise ValueError(f"EPSS 파일은 최대 {MAX_CACHE:,}개 CVE까지 허용합니다")
            if None in record or any(value is None for value in record.values()):
                raise ValueError("EPSS CSV 열 개수가 올바르지 않습니다")
            normalized = validate_epss({**record, "date": day.isoformat()})
            if normalized["cve"] in seen:
                raise ValueError("EPSS 파일에 중복 CVE가 있습니다")
            seen.add(normalized["cve"])
            records.append(normalized)
        if not records:
            raise ValueError("EPSS 파일에 점수가 없습니다")
        return {"date": day.isoformat(), "modelVersion": metadata["model_version"], "sha256": digest,
                "sourceUrl": SOURCE, "recordCount": len(records)}, records
    except (OSError, EOFError, UnicodeError, csv.Error, TypeError, OverflowError) as exc:
        raise ValueError("올바른 FIRST EPSS CSV(.gz) 파일이 아닙니다") from exc


def import_snapshot(db: Session, metadata: dict, records: list[dict], *, actor: str, at=None) -> dict:
    """Caller commits only after audit succeeds; never commit a partial snapshot."""
    at = at or datetime.now(UTC)
    source_day = date.fromisoformat(metadata["date"])
    fetched = datetime.combine(source_day, datetime.min.time(), UTC)
    expires = fetched + timedelta(days=get_settings().epss_policy_max_age_days + 1)
    existing = {}
    for offset in range(0, len(records), 500):
        ids = [value["cve"] for value in records[offset:offset + 500]]
        query = select(VulnerabilityIntelligence.cve, VulnerabilityIntelligence.document["date"].as_string(),
                       VulnerabilityIntelligence.document["snapshotSha256"].as_string()).where(VulnerabilityIntelligence.cve.in_(ids))
        for cve, source_date, source_hash in db.execute(query):
            existing[cve] = {"date": source_date or "", "snapshotSha256": source_hash}
    total = db.query(VulnerabilityIntelligence).count()
    if total + sum(record["cve"] not in existing for record in records) > MAX_CACHE:
        raise ValueError(f"EPSS 캐시 {MAX_CACHE:,}개 한도를 초과합니다")
    imported = skipped = 0
    additions = []
    updates = []
    for record in records:
        previous = existing.get(record["cve"])
        if previous is not None and (previous.get("date", "") > metadata["date"] or
                                     previous.get("snapshotSha256") == metadata["sha256"]):
            skipped += 1
            continue
        document = {**record, "sourceKind": "offline_snapshot", "sourceUrl": metadata["sourceUrl"],
                    "modelVersion": metadata["modelVersion"], "snapshotSha256": metadata["sha256"],
                    "importedAt": at.isoformat(), "importedBy": actor}
        values = {"state": "completed", "document": document, "attempts": 0, "error": None,
                  "fetched_at": fetched, "expires_at": expires, "next_attempt_at": expires}
        if previous is None:
            additions.append({"cve": record["cve"], **values})
        else:
            updates.append({"cve": record["cve"], **values})
        imported += 1
        if len(additions) == 1000:
            db.execute(insert(VulnerabilityIntelligence), additions)
            additions.clear()
        if len(updates) == 1000:
            db.execute(update(VulnerabilityIntelligence), updates, execution_options={"synchronize_session": False})
            updates.clear()
    if additions:
        db.execute(insert(VulnerabilityIntelligence), additions)
    if updates:
        db.execute(update(VulnerabilityIntelligence), updates, execution_options={"synchronize_session": False})
    db.flush()
    db.expire_all()
    return {**metadata, "imported": imported, "skipped": skipped, "importedAt": at.isoformat(),
            "policyMaxAgeDays": get_settings().epss_policy_max_age_days,
            "policyEligible": -1 <= (at.date() - source_day).days <= get_settings().epss_policy_max_age_days}
