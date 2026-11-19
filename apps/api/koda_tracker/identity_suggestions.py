"""CPE identity suggestions for components without a PURL.

Candidates come only from the active, approved NVD index by a deterministic name rule.
The model may rank and explain those candidates; it cannot add a vendor/product, and
nothing here changes the stored SBOM or analysis. Applying a CPE stays a human edit
to the source SBOM followed by a new upload.
"""
import re
from contextlib import closing
from itertools import islice
from threading import BoundedSemaphore
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from sqlalchemy import select
from sqlalchemy.orm import Session

from .cve_catalog_api import catalog_release, products_for
from .db import get_db
from .models import RunComponent, SbomRun
from .security import require_csrf, require_permission
from .shared_ai import _GUARD, Short, structured

router = APIRouter(prefix="/api/v1/ai", tags=["Suite AI"])
_SCAN_LIMIT = 2000  # ponytail: bounded substring scan of NVD descriptions; add a product index if recall matters
_CANDIDATE_LIMIT = 8
_SO_SUFFIX = re.compile(r"\.so(?:\.[0-9]+)*$|\.(?:dll|jar|exe)$")
_VERSION_SUFFIX = re.compile(r"[-_.]v?[0-9]+(?:[._-][0-9A-Za-z]+)*$")
_SCAN = BoundedSemaphore(2)  # each lookup may walk the whole NVD index; keep it off the threadpool
_CPE_VERSION = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_IDENTITY_PROMPT = _GUARD + (
    "구성요소의 이름, 그룹, 버전, 종류와 결정적 규칙으로 찾은 NVD CPE 후보만 비교해 순위를 매기세요. "
    "후보 밖의 vendor나 product를 만들지 마세요. ranking은 관련 있는 후보만 최대 10개인 배열이며 "
    "각 항목은 {candidate: 후보 id, confidence: high|medium|low, reason: 300자 이하 근거}입니다. "
    "맞는 후보가 없으면 빈 배열을 반환하세요."
)


class SuggestionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    identityKey: str = Field(min_length=1, max_length=1024)


class IdentityRank(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    candidate: Annotated[str, StringConstraints(pattern=r"^c[0-9]{1,2}$")]
    confidence: Literal["high", "medium", "low"]
    reason: Short


class IdentityRanking(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ranking: list[IdentityRank] = Field(max_length=10)


def _squash(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _plain_names(name: str) -> set[str]:
    """Lowercased name, suffix- and version-stripped, with and without "lib"; separators are kept."""
    base = _SO_SUFFIX.sub("", name.strip().lower())
    names = {_VERSION_SUFFIX.sub("", base) or base}
    names |= {value.removeprefix("lib") for value in names}
    return {value.strip("-_. ") for value in names} - {""}


def _name_forms(name: str) -> set[str]:
    return {form for form in map(_squash, _plain_names(name)) if len(form) >= 3}


def _search_terms(name: str) -> list[str]:
    """NVD descriptions keep separators, so search with readable names and their longest tokens."""
    names = _plain_names(name)
    tokens = {token for value in names for token in re.split(r"[-_. ]+", value) if len(token) >= 4 and not token.isdigit()}
    terms = sorted({value for value in names if len(value) >= 3}, key=len, reverse=True)
    terms += sorted(tokens - set(terms), key=len, reverse=True)
    return terms[:4]


def _literal(field: str) -> str:
    return field.replace("\\", "")


def _collect(found, forms, identifier, record):
    for product in products_for(record):
        if product["source"] != "nvd":
            continue
        part, vendor, name_field = product["raw"]["criteria"].split(":")[2], product["vendor"], product["product"]
        squashed = _squash(_literal(name_field))
        if squashed in forms:
            match = "exact"
        elif len(squashed) >= 3 and any(form in squashed or squashed in form for form in forms):
            match = "partial"
        else:
            continue
        entry = found.setdefault((part, vendor, name_field), {"part": part, "vendor": vendor,
                                 "product": name_field, "match": match, "cves": set()})
        entry["cves"].add(identifier)


def nvd_candidates(index, name: str, group: str) -> list[dict]:
    """Return NVD products whose name equals (exact) or contains/is contained in (partial) a name form."""
    forms = _name_forms(name)
    vendor_form = _squash(group.rsplit(".", 1)[-1]) if group else ""
    found: dict[tuple[str, str, str], dict] = {}
    for query in _search_terms(name):
        with closing(index.items(query)) as records:  # release the SQLite cursor when the scan stops early
            for identifier, record in islice(records, _SCAN_LIMIT):
                _collect(found, forms, identifier, record)
    rows = [{"vendor": _literal(item["vendor"]), "product": _literal(item["product"]),
             "match": item["match"], "part": item["part"], "cpeVendor": item["vendor"], "cpeProduct": item["product"],
             "vendorMatchesGroup": bool(vendor_form) and _squash(_literal(item["vendor"])) == vendor_form,
             "cveCount": len(item["cves"])} for item in found.values()]
    rows.sort(key=lambda row: (row["match"] != "exact", not row["vendorMatchesGroup"], -row["cveCount"],
                               row["vendor"], row["product"]))
    return rows[:_CANDIDATE_LIMIT]


def _cpe(row: dict, version: str) -> str:
    # Versions that would need CPE escaping are left as ANY instead of being guessed.
    filled = version if _CPE_VERSION.fullmatch(version) else "*"
    return f"cpe:2.3:{row['part']}:{row['cpeVendor']}:{row['cpeProduct']}:{filled}:*:*:*:*:*:*:*"


@router.post("/runs/{run_id}/identity-suggestions",
             dependencies=[Depends(require_permission("runs.view")), Depends(require_csrf)])
def suggest_identity(run_id: str, body: SuggestionRequest, db: Session = Depends(get_db)):
    run = db.get(SbomRun, run_id)
    component = db.scalar(select(RunComponent).where(RunComponent.run_id == run_id,
                                                     RunComponent.identity_key == body.identityKey))
    if not run or run.archived_at is not None or component is None:
        raise HTTPException(404, "구성요소를 찾을 수 없습니다")
    if component.purl:
        raise HTTPException(409, "PURL이 있는 구성요소는 식별 후보를 만들지 않습니다")
    if not _SCAN.acquire(blocking=False):
        raise HTTPException(429, "식별 후보 검색이 처리 중입니다. 잠시 후 다시 시도하세요")
    try:
        with catalog_release() as (_records, index, metadata):
            rows = nvd_candidates(index, component.name, component.group_name)
    finally:
        _SCAN.release()
    result = {"dataAsOf": metadata.get("dataAsOf"), "advisory": True, "model": None}
    if not rows:
        return {**result, "candidates": [], "reason": "활성 NVD 자료에서 이름이 일치하는 제품을 찾지 못했습니다"}
    public = [{"id": f"c{index}", "vendor": row["vendor"], "product": row["product"], "match": row["match"],
               "vendorMatchesGroup": row["vendorMatchesGroup"], "cveCount": row["cveCount"],
               "cpe": _cpe(row, component.version)} for index, row in enumerate(rows)]
    facts = {"component": {"name": component.name[:200], "group": component.group_name[:200],
                           "version": component.version[:100], "type": component.component_type[:64]},
             "candidates": [{key: row[key] for key in ("id", "vendor", "product", "match", "vendorMatchesGroup", "cveCount")}
                            for row in public]}
    model, ranking = structured(db, facts, system=_IDENTITY_PROMPT, schema=IdentityRanking, max_tokens=1200)
    by_id = {row["id"]: row for row in public}
    ranked, seen = [], set()
    for item in ranking["ranking"]:
        if item["candidate"] in by_id and item["candidate"] not in seen:  # unknown IDs are dropped, never shown
            seen.add(item["candidate"])
            ranked.append({**by_id[item["candidate"]], "confidence": item["confidence"], "reason": item["reason"]})
    unranked = [{**row, "confidence": None, "reason": None} for row in public if row["id"] not in seen]
    return {**result, "model": model, "candidates": ranked + unranked}
