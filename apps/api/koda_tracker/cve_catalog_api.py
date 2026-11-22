"""Read-only CVE catalog from the currently approved, pinned offline release.

Product/version search is evidence discovery. It is not a substitute for an
inventory-aware applicability analysis, especially for AND/OR and OS conditions.
"""
from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from .config import get_settings
from .data_updates import DataUpdateError, assert_approved_release, release_read_lease
from .db import get_db
from .models import AnalysisRevision, Environment, Release, RolePolicy, SbomRun, Service
from .offline_cpe import _compare, _fields, evaluate
from .nvd_catalog_products import cna_names, cna_products, cpe_leaves
from .nvd_record_index import cache_directory, cached_nvd_records, nvd_description as _description
from .security import DEFAULT_ROLE_PERMISSIONS, require_permission, run_scope
from .vulnerability import _nvd_details, _safe_bundle_file, active_bundle, cvss_score

router = APIRouter(prefix="/api/v1/cve-catalog", tags=["cve-catalog"])
_reader = require_permission("vulnerability.view", "metadata.view")
_identifier = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def _http_url(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = urlsplit(value)
        return value if parsed.scheme in {"https", "http"} and parsed.hostname and not parsed.username and not parsed.password else None
    except ValueError:
        return None



def _range_label(version):
    start = str(version.get("version") or "미제공")
    end = version.get("lessThan")
    inclusive = version.get("lessThanOrEqual")
    if end is not None:
        return f"{start} 이상 · {end} 미만"
    if inclusive is not None:
        return f"{start} 이상 · {inclusive} 이하"
    return "범위·조건 확인 필요" if start in {"*", "-", "미제공"} else start


def products_for(record):
    products = []
    for product, source_identifier in cna_products(record):
        vendor, name = cna_names(product)
        versions = product.get("versions") if isinstance(product.get("versions"), list) else []
        products.append({"source": "cna", "sourceIdentifier": source_identifier, "vendor": vendor, "product": name, "ranges": [{"label": _range_label(v), "status": str(v.get("status") or "unknown"), "versionType": str(v.get("versionType") or "미제공")} for v in versions if isinstance(v, dict)], "defaultStatus": product.get("defaultStatus", "unknown"), "condition": "발행기관 공지 · 원문 조건 확인", "raw": product})
    seen = set()
    for match in cpe_leaves(record.get("configurations")):
        try:
            fields = _fields(match["criteria"])
        except (ValueError, KeyError):
            continue
        key = json.dumps(match, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        ranges = []
        for name, suffix in (("versionStartIncluding", "이상"), ("versionStartExcluding", "초과"), ("versionEndIncluding", "이하"), ("versionEndExcluding", "미만")):
            if name in match:
                ranges.append(f"{match[name]} {suffix}")
        label = " · ".join(ranges) or (fields[3] if fields[3] not in {"*", "-"} else "별도 버전 경계 없음 · 전체 조건 확인")
        products.append({"source": "nvd", "vendor": fields[1], "product": fields[2], "ranges": [{"label": label, "status": "affected" if match.get("vulnerable") is True else "environment", "versionType": "CPE"}], "condition": "NVD AND/OR·환경 조건 적용" if match.get("vulnerable") is True else "환경 선행조건", "raw": match})
    return products


def _cna_version(product, version):
    """Conservative numeric boundaries; unknown vendor comparators stay unknown."""
    results = []
    for entry in product.get("versions") or []:
        if not isinstance(entry, dict):
            continue
        start = str(entry.get("version") or "")
        upper = entry.get("lessThan", entry.get("lessThanOrEqual"))
        if entry.get("changes"):
            results.append("unknown")
            continue
        if upper is None:
            if start == version:
                results.append(entry.get("status", "unknown"))
            elif start in {"*", "-", ""}:
                results.append("unknown")
            continue
        if entry.get("versionType") != "semver":
            results.append("unknown")
            continue
        lower_cmp = 1 if start == "*" else _compare(version, start)
        upper_cmp = -1 if upper == "*" else _compare(version, str(upper))
        if lower_cmp is None or upper_cmp is None:
            results.append("unknown")
        elif lower_cmp >= 0 and (upper_cmp < 0 or ("lessThanOrEqual" in entry and upper_cmp == 0)):
            results.append(entry.get("status", "unknown"))
    if "affected" in results:
        return "match"
    if "unknown" in results:
        return "unknown"
    if results:
        return "outside"
    default = product.get("defaultStatus", "unknown")
    return "outside" if default == "unaffected" else "match" if default == "affected" else "unknown"


def version_match(record, products, version):
    if not version:
        return "not_requested"
    outcomes = []
    for product in products:
        if product["source"] == "cna":
            outcomes.append(_cna_version(product["raw"], version))
        elif product["raw"].get("vulnerable") is True:
            try:
                fields = list(_fields(product["raw"]["criteria"]))
                fields[3] = version
                # Unprovided platform/edition details must not be guessed.
                fields[4:] = ["*"] * len(fields[4:])
                outcome = evaluate(record.get("configurations"), ["cpe:2.3:" + ":".join(fields)])
                outcomes.append({"affected": "match", "not_affected": "outside"}.get(outcome.status, "unknown"))
            except (ValueError, TypeError):
                outcomes.append("unknown")
    return "match" if "match" in outcomes else "unknown" if not outcomes or "unknown" in outcomes else "outside"


def _summary(identifier, record, products=None):
    if products is None:
        products = products_for(record)
    return {"id": identifier, "description": _description(record), "published": record.get("published"), "lastModified": record.get("lastModified"), "status": record.get("vulnStatus", "Unknown"), "cvss": cvss_score({"nvdCvss": record.get("cvss") or record.get("metrics") or {}}), "products": products, "versionMatch": "not_requested"}


@lru_cache(maxsize=2)
def _search_index(path_name, file_identity, manifest_hash):
    # Keep only a private disk index in the cache, never the complete raw JSON
    # and expanded summaries. The release identity and approval are rechecked
    # for every request under the existing release read lease.
    settings = get_settings()
    return cached_nvd_records(path_name, file_identity, manifest_hash, str(cache_directory(settings)), _nvd_details)


@contextmanager
def catalog_release():
    settings = get_settings()
    try:
        with release_read_lease(settings):
            bundle = active_bundle(settings)
            if bundle is None:
                _search_index.cache_clear()
                cached_nvd_records.cache_clear()
                raise DataUpdateError("활성 취약점 자료가 없습니다. 승인된 통합 자료를 반입·적용하세요")
            assert_approved_release(settings, bundle.path)
            path = _safe_bundle_file(bundle.path, bundle.metadata.get("NVD_INDEX"), ("nvd.json", "nvd-data.json"))
            if path is None:
                _search_index.cache_clear()
                cached_nvd_records.cache_clear()
                raise DataUpdateError("활성 자료에 NVD 상세 정보가 없습니다")
            stat = path.stat()
            identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)
            records = _search_index(str(path), identity, bundle.manifest_sha256)
            with records.checked():
                yield records, records, {"state": "ready", "bundleVersion": bundle.version, "dataAsOf": bundle.metadata.get("NVD_DATASET_DATE", bundle.data_as_of), "source": "승인된 활성 NVD 반입 자료"}
                after = path.stat()
                if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity:
                    raise DataUpdateError("조회 중 NVD 원본이 변경되었습니다")
                current = active_bundle(settings)
                if current is None or (current.path, current.version, current.manifest_sha256) != (bundle.path, bundle.version, bundle.manifest_sha256):
                    raise DataUpdateError("조회 중 활성 취약점 자료가 변경되었습니다")
                assert_approved_release(settings, bundle.path)
    except (DataUpdateError, OSError, ValueError, TypeError, sqlite3.Error) as exc:
        _search_index.cache_clear()
        cached_nvd_records.cache_clear()
        raise HTTPException(503, f"CVE 자료 조회 불가: {exc}") from exc


@router.get("")
def search_cves(q: str = Query("", max_length=256), vendor: str = Query("", max_length=256), product: str = Query("", max_length=256), version: str = Query("", max_length=128), page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), principal=Depends(_reader)):
    with catalog_release() as (records, index, metadata):
        query, vendor, product = (value.strip().casefold() for value in (q, vendor, product))
        version = version.strip()
        start = (page - 1) * size
        rows = []
        total = 0
        filtered = bool(vendor or product or version)
        if _identifier.fullmatch(query):
            identifier = query.upper()
            record = records.get(identifier)
            candidates = [(identifier, record)] if record is not None else []
        elif not filtered:
            total, candidates = index.catalog_page(query, start, size)
        else:
            candidates = index.catalog_candidates(query, vendor, product)
        paginated = not filtered and not _identifier.fullmatch(query)
        for identifier, record in candidates:
            if not paginated and not _identifier.fullmatch(identifier):
                continue
            products = products_for(record)
            matches = [
                entry for entry in products
                if (entry["source"] == "cna" or entry["raw"].get("vulnerable") is True)
                and vendor in entry["vendor"].casefold() and product in entry["product"].casefold()
            ]
            if (vendor or product) and not matches:
                continue
            status = version_match(record, matches, version)
            if status == "outside":
                continue
            if not paginated:
                total += 1
                if not start < total <= start + size:
                    continue
            matched = [entry for entry in matches if version_match(record, [entry], version) != "outside"]
            row = _summary(identifier, record, products)
            def public_product(entry):
                return {key: value for key, value in entry.items() if key != "raw"}
            rows.append({**row, "products": [public_product(entry) for entry in products], "matchedProducts": [public_product(entry) for entry in matched], "versionMatch": status})
        return {**metadata, "items": rows, "total": total, "page": page, "size": size, "versionSearchNote": "지원하지 않는 버전 체계·환경 조건은 확인 필요로 포함합니다. 실제 영향 판정은 SBOM 분석 근거를 확인하세요."}


def _observations(db, principal, identifier):
    policy = db.get(RolePolicy, principal.role)
    permissions = set(policy.permissions if policy else DEFAULT_ROLE_PERMISSIONS.get(principal.role, ()))
    if "runs.view" not in permissions:
        return {"items": [], "available": False, "reason": "SBOM 회차 조회 권한이 필요합니다", "truncated": False}
    ranked = select(SbomRun.id, func.row_number().over(partition_by=SbomRun.release_id, order_by=(SbomRun.round_number.desc(), SbomRun.created_at.desc(), SbomRun.id.desc())).label("rank")).where(SbomRun.archived_at.is_(None), run_scope(principal)).subquery()
    ids = select(ranked.c.id).where(ranked.c.rank == 1)
    revision_ranks = select(AnalysisRevision.id, func.row_number().over(partition_by=AnalysisRevision.run_id, order_by=AnalysisRevision.sequence.desc()).label("rank")).where(AnalysisRevision.run_id.in_(ids)).subquery()
    revision_ids = select(revision_ranks.c.id).where(revision_ranks.c.rank == 1)
    # Select only evidence columns from the latest revision. Loading SbomRun ORM
    # objects here would also deserialize every original normalized SBOM; eager
    # loading its analyses would materialize every historic analysis revision.
    query = select(SbomRun.id.label("run_id"), SbomRun.created_at,
        Service.name.label("service"), Environment.name.label("environment"), Release.version.label("release"),
        AnalysisRevision.findings, AnalysisRevision.state.label("analysis_state"), AnalysisRevision.data_as_of,
    ).select_from(SbomRun).join(Release, SbomRun.release_id == Release.id).join(Service, Release.service_id == Service.id).join(Environment, Release.environment_id == Environment.id).outerjoin(AnalysisRevision, (AnalysisRevision.run_id == SbomRun.id) & AnalysisRevision.id.in_(revision_ids)).where(SbomRun.id.in_(ids)).order_by(SbomRun.created_at.desc(), SbomRun.id).limit(1001)
    items = []; truncated = False
    for index, row in enumerate(db.execute(query.execution_options(yield_per=20)).mappings()):
        if index == 1000:
            truncated = True
            break
        for finding in row["findings"] or []:
            if not isinstance(finding, dict):
                continue
            aliases = finding.get("aliases")
            values = [finding.get("id"), finding.get("canonicalId"), *(aliases if isinstance(aliases, list) else [aliases])]
            if identifier not in {str(value).upper() for value in values}:
                continue
            items.append({"runId": row["run_id"], "service": row["service"], "environment": row["environment"], "release": row["release"], "component": finding.get("component", ""), "version": finding.get("version", ""), "observedAt": row["created_at"].isoformat(), "analysisState": str(row["analysis_state"].value), "dataAsOf": row["data_as_of"]})
            if len(items) > 200:
                truncated = True
                break
        if len(items) > 200:
            break
    return {"items": items[:200], "available": True, "truncated": truncated, "scope": "릴리스별 최신 보관 SBOM의 저장 분석 결과"}


@router.get("/{identifier}")
def cve_detail(identifier: str, db=Depends(get_db), principal=Depends(_reader)):
    identifier = identifier.upper()
    if not _identifier.fullmatch(identifier):
        raise HTTPException(422, "올바른 CVE 번호를 입력하세요")
    with catalog_release() as (records, _index, metadata):
        record = records.get(identifier)
        if record is None:
            raise HTTPException(404, "활성 반입 자료에서 CVE를 찾을 수 없습니다")
        references = []
        for reference in record.get("references", []):
            url = _http_url(reference.get("url") if isinstance(reference, dict) else reference)
            if url and url not in references:
                references.append(url)
        return {**metadata, **_summary(identifier, record), "weaknesses": record.get("weaknesses", []), "references": references, "configurations": record.get("configurations", []), "affected": record.get("affected", []), "observations": _observations(db, principal, identifier), "applicabilityNote": "발행기관 공지와 NVD 적용 조건을 구분합니다. 버전 경계의 상한은 수정 버전의 확정 근거가 아닙니다."}
