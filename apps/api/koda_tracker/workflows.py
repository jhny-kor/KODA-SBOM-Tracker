"""Version-scoped VEX decisions and durable native analysis notifications.

CycloneDX enum values follow the official 1.6 schema (also supported by 1.7).
An imported VEX statement is a request for review, never an approval credential.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AnalysisRevision, AuditEvent, JobState, SbomRun, User, now
from .workflow_models import FindingReview, NotificationDelivery, NotificationEvent, ReviewEvent
from .vulnerability import project_cve_findings

STATES = {"resolved", "resolved_with_pedigree", "exploitable", "in_triage", "false_positive", "not_affected"}
JUSTIFICATIONS = {"code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency", "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control"}
RESPONSES = {"can_not_fix", "will_not_fix", "update", "rollback", "workaround_available"}
SUPPRESS_STATES = {"false_positive", "not_affected"}


def utc(value):
    return value.replace(tzinfo=UTC) if value and value.tzinfo is None else value


def iso(value):
    return utc(value).isoformat() if value else None


def audit(db, actor, action, target, detail=None):
    db.add(AuditEvent(actor=actor, action=action, target_type="workflow", target_id=target, detail=detail or {}))


def identity(finding):
    component = str(finding.get("component") or "")
    version = str(finding.get("version") or finding.get("componentVersion") or "")
    if not component.startswith("pkg:") and version and not component.endswith("@" + version):
        component += "@" + version
    return component, version, str(finding.get("canonicalId") or finding.get("id") or finding.get("vulnerabilityId") or "")


def latest_revision(run):
    return max((r for r in run.analyses if r.state == JobState.COMPLETED), key=lambda r: r.sequence, default=None)


def targets(run):
    revision = latest_revision(run)
    return {identity(f): f for f in (revision.findings if revision else [])}


def resolve_target(run, component, vulnerability_id):
    matches = [(key, finding) for key, finding in targets(run).items()
               if key[0] == component and vulnerability_id in {key[2], finding.get("id"), *(finding.get("aliases") or [])}]
    if len(matches) != 1:
        raise HTTPException(422, "검토 대상은 현재 분석의 정확한 구성요소 버전과 취약점이어야 합니다")
    return matches[0][0]


def review_dict(review):
    return {"id": review.id, "runId": review.run_id, "component": review.component,
            "componentVersion": review.component_version, "vulnerabilityId": review.vulnerability_id,
            "state": review.state, "justification": review.justification, "detail": review.detail,
            "response": review.response, "expiresAt": iso(review.expires_at), "status": review.status,
            "author": review.author, "reviewer": review.reviewer, "decisionReason": review.decision_reason,
            "createdAt": iso(review.created_at), "decidedAt": iso(review.decided_at),
            "expired": bool(review.expires_at and utc(review.expires_at) <= now())}


def create_review(db: Session, run: SbomRun, author: User, body: dict, *, imported=False):
    component, version, vulnerability = resolve_target(run, body["component"], body["vulnerabilityId"])
    state = body["state"]
    justification = body.get("justification") or ""
    detail = body.get("detail") or ""
    if not isinstance(detail, str) or len(detail) > 10000:
        raise HTTPException(422, "검토 설명은 최대 10000자 문자열이어야 합니다")
    detail = detail.strip()
    response = body.get("response") or []
    expiry = body.get("expiresAt")
    if (not isinstance(state, str) or state not in STATES or not isinstance(justification, str)
            or (justification and justification not in JUSTIFICATIONS) or not isinstance(response, list)
            or len(response) > 5 or any(not isinstance(r, str) or r not in RESPONSES for r in response)):
        raise HTTPException(422, "CycloneDX VEX 상태·근거·대응 값이 유효하지 않습니다")
    if not detail or (state in SUPPRESS_STATES and not justification):
        raise HTTPException(422, "검토 설명이 필요하며 영향 없음/오탐에는 근거 코드도 필요합니다")
    if expiry and (expiry.tzinfo is None or expiry <= now()):
        raise HTTPException(422, "만료 시각은 시간대를 포함한 미래 시각이어야 합니다")
    review = FindingReview(run_id=run.id, service_id=run.release.service_id,
                           environment_id=run.release.environment_id, component=component,
                           component_version=version, vulnerability_id=vulnerability, state=state,
                           justification=justification, detail=detail, response=response, expires_at=expiry,
                           author_id=author.id, author=author.username)
    db.add(review)
    db.flush()
    db.add(ReviewEvent(review_id=review.id, kind="imported" if imported else "submitted", actor=author.username, comment=detail))
    audit(db, author.username, "vex.import" if imported else "vex.submit", review.id)
    emit_notification(db, "review:" + review.id, "review_submitted", "VEX 검토 요청",
                      f"{author.username}: {vulnerability} · {state}", run.id, None, {"reviewId": review.id})
    return review


def decide_review(db: Session, review: FindingReview, reviewer: User, decision: str, reason: str):
    if decision not in {"approved", "rejected"} or not reason.strip():
        raise HTTPException(422, "승인 또는 거절과 검토 사유가 필요합니다")
    if decision == "approved" and reviewer.id == review.author_id:
        raise HTTPException(403, "작성자는 자신의 VEX 요청을 승인할 수 없습니다")
    if decision == "approved" and review.expires_at and utc(review.expires_at) <= now():
        raise HTTPException(409, "만료된 요청은 승인할 수 없습니다. 새 검토를 제출하세요")
    timestamp = now()
    changed = db.execute(update(FindingReview).where(FindingReview.id == review.id, FindingReview.status == "submitted")
                         .values(status=decision, reviewer=reviewer.username, decision_reason=reason.strip(), decided_at=timestamp))
    if changed.rowcount != 1:
        raise HTTPException(409, "이미 결정된 검토는 변경할 수 없습니다. 새 검토를 제출하세요")
    db.add(ReviewEvent(review_id=review.id, kind=decision, actor=reviewer.username, comment=reason.strip()))
    audit(db, reviewer.username, "vex." + decision, review.id)
    db.flush()
    db.refresh(review)
    emit_notification(db, "decision:" + review.id, "review_" + decision, "VEX 검토 " + ("승인" if decision == "approved" else "거절"),
                      f"{reviewer.username}: {review.vulnerability_id}", review.run_id, None, {"reviewId": review.id, "decision": decision})
    return review


def approved_for_run(db, run):
    rows = db.scalars(select(FindingReview).where(FindingReview.service_id == run.release.service_id,
                       FindingReview.environment_id == run.release.environment_id, FindingReview.status == "approved")
                      .order_by(FindingReview.decided_at.desc(), FindingReview.id.desc())).all()
    chosen = {}
    for row in rows:
        chosen.setdefault((row.component, row.component_version, row.vulnerability_id), row)
    # An expired later approval must not resurrect an earlier approval.
    return {key: row for key, row in chosen.items() if not row.expires_at or utc(row.expires_at) > now()}


def apply_vex_reviews(db, run, revision):
    if revision.state != JobState.COMPLETED or revision.policy_state != "completed":
        return {"applied": 0, "suppressed": 0}
    decisions = approved_for_run(db, run)
    findings, snapshots = [], {}
    suppressed = set()
    for original in revision.findings or []:
        finding = dict(original)
        key = identity(finding)
        review = decisions.get(key)
        if review:
            evidence = review_dict(review)
            finding["vex"] = {**evidence, "reviewId": review.id, "suppressed": review.state in SUPPRESS_STATES}
            snapshots[review.id] = evidence
            if review.state in SUPPRESS_STATES:
                suppressed.add(key)
        findings.append(finding)
    policies = []
    for original in revision.policies or []:
        row = dict(original)
        key = (str(row.get("component") or ""), str(row.get("componentVersion") or ""), str(row.get("vulnerabilityId") or ""))
        # CEL is eligible only when it is explicitly a vulnerability-target rule.
        security = row.get("type") in {"severity", "kev"} or (row.get("type") == "cel" and row.get("target") == "vulnerability")
        if security and key in suppressed and not row.get("suppressed"):
            review = decisions[key]
            row.update(suppressed=True, vex=review_dict(review), suppressionSource="vex")
        policies.append(row)
    active = [p for p in policies if not p.get("suppressed")]
    metrics = dict(revision.metrics or {})
    metrics.update(effectiveVulnerabilityCount=len(project_cve_findings([f for f in findings if identity(f) not in suppressed])),
                   vexSuppressedCount=len(suppressed), vexReviews=list(snapshots.values()),
                   policyViolationCount=len(active), policyFailCount=sum(p.get("action") == "fail" for p in active),
                   policyWarnCount=sum(p.get("action") == "warn" for p in active),
                   policyInfoCount=sum(p.get("action") == "info" for p in active),
                   policySuppressedCount=len(policies) - len(active))
    if revision.policy_state == "completed":
        metrics["policyStatus"] = "fail" if metrics["policyFailCount"] else "warn" if metrics["policyWarnCount"] else "info" if metrics["policyInfoCount"] else "pass"
    revision.findings, revision.policies, revision.metrics = findings, policies, metrics
    return {"applied": len(snapshots), "suppressed": len(suppressed)}


def bom_targets(run):
    result = {}
    def visit(components):
        for component in components or []:
            ref = component.get("bom-ref")
            name = component.get("purl") or component.get("name") or ""
            version = str(component.get("version") or "")
            key = name if name.startswith("pkg:") or not version else name + "@" + version
            if ref:
                value = (key, version, component)
                if ref in result and result[ref][:2] != value[:2]:
                    raise HTTPException(422, "SBOM의 bom-ref가 모호합니다")
                result[ref] = value
            visit(component.get("components"))
    visit((run.normalized_bom or {}).get("components"))
    root_component = ((run.normalized_bom or {}).get("metadata") or {}).get("component")
    if isinstance(root_component, dict):
        visit([root_component])
    return result


def export_vex(db, run):
    refs = bom_targets(run)
    reverse = {}
    for ref, (component, version, original) in refs.items():
        reverse.setdefault((component, version), (ref, original))
    vulnerabilities, components = [], {}
    for key, review in approved_for_run(db, run).items():
        if key not in targets(run) or key[:2] not in reverse:
            continue
        ref, component = reverse[key[:2]]
        components[ref] = {k: v for k, v in component.items() if k in {"type", "name", "version", "purl", "bom-ref", "group"}}
        analysis = {"state": review.state, "detail": review.detail, "response": review.response,
                    "firstIssued": iso(review.created_at), "lastUpdated": iso(review.decided_at)}
        if review.justification:
            analysis["justification"] = review.justification
        vulnerabilities.append({"id": review.vulnerability_id, "affects": [{"ref": ref}], "analysis": analysis})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": list(components.values()), "vulnerabilities": vulnerabilities}


def import_vex(db, run, author, document):
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") not in {"1.6", "1.7"}:
        raise HTTPException(422, "CycloneDX 1.6/1.7 VEX JSON이 필요합니다")
    refs, requests = bom_targets(run), []
    declared = document.get("components") or []
    if not isinstance(declared, list):
        raise HTTPException(422, "VEX 구성요소 목록이 유효하지 않습니다")
    seen = {}
    for component in declared:
        if not isinstance(component, dict) or not isinstance(component.get("bom-ref"), str):
            raise HTTPException(422, "VEX 구성요소에는 정확한 bom-ref가 필요합니다")
        ref = component["bom-ref"]
        version = str(component.get("version") or "")
        name = component.get("purl") or component.get("name") or ""
        if not isinstance(name, str):
            raise HTTPException(422, "VEX 구성요소 식별자가 유효하지 않습니다")
        name = name if name.startswith("pkg:") or not version else name + "@" + version
        if ref not in refs or refs[ref][:2] != (name, version) or (ref in seen and seen[ref] != (name, version)):
            raise HTTPException(422, "VEX 구성요소가 현재 SBOM의 bom-ref와 일치하지 않습니다")
        seen[ref] = (name, version)
    vulnerabilities = document.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        raise HTTPException(422, "VEX 취약점 목록이 필요합니다")
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise HTTPException(422, "VEX 취약점 형식이 유효하지 않습니다")
        if not isinstance(vulnerability.get("id"), str) or not vulnerability["id"] or len(vulnerability["id"]) > 255:
            raise HTTPException(422, "VEX 취약점 ID가 유효하지 않습니다")
        analysis = vulnerability.get("analysis") or {}
        affects = vulnerability.get("affects") or []
        if not isinstance(affects, list) or not affects or not isinstance(analysis, dict):
            raise HTTPException(422, "VEX analysis와 affects 대상이 필요합니다")
        for target in affects:
            ref = target.get("ref") if isinstance(target, dict) else None
            if not isinstance(ref, str) or ref not in refs or target.get("versions"):
                raise HTTPException(422, "현재 SBOM의 정확한 bom-ref만 가져올 수 있습니다")
            requests.append({"component": refs[ref][0], "vulnerabilityId": vulnerability.get("id"),
                             "state": analysis.get("state"), "justification": analysis.get("justification", ""),
                             "detail": analysis.get("detail", ""), "response": analysis.get("response", [])})
            if len(requests) > 100:
                raise HTTPException(422, "VEX는 한 번에 최대 100개 대상만 가져올 수 있습니다")
    # Validate all targets before inserting, preserving atomic import semantics.
    for body in requests:
        resolve_target(run, body["component"], body["vulnerabilityId"])
        if not isinstance(body["state"], str) or body["state"] not in STATES or not isinstance(body["detail"], str) or not isinstance(body["response"], list):
            raise HTTPException(422, "VEX 분석 형식이 유효하지 않습니다")
    return [create_review(db, run, author, body, imported=True) for body in requests]


def webhook_settings(settings=None):
    settings = settings or get_settings()
    enabled = bool(getattr(settings, "notification_webhook_enabled", False))
    url = getattr(settings, "notification_webhook_url", "") or ""
    secret = getattr(settings, "notification_webhook_secret", "") or ""
    allowed = {h.strip().lower() for h in (getattr(settings, "notification_allowed_hosts", "") or "").split(",") if h.strip()}
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        parsed.port  # Validate a malformed port before attempting network I/O.
    except ValueError:
        return settings, enabled, url, secret, "", False
    valid = bool(host and host in allowed and parsed.scheme in {"https", "http"} and not parsed.username and not parsed.password and not parsed.fragment)
    if parsed.scheme == "http":
        try:
            internal = ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
        except ValueError:
            internal = host == "localhost" or "." not in host or host.endswith((".internal", ".local", ".test"))
        valid = valid and internal
    return settings, enabled, url, secret, host, valid


def emit_notification(db, dedupe_key, kind, title, message, run_id, revision_id, payload):
    existing = db.scalar(select(NotificationEvent).where(NotificationEvent.dedupe_key == dedupe_key))
    if existing:
        return existing
    event = NotificationEvent(dedupe_key=dedupe_key, kind=kind, title=title, message=message,
                              run_id=run_id, revision_id=revision_id, payload=payload)
    db.add(event)
    db.flush()
    _, enabled, _, _, _, _ = webhook_settings()
    if enabled:
        db.add(NotificationDelivery(event_id=event.id))
    return event


def notify_analysis(db, run, revision):
    prior = db.scalar(select(AnalysisRevision).where(AnalysisRevision.run_id == run.id,
                       AnalysisRevision.sequence < revision.sequence).order_by(AnalysisRevision.sequence.desc()).limit(1))
    def signature(item):
        return {"state": str(getattr(item.state, "value", item.state)),
                "findings": sorted({json.dumps({"identity": identity(f), "severity": f.get("severity"),
                    "cvssScore": f.get("cvssScore"), "nvdCvss": f.get("nvdCvss"), "kev": f.get("kev"),
                    "fixedIn": sorted(f.get("fixedIn") or []), "vexState": (f.get("vex") or {}).get("state"),
                    "vexJustification": (f.get("vex") or {}).get("justification")}, sort_keys=True) for f in item.findings or []}),
                "policies": sorted((str(p.get("policyId")), str(p.get("component")), str(p.get("vulnerabilityId")),
                                    str(p.get("action")), bool(p.get("suppressed"))) for p in item.policies or []),
                "policyState": item.policy_state, "policyVersion": item.policy_version}
    current = signature(revision)
    if prior and signature(prior) == current:
        return None
    failed = revision.state == JobState.FAILED or revision.policy_state == "failed"
    return emit_notification(db, "analysis:" + revision.id, "policy_failed" if revision.policy_state == "failed" else "analysis_failed" if failed else "analysis_changed",
                             "SBOM 정책 평가 실패" if revision.policy_state == "failed" else "SBOM 분석 실패" if failed else "SBOM 분석 결과 변경",
                             f"분석 #{revision.sequence}: 취약점 {len(current['findings'])}건, 정책 위반 {sum(not p.get('suppressed') for p in revision.policies or [])}건",
                             run.id, revision.id, {"runId": run.id, "revisionId": revision.id, "summary": current})


def notify_job_failure(db, job, run=None):
    """Record terminal worker/lease failures without exposing exception or payload secrets."""
    return emit_notification(db, "job_failed:" + job.id, "job_failed", "SBOM 작업 최종 실패",
                             "작업이 재시도 한도를 초과하거나 처리 중 실패했습니다. 관리자 확인이 필요합니다.",
                             run.id if run is not None else getattr(job, "run_id", None), None,
                             {"jobId": job.id, "attempts": job.attempts, "kind": job.kind})


def delivery_dict(row):
    return {"id": row.id, "eventId": row.event_id, "notificationId": row.event_id, "channel": "webhook",
            "status": row.status, "attempts": row.attempts, "lastError": row.last_error, "error": row.last_error,
            "nextAttemptAt": iso(row.next_attempt_at), "deliveredAt": iso(row.delivered_at), "createdAt": iso(row.created_at)}


def deliver_notifications(db, limit=1, *, transport=None):
    """Bounded leased outbox tick. No redirect, proxy environment, or unapproved host."""
    _, enabled, url, secret, _, valid = webhook_settings()
    if not enabled:
        return 0
    timestamp = now()
    rows = db.scalars(select(NotificationDelivery).where(NotificationDelivery.status.in_(["pending", "sending"]),
                      NotificationDelivery.next_attempt_at <= timestamp).order_by(NotificationDelivery.created_at).limit(min(limit, 10))).all()
    delivered = 0
    for row in rows:
        claim = db.execute(update(NotificationDelivery).where(NotificationDelivery.id == row.id,
                           NotificationDelivery.status.in_(["pending", "sending"]), NotificationDelivery.next_attempt_at <= timestamp)
                           .values(status="sending", next_attempt_at=timestamp + timedelta(seconds=60), attempts=NotificationDelivery.attempts + 1)
                           .execution_options(synchronize_session=False))
        db.commit()
        if claim.rowcount != 1:
            continue
        db.refresh(row)
        event = db.get(NotificationEvent, row.event_id)
        error = None
        if not valid or not secret:
            error = "Webhook destination or signing secret is not configured safely"
        elif not event:
            error = "Notification event is unavailable"
        else:
            payload = json.dumps({"id": event.id, "kind": event.kind, "title": event.title, "message": event.message,
                                  "createdAt": iso(event.created_at), "payload": event.payload}, sort_keys=True, separators=(",", ":")).encode()
            signature = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
            try:
                with httpx.Client(timeout=httpx.Timeout(5.0), follow_redirects=False, trust_env=False, transport=transport) as client:
                    with client.stream("POST", url, content=payload, headers={"Content-Type": "application/json", "X-KODA-Signature": "sha256=" + signature, "Idempotency-Key": event.id}) as response:
                        if not 200 <= response.status_code < 300:
                            error = f"Webhook HTTP status {response.status_code}"
            except (httpx.HTTPError, ValueError):
                # Exception text may contain credentials, URL, or secrets; expose a fixed category only.
                error = "Webhook connection failed"
        if error:
            row.status = "failed" if row.attempts >= 5 else "pending"
            row.last_error = error
            row.next_attempt_at = now() + timedelta(seconds=min(3600, 30 * 2 ** (row.attempts - 1)))
        else:
            row.status, row.delivered_at, row.last_error = "delivered", now(), None
            delivered += 1
        db.commit()
    return delivered
