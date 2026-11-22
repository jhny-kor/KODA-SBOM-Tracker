"""Authenticated native VEX review and notification endpoints."""
from __future__ import annotations

import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select, true, tuple_
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from .db import get_db
from .models import Role, SbomRun, User
from .security import current_principal, require_csrf, require_permission, environment_scope, run_scope
from .workflow_models import FindingReview, NotificationDelivery, NotificationEvent, NotificationReceipt, ReviewEvent
from .workflows import (audit, create_review, decide_review, delivery_dict, export_vex, import_vex,
                        iso, now, review_dict, targets, webhook_settings)

router = APIRouter(prefix="/api/v1", tags=["native-workflows"])


def workflow_csrf(principal: User = Depends(current_principal), csrf: None = Depends(require_csrf)):
    """Authenticate before CSRF reads request.state.session."""


class ReviewBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    component: str = Field(min_length=1, max_length=4096)
    vulnerabilityId: str = Field(min_length=1, max_length=255)
    state: str = Field(max_length=32)
    justification: str = Field(default="", max_length=64)
    detail: str = Field(min_length=1, max_length=10000)
    response: list[str] = Field(default_factory=list, max_length=5)
    expiresAt: datetime | None = None


class DecisionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str
    reason: str = Field(min_length=1, max_length=10000)


class CommentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    comment: str = Field(min_length=1, max_length=10000)


def load_run(db, run_id):
    run = db.get(SbomRun, run_id)
    if not run:
        raise HTTPException(404, "SBOM을 찾을 수 없습니다")
    return run


def load_review(db, review_id, principal):
    review = db.scalar(select(FindingReview).where(FindingReview.id == review_id, environment_scope(principal, FindingReview.environment_id)))
    if not review:
        raise HTTPException(404, "검토를 찾을 수 없습니다")
    return review


@router.get("/sbom-runs/{run_id}/reviews")
def list_reviews(run_id: str, page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=100),
                 db: Session = Depends(get_db), principal: User = Depends(require_permission("vex.view", "vex.manage", "vex.approve"))):
    run = load_run(db, run_id)
    keys = targets(run)
    query = select(FindingReview).where(FindingReview.service_id == run.release.service_id,
                                        FindingReview.environment_id == run.release.environment_id)
    if not keys:
        return {"items": [], "total": 0, "page": page, "size": size}
    if len(keys) <= 2000:
        query = query.where(tuple_(FindingReview.component, FindingReview.component_version,
                                   FindingReview.vulnerability_id).in_(list(keys)))
        total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = db.scalars(query.order_by(FindingReview.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    else:
        # Avoid unbounded SQL bind parameters on very large SBOMs.
        rows = [r for r in db.scalars(query.order_by(FindingReview.created_at.desc()))
                if (r.component, r.component_version, r.vulnerability_id) in keys]
        total, rows = len(rows), rows[(page - 1) * size:page * size]
    return {"items": [review_dict(r) for r in rows], "total": total, "page": page, "size": size}


@router.post("/sbom-runs/{run_id}/reviews", dependencies=[Depends(workflow_csrf)], status_code=201)
def submit_review(run_id: str, body: ReviewBody, db: Session = Depends(get_db),
                  principal: User = Depends(require_permission("vex.manage"))):
    review = create_review(db, load_run(db, run_id), principal, body.model_dump())
    db.commit()
    return review_dict(review)


@router.get("/reviews/{review_id}/events")
def review_events(review_id: str, db: Session = Depends(get_db), principal: User = Depends(require_permission("vex.view", "vex.manage", "vex.approve"))):
    load_review(db, review_id, principal)
    rows = db.scalars(select(ReviewEvent).where(ReviewEvent.review_id == review_id).order_by(ReviewEvent.created_at, ReviewEvent.id)).all()
    return {"items": [{"id": r.id, "kind": r.kind, "actor": r.actor, "comment": r.comment, "createdAt": iso(r.created_at)} for r in rows]}


@router.post("/reviews/{review_id}/events", dependencies=[Depends(workflow_csrf)], status_code=201)
def comment_review(review_id: str, body: CommentBody, db: Session = Depends(get_db),
                   principal: User = Depends(require_permission("vex.manage"))):
    load_review(db, review_id, principal)
    if not body.comment.strip():
        raise HTTPException(422, "검토 의견이 필요합니다")
    event = ReviewEvent(review_id=review_id, kind="comment", actor=principal.username, comment=body.comment.strip())
    db.add(event)
    audit(db, principal.username, "vex.comment", review_id)
    db.commit()
    return {"id": event.id, "kind": event.kind, "actor": event.actor, "comment": event.comment, "createdAt": iso(event.created_at)}


@router.post("/reviews/{review_id}/decision", dependencies=[Depends(workflow_csrf)])
def decision_review(review_id: str, body: DecisionBody, db: Session = Depends(get_db),
                    principal: User = Depends(require_permission("vex.approve"))):
    review = decide_review(db, load_review(db, review_id, principal), principal, body.decision, body.reason)
    db.commit()
    return review_dict(review)


@router.get("/sbom-runs/{run_id}/vex")
def get_vex(run_id: str, db: Session = Depends(get_db), principal: User = Depends(require_permission("vex.view", "vex.manage", "vex.approve"))):
    return export_vex(db, load_run(db, run_id))


@router.post("/sbom-runs/{run_id}/vex-import", dependencies=[Depends(workflow_csrf)], status_code=201)
async def post_vex(run_id: str, request: Request, db: Session = Depends(get_db),
                   principal: User = Depends(require_permission("vex.manage"))):
    # Bounded incremental body avoids accepting arbitrary document sizes even without middleware.
    raw = bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw) > 65536:
            raise HTTPException(413, "VEX JSON은 최대 64KiB입니다")
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(422, "유효한 VEX JSON이 필요합니다") from None
    if not isinstance(document, dict):
        raise HTTPException(422, "VEX 문서 객체가 필요합니다")
    try:
        reviews = import_vex(db, load_run(db, run_id), principal, document)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"imported": len(reviews), "items": [review_dict(r) for r in reviews]}


def notification_scope(principal: User):
    if principal.role == Role.ADMIN:
        return true()
    return or_(NotificationEvent.run_id.is_(None),
               NotificationEvent.run_id.in_(select(SbomRun.id).where(run_scope(principal))))


@router.get("/notifications")
def list_notifications(page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=100),
                       db: Session = Depends(get_db), principal: User = Depends(require_permission("notifications.view", "notifications.manage"))):
    scope = notification_scope(principal)
    total = db.scalar(select(func.count()).select_from(NotificationEvent).where(scope)) or 0
    receipts = {r.event_id: r.read_at for r in db.scalars(select(NotificationReceipt).where(NotificationReceipt.user_id == principal.id))}
    unread = db.scalar(select(func.count()).select_from(NotificationEvent).where(scope, ~NotificationEvent.id.in_(select(NotificationReceipt.event_id).where(NotificationReceipt.user_id == principal.id)))) or 0
    rows = db.scalars(select(NotificationEvent).where(scope).order_by(NotificationEvent.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return {"items": [{"id": r.id, "kind": r.kind, "eventType": r.kind, "title": r.title, "message": r.message,
                       "runId": r.run_id, "revisionId": r.revision_id, "payload": r.payload, "createdAt": iso(r.created_at),
                       "read": r.id in receipts, "readAt": iso(receipts.get(r.id))} for r in rows],
            "total": total, "unreadCount": unread, "page": page, "size": size}


@router.post("/notifications/{event_id}/read", dependencies=[Depends(workflow_csrf)])
def read_notification(event_id: str, db: Session = Depends(get_db),
                      principal: User = Depends(require_permission("notifications.view", "notifications.manage"))):
    if not db.scalar(select(NotificationEvent.id).where(NotificationEvent.id == event_id, notification_scope(principal))):
        raise HTTPException(404, "알림을 찾을 수 없습니다")
    if not db.scalar(select(NotificationReceipt).where(NotificationReceipt.event_id == event_id, NotificationReceipt.user_id == principal.id)):
        try:
            with db.begin_nested():
                db.add(NotificationReceipt(event_id=event_id, user_id=principal.id))
                db.flush()
        except IntegrityError:
            pass  # A concurrent mark-read already wrote this unique user/event receipt.
        db.commit()
    return {"id": event_id, "read": True}


@router.get("/notification-deliveries")
def list_deliveries(page: int = Query(1, ge=1), size: int = Query(50, ge=1, le=100),
                    db: Session = Depends(get_db), principal: User = Depends(require_permission("notifications.manage"))):
    scope = NotificationDelivery.event_id.in_(select(NotificationEvent.id).where(notification_scope(principal)))
    total = db.scalar(select(func.count()).select_from(NotificationDelivery).where(scope)) or 0
    rows = db.scalars(select(NotificationDelivery).where(scope).order_by(NotificationDelivery.created_at.desc()).offset((page - 1) * size).limit(size)).all()
    return {"items": [delivery_dict(r) for r in rows], "total": total, "page": page, "size": size}


@router.post("/notification-deliveries/{delivery_id}/retry", dependencies=[Depends(workflow_csrf)])
def retry_delivery(delivery_id: str, db: Session = Depends(get_db),
                   principal: User = Depends(require_permission("notifications.manage"))):
    row = db.scalar(select(NotificationDelivery).where(
        NotificationDelivery.id == delivery_id,
        NotificationDelivery.event_id.in_(select(NotificationEvent.id).where(notification_scope(principal))),
    ))
    if not row:
        raise HTTPException(404, "알림 전송을 찾을 수 없습니다")
    if row.status != "failed":
        raise HTTPException(409, "최종 실패한 전송만 수동 재시도할 수 있습니다")
    previous_attempts = row.attempts
    row.status, row.attempts, row.next_attempt_at, row.last_error = "pending", 0, now(), None
    audit(db, principal.username, "notification.retry", row.id, {"previousAttempts": previous_attempts})
    db.commit()
    return delivery_dict(row)


@router.get("/notification-settings")
def notification_settings(principal: User = Depends(require_permission("notifications.manage"))):
    _, enabled, _, secret, host, valid = webhook_settings()
    return {"webhookEnabled": enabled, "webhookConfigured": valid and bool(secret), "webhookHost": host, "secretConfigured": bool(secret)}
