from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .db import get_db
from .models import Environment, Service, now
from .security import require_csrf, require_permission
from .reanalysis import ReanalysisCycle, ReanalysisSchedule, cycle_payload, get_schedule, schedule_payload, scheduler_tick, start_cycle
from .services import audit

router = APIRouter(prefix='/api/v1')

class ScheduleRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    expectedVersion: int
    enabled: bool
    intervalMinutes: int = Field(ge=5, le=10080)
    onDataUpdate: bool = True
    latestOnly: bool = False
    serviceIds: list[str] = Field(default_factory=list, max_length=1000)
    environmentIds: list[str] = Field(default_factory=list, max_length=1000)

@router.get('/reanalysis-schedule')
def read_schedule(db: Session = Depends(get_db), _=Depends(require_permission('reanalysis.view', 'reanalysis.manage'))):
    return schedule_payload(db, get_schedule(db))

@router.put('/reanalysis-schedule')
def update_schedule(body: ScheduleRequest, db: Session = Depends(get_db), principal=Depends(require_permission('reanalysis.manage')), _csrf=Depends(require_csrf)):
    item = db.scalar(select(ReanalysisSchedule).where(ReanalysisSchedule.id == 'default').with_for_update())
    if item is None or item.version != body.expectedVersion:
        raise HTTPException(409, '재분석 일정이 변경되었습니다. 다시 불러오세요')
    for ids, model in ((body.serviceIds, Service), (body.environmentIds, Environment)):
        if ids and set(ids) != set(db.scalars(select(model.id).where(model.id.in_(ids)))):
            raise HTTPException(422, '존재하지 않는 서비스 또는 환경 범위입니다')
    for key, value in body.model_dump(exclude={'expectedVersion'}).items():
        setattr(item, {'intervalMinutes': 'interval_minutes', 'onDataUpdate': 'on_data_update', 'latestOnly': 'latest_only', 'serviceIds': 'service_ids', 'environmentIds': 'environment_ids'}.get(key, key), value)
    item.version += 1
    item.next_run_at = now() + timedelta(minutes=item.interval_minutes) if item.enabled else None
    if not item.enabled:
        item.rerun_requested = False
    audit(db, principal.username, 'reanalysis_schedule.update', 'schedule', 'default', body.model_dump())
    db.commit()
    return schedule_payload(db, item)

@router.post('/reanalysis-schedule/run-now', status_code=202)
def run_now(db: Session = Depends(get_db), principal=Depends(require_permission('reanalysis.manage')), _csrf=Depends(require_csrf)):
    item = db.scalar(select(ReanalysisSchedule).where(ReanalysisSchedule.id == 'default').with_for_update())
    cycle = start_cycle(db, item or get_schedule(db), 'manual')
    scheduler_tick(db)
    audit(db, principal.username, 'reanalysis_cycle.create', 'cycle', cycle.id)
    db.commit()
    return cycle_payload(db, cycle)

@router.get('/reanalysis-cycles')
def list_cycles(page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), _=Depends(require_permission('reanalysis.view', 'reanalysis.manage'))):
    return {'items': [cycle_payload(db, item) for item in db.scalars(select(ReanalysisCycle).order_by(ReanalysisCycle.created_at.desc()).offset((page - 1) * size).limit(size))], 'total': db.scalar(select(func.count()).select_from(ReanalysisCycle)) or 0, 'page': page, 'size': size}
