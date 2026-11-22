"""Analysis endpoints: POST /api/analyze + History + Result + Report (Person 1 & 2)."""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal, get_db, set_rls_context
from app.core.security import get_current_user
from app.engine.pipeline import run_analysis
from app.models import Analysis, ScanStatus, ScanType, Severity, User, Verdict
from app.schemas import (AnalyzeIn, AnalyzeOut, EvidenceOut, HistoryItem, HistoryOut,
                         ResultOut)

router = APIRouter(prefix="/api", tags=["analysis"])


def _dedup_hash(content: str, itype: ScanType | None) -> bytes:
    return hashlib.sha256(f"{itype.value if itype else 'auto'}|{content.strip().lower()}".encode()).digest()


@router.post("/analyze", response_model=AnalyzeOut, status_code=202)
async def analyze(body: AnalyzeIn, background: BackgroundTasks,
                  db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    set_rls_context(db, user.id, user.role.value)
    req_hash = _dedup_hash(body.content, body.input_type)
    # نفس المدخل خلال فترة الكاش؟ رجّع نفس الفحص (حماية كوتا + سرعة)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.analysis_dedup_hours)
    existing = db.execute(
        select(Analysis).where(Analysis.request_hash == req_hash,
                               Analysis.status == ScanStatus.done,
                               Analysis.created_at >= cutoff,
                               Analysis.user_id == user.id)
        .order_by(Analysis.created_at.desc())).scalars().first()
    if existing:
        return AnalyzeOut(analysis_id=existing.id, status=existing.status)

    analysis = Analysis(user_id=user.id, input_type=body.input_type or ScanType.url,
                        raw_input=body.content, normalized_input=body.content[:2000],
                        request_hash=req_hash)
    db.add(analysis)
    db.commit()
    background.add_task(_run_in_new_session, analysis.id)
    return AnalyzeOut(analysis_id=analysis.id, status=analysis.status)


def _run_in_new_session(analysis_id: uuid.UUID) -> None:
    import asyncio
    with SessionLocal() as db:
        analysis = db.get(Analysis, analysis_id)
        if not analysis:
            return
        asyncio.run(run_analysis(db, analysis))
        db.commit()


def _to_result(db: Session, a: Analysis) -> ResultOut:
    return ResultOut(
        analysis_id=a.id, status=a.status, input_type=a.input_type,
        risk_score=a.risk_score, severity=a.severity, verdict=a.verdict,
        was_blocked=a.was_blocked, findings=a.findings or [],
        evidence=[EvidenceOut(source=e.source.value, provider=e.provider,
                              evidence_type=e.evidence_type, state=e.state.value,
                              data=e.data, weight=e.weight) for e in a.evidence],
        iocs=a.iocs or [],
        recommended_actions=[a.recommended_action] if a.recommended_action else [],
        explanation=a.explanation, created_at=a.created_at, completed_at=a.completed_at)


def _owned(db: Session, analysis_id: uuid.UUID, user: User) -> Analysis:
    a = db.get(Analysis, analysis_id)
    # User Scan Ownership: مالك الفحص أو analyst/admin بس
    if not a or (a.user_id != user.id and user.role.value not in ("analyst", "admin")):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return a


@router.get("/analyses/{analysis_id}", response_model=ResultOut)
def get_analysis(analysis_id: uuid.UUID, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    set_rls_context(db, user.id, user.role.value)
    return _to_result(db, _owned(db, analysis_id, user))


@router.get("/analyses/{analysis_id}/report", response_model=ResultOut)
def get_report(analysis_id: uuid.UUID, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    # Reports Support: JSON دلوقتي، PDF في M5
    set_rls_context(db, user.id, user.role.value)
    return _to_result(db, _owned(db, analysis_id, user))


@router.get("/analyses", response_model=HistoryOut)
def history(db: Session = Depends(get_db), user: User = Depends(get_current_user),
            page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
            input_type: ScanType | None = None, verdict: Verdict | None = None,
            severity: Severity | None = None,
            date_from: datetime | None = None, date_to: datetime | None = None):
    set_rls_context(db, user.id, user.role.value)
    q = select(Analysis).where(Analysis.user_id == user.id)
    count_q = select(func.count(Analysis.id)).where(Analysis.user_id == user.id)
    for cond in (
        input_type and Analysis.input_type == input_type,
        verdict and Analysis.verdict == verdict,
        severity and Analysis.severity == severity,
        date_from and Analysis.created_at >= date_from,
        date_to and Analysis.created_at <= date_to,
    ):
        if cond is not None and cond is not False:
            q = q.where(cond)
            count_q = count_q.where(cond)
    total = db.execute(count_q).scalar_one()
    rows = db.execute(q.order_by(Analysis.created_at.desc())
                      .offset((page - 1) * page_size).limit(page_size)).scalars().all()
    return HistoryOut(items=[HistoryItem.model_validate(r) for r in rows],
                      total=total, page=page, page_size=page_size)
