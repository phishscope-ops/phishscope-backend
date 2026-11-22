"""Dashboard + Inbox + Devices + Health."""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db, set_rls_context
from app.core.security import get_current_user
from app.models import Analysis, Device, MessageInbox, ScanStatus, User, Verdict
from app.schemas import DashboardStats, DeviceIn, InboxItem

router = APIRouter(prefix="/api", tags=["misc"])


@router.get("/health")
def health():
    return {"status": "ok", "service": "phishscope-backend"}


@router.get("/dashboard/stats", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    set_rls_context(db, user.id, user.role.value)
    base = select(func.count()).select_from(Analysis).where(
        Analysis.user_id == user.id, Analysis.status == ScanStatus.done)

    def cnt(*conds):
        return db.execute(base.where(*conds)).scalar_one()

    return DashboardStats(
        total_scans=cnt(),
        safe_count=cnt(Analysis.verdict.in_([Verdict.SAFE, Verdict.LOW_RISK])),
        suspicious_count=cnt(Analysis.verdict == Verdict.SUSPICIOUS),
        malicious_count=cnt(Analysis.verdict.in_([Verdict.HIGH_RISK, Verdict.MALICIOUS])),
        unknown_count=cnt(Analysis.verdict == Verdict.INSUFFICIENT_DATA),
        last_30d=cnt(Analysis.created_at >= datetime.now(timezone.utc) - timedelta(days=30)),
    )


@router.get("/inbox", response_model=list[InboxItem])
def inbox(unread_only: bool = False, db: Session = Depends(get_db),
          user: User = Depends(get_current_user)):
    set_rls_context(db, user.id, user.role.value)
    q = select(MessageInbox).where(MessageInbox.user_id == user.id)
    if unread_only:
        q = q.where(MessageInbox.is_read.is_(False))
    return db.execute(q.order_by(MessageInbox.created_at.desc()).limit(100)).scalars().all()


@router.post("/inbox/{message_id}/read", status_code=204)
def mark_read(message_id, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    import uuid as _uuid
    msg = db.get(MessageInbox, _uuid.UUID(str(message_id)))
    if not msg or msg.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Message not found")
    msg.is_read = True
    msg.read_at = datetime.now(timezone.utc)
    db.commit()


@router.post("/devices", status_code=201)
def register_device(body: DeviceIn, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    existing = db.execute(select(Device).where(Device.user_id == user.id,
                                               Device.push_token == body.push_token)).scalar_one_or_none()
    if existing:
        existing.last_seen_at = datetime.now(timezone.utc)
    else:
        db.add(Device(user_id=user.id, push_token=body.push_token, platform=body.platform))
    db.commit()
    return {"registered": True}
