"""التنبيهات: إعدادات المستخدم + قائمة التنبيهات + ربط Telegram بكود لمرة واحدة."""
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.integrations.notify import send_telegram, valid_slack_webhook
from app.models import Alert, AlertPrefs, TelegramLinkCode, User

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
public_router = APIRouter(tags=["telegram"])


class PrefsIn(BaseModel):
    threshold: int | None = Field(default=None, ge=0, le=100)
    in_app: bool | None = None
    telegram_enabled: bool | None = None
    slack_enabled: bool | None = None
    slack_webhook_url: str | None = Field(default=None, max_length=300)  # "" = مسح
    n8n_enabled: bool | None = None


def _prefs(db: Session, user: User) -> AlertPrefs:
    p = db.get(AlertPrefs, user.id)
    if not p:
        p = AlertPrefs(user_id=user.id, threshold=70, in_app=True, telegram_enabled=True,
                       slack_enabled=False, n8n_enabled=True)
        db.add(p)
        db.flush()
    return p


def _prefs_out(p: AlertPrefs) -> dict:
    return {
        "threshold": p.threshold, "in_app": p.in_app,
        "telegram_enabled": p.telegram_enabled, "telegram_linked": bool(p.telegram_chat_id),
        "telegram_available": bool(settings.telegram_bot_token),
        "slack_enabled": p.slack_enabled, "slack_configured": bool(p.slack_webhook_url),
        "n8n_enabled": p.n8n_enabled,
        # القنوات اللي مش مجانية ودايمة: ظاهرة كـ "غير متاح"
        "whatsapp": "unavailable", "email": "unavailable",
    }


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    p = _prefs(db, user)
    db.commit()
    return _prefs_out(p)


@router.put("/settings")
def put_settings(body: PrefsIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    p = _prefs(db, user)
    if body.threshold is not None:
        p.threshold = body.threshold
    for f in ("in_app", "telegram_enabled", "slack_enabled", "n8n_enabled"):
        v = getattr(body, f)
        if v is not None:
            setattr(p, f, v)
    if body.slack_webhook_url is not None:
        url = body.slack_webhook_url.strip()
        if url and not valid_slack_webhook(url):
            raise HTTPException(422, "رابط Slack webhook لازم يبدأ بـ https://hooks.slack.com/services/")
        p.slack_webhook_url = url or None
        if not url:
            p.slack_enabled = False
    db.commit()
    return _prefs_out(p)


@router.get("")
def list_alerts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.execute(select(Alert).where(Alert.user_id == user.id)
                      .order_by(Alert.created_at.desc()).limit(100)).scalars().all()
    return {"items": [{"id": str(a.id), "analysis_id": str(a.analysis_id) if a.analysis_id else None,
                       "risk_score": a.risk_score, "verdict": a.verdict, "title": a.title,
                       "channels": a.channels or [], "read": a.read,
                       "created_at": a.created_at.isoformat() if a.created_at else None}
                      for a in rows],
            "unread": sum(1 for a in rows if not a.read)}


@router.post("/read-all")
def read_all(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    db.execute(update(Alert).where(Alert.user_id == user.id, Alert.read.is_(False)).values(read=True))
    db.commit()
    return {"ok": True}


@router.post("/telegram/link-code")
def link_code(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not settings.telegram_bot_token:
        raise HTTPException(503, "Telegram غير مفعّل على السيرفر")
    code = secrets.token_hex(4).upper()
    db.add(TelegramLinkCode(code=code, user_id=user.id,
                            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)))
    db.commit()
    uname = settings.telegram_bot_username
    return {"code": code, "expires_in_minutes": 15, "bot_username": uname,
            "deep_link": f"https://t.me/{uname}?start={code}" if uname else None}


@router.post("/telegram/unlink")
def unlink(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    p = _prefs(db, user)
    p.telegram_chat_id = None
    db.commit()
    return _prefs_out(p)


@public_router.post("/api/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, update_body: dict, db: Session = Depends(get_db)):
    """بيستقبل رسايل البوت. الـ secret في الـ path لازم يطابق المُسجّل عند Telegram."""
    if not settings.telegram_webhook_secret or not secrets.compare_digest(
            secret, settings.telegram_webhook_secret):
        raise HTTPException(404)
    msg = update_body.get("message") or {}
    text = (msg.get("text") or "").strip()
    chat = (msg.get("chat") or {})
    chat_id = str(chat.get("id") or "")
    if not chat_id or chat.get("type") != "private":
        return {"ok": True}
    if text.startswith("/start"):
        code = text.split(maxsplit=1)[1].strip().upper() if " " in text else ""
        row = db.get(TelegramLinkCode, code) if code else None
        now = datetime.now(timezone.utc)
        exp = row.expires_at if row else None
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if row and exp and exp > now:
            p = db.get(AlertPrefs, row.user_id)
            if not p:
                p = AlertPrefs(user_id=row.user_id, threshold=70, in_app=True,
                               telegram_enabled=True, slack_enabled=False, n8n_enabled=True)
                db.add(p)
            p.telegram_chat_id = chat_id
            db.delete(row)  # استخدام واحد
            db.commit()
            await send_telegram(chat_id, "تم ربط PhishScope. هتوصلك تنبيهات الروابط الخطيرة هنا.")
        else:
            await send_telegram(chat_id, "الكود غير صالح أو انتهت صلاحيته. ولّد كود جديد من التطبيق.")
    return {"ok": True}
