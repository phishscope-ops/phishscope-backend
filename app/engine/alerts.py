"""توزيع التنبيهات حسب تفضيلات المستخدم بعد اكتمال التحليل."""
import logging

from sqlalchemy.orm import Session

from app.analysis.normalize import defang
from app.integrations.notify import send_slack, send_telegram
from app.models import Alert, AlertPrefs

log = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 70


def get_prefs(db: Session, user_id) -> AlertPrefs | None:
    return db.get(AlertPrefs, user_id) if user_id else None


def threshold_for(prefs: AlertPrefs | None) -> int:
    return prefs.threshold if prefs else DEFAULT_THRESHOLD


def _safe_target(analysis) -> str:
    """النطاق فقط (defanged): من غير path/query/نص الرسالة الخام (ممكن فيه tokens أو بيانات خاصة)."""
    from urllib.parse import urlsplit
    raw = (analysis.raw_input or "").strip()
    kind = analysis.input_type.value if analysis.input_type else ""
    if kind in ("url", "qr", "domain"):
        try:
            u = urlsplit(raw if "://" in raw else "//" + raw)
            if u.hostname:
                return "الهدف: " + defang(u.hostname)
        except ValueError:
            pass
    return "الهدف: " + ("رسالة" if kind == "sms" else "إيميل" if kind == "email" else "محتوى مفحوص")


def alert_text(analysis) -> str:
    v = analysis.verdict.value if analysis.verdict else "?"
    return (f"PhishScope: تنبيه خطر {analysis.risk_score}/100 ({v})\n"
            f"{_safe_target(analysis)}\nافتح التطبيق للتفاصيل. متفتحش الرابط ولا تدخّل بيانات.")


async def dispatch(db: Session, analysis) -> list[str]:
    """بيسجل التنبيه (in-app) ويبعت على القنوات المفعّلة لو الدرجة >= threshold المستخدم."""
    if not analysis.user_id or analysis.risk_score is None:
        return []
    prefs = get_prefs(db, analysis.user_id)
    if analysis.risk_score < threshold_for(prefs):
        return []
    text = alert_text(analysis)
    sent: list[str] = []
    if prefs is None or prefs.in_app:
        sent.append("in_app")
    if prefs and prefs.telegram_enabled and prefs.telegram_chat_id:
        if await send_telegram(prefs.telegram_chat_id, text):
            sent.append("telegram")
    if prefs and prefs.slack_enabled and prefs.slack_webhook_url:
        if await send_slack(prefs.slack_webhook_url, text):
            sent.append("slack")
    if "in_app" in sent:
        db.add(Alert(user_id=analysis.user_id, analysis_id=analysis.id,
                     risk_score=analysis.risk_score,
                     verdict=analysis.verdict.value if analysis.verdict else None,
                     title=text.splitlines()[0], channels=sent))
        db.flush()
    return sent
