"""n8n integration: webhook محمي بـ secret header. n8n طبقة automation فقط."""
import logging

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)


async def send_alert_event(analysis) -> None:
    if not settings.n8n_webhook_url:
        return
    payload = {
        "analysis_id": str(analysis.id),
        "user_id": str(analysis.user_id) if analysis.user_id else None,
        "input_type": analysis.input_type.value if analysis.input_type else None,
        "verdict": analysis.verdict.value if analysis.verdict else None,
        "severity": analysis.severity.value if analysis.severity else None,
        "risk_score": analysis.risk_score,
        "recommended_action": analysis.recommended_action,
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(settings.n8n_webhook_url, json=payload,
                              headers={"X-PhishScope-Secret": settings.n8n_webhook_secret})
    except Exception as exc:
        # لو n8n وقع التحليل الأساسي بيكمل عادي
        log.warning("n8n event failed: %s", type(exc).__name__)
