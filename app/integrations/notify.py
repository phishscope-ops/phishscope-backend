"""قنوات التنبيه المجانية الدائمة: Telegram bot + Slack incoming webhook.
فشل أي قناة ما بيكسرش التحليل.
"""
import logging

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)

SLACK_PREFIX = "https://hooks.slack.com/services/"


def valid_slack_webhook(url: str) -> bool:
    return url.startswith(SLACK_PREFIX) and len(url) < 300 and " " not in url


async def send_telegram(chat_id: str, text: str) -> bool:
    if not settings.telegram_bot_token or not chat_id:
        return False
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.post(
                f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
                json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True})
        return r.status_code == 200
    except Exception as exc:
        log.warning("telegram send failed: %s", type(exc).__name__)
        return False


async def send_slack(webhook_url: str, text: str) -> bool:
    if not valid_slack_webhook(webhook_url or ""):
        return False
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.post(webhook_url, json={"text": text})
        return r.status_code == 200
    except Exception as exc:
        log.warning("slack send failed: %s", type(exc).__name__)
        return False
