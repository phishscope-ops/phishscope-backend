"""Classification: التطبيق بيعرف نوع الإدخال لوحده (URL / Email / SMS / QR data)."""
import re

from app.models import ScanType
from .normalize import extract_urls

_EMAIL_FULL = re.compile(r"(?im)^(from|subject|received|to|reply-to):", re.MULTILINE)


def classify(content: str) -> ScanType:
    stripped = content.strip()
    # إيميل خام (.eml): فيه headers
    if len(_EMAIL_FULL.findall(stripped)) >= 2:
        return ScanType.email
    # URL واحد بس
    urls = extract_urls(stripped)
    if urls and refang_single(stripped) == refang_single(urls[0]):
        return ScanType.url
    # نص فيه لينكات أو نص رسالة
    return ScanType.sms


def refang_single(s: str) -> str:
    return s.replace("[.]", ".").lower().replace("hxxps://", "https://").replace("hxxp://", "http://")
