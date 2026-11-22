"""Threat type classification: نوع التهديد بالضبط + سبب عربي واضح.

بيكمّل الـ verdict: الحكم يقول "خطير قد إيه"، وده يقول "نوعه إيه".
"""
from app.models import ScanType, Verdict

TYPES = {
    "credential_phishing": "تصيّد بيانات حسابات/بطاقات",
    "prize_scam": "احتيال جوائز وأرباح وهمية",
    "delivery_scam": "احتيال شحنات وجمارك",
    "otp_fraud": "احتيال رموز التحقق (OTP)",
    "investment_scam": "احتيال استثمار/عملات",
    "malware_link": "رابط خبيث/ملغّم",
    "spam_ad": "إعلانات مزعجة (سبام)",
    "smishing": "تصيّد عبر الرسائل النصية",
    "suspicious_generic": "محتوى مشبوه",
    "benign": "محتوى سليم",
}

_PRIZE = ("كسبت", "جايزة", "جائزة", "مبروك", "ربحت", "فائز", "winner", "prize", "congratulations", "won")
_DELIVERY = ("شحنة", "شحنه", "طرد", "جمارك", "بريد", "ارامكس", "أرامكس", "customs", "package", "delivery", "shipment", "parcel")
_OTP = ("رمز", "كود التحقق", "رمز التحقق", "otp", "verification code", "كود")
_CRED = ("حسابك", "بياناتك", "بطاقة", "فيزا", "كارت", "محفظة", "بنك", "مصرف", "verify", "account", "password", "billing", "login", "تسجيل الدخول", "فودافون كاش", "انستاباي", "انستا باي")
_INVEST = ("استثمار", "استثمر", "عملات", "بيتكوين", "كريبتو", "bitcoin", "crypto", "invest", "trading", "فوركس")
_PROMO = ("عرض", "خصم", "تخفيض", "اشترك", "مجانا", "مجاناً", "offer", "discount", "subscribe", "sale", "برومو")


def classify_threat(itype: ScanType, verdict: Verdict, findings: list[dict],
                    text: str, feats: dict | None) -> str:
    """بيرجع مفتاح نوع التهديد من TYPES."""
    if verdict in (Verdict.SAFE, Verdict.LOW_RISK):
        return "benign"
    lower = (text or "").lower()
    rules = {f.get("rule") for f in findings}
    feats = feats or {}

    if rules & {"TI_VIRUSTOTAL_MALICIOUS", "TI_SAFE_BROWSING_MALICIOUS", "TI_URLHAUS_MALICIOUS"}:
        return "malware_link"
    hits = lambda words: sum(1 for w in words if w in lower or w in (text or ""))

    if hits(_OTP) and feats.get("num_urls", 0) == 0:
        return "otp_fraud"
    if hits(_DELIVERY):
        return "delivery_scam"
    if hits(_PRIZE):
        return "prize_scam"
    if hits(_INVEST):
        return "investment_scam"
    if hits(_CRED):
        return "credential_phishing"
    if verdict in (Verdict.SUSPICIOUS,) and hits(_PROMO) and not hits(_URGENT_HINTS):
        return "spam_ad"
    if itype == ScanType.sms:
        return "smishing"
    return "suspicious_generic"


_URGENT_HINTS = ("عاجل", "فورا", "فوراً", "urgent", "suspended", "locked", "اتوقف", "محظور")


def threat_label(key: str) -> str:
    return TYPES.get(key, TYPES["suspicious_generic"])
