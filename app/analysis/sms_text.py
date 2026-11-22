"""SMS analysis: features + findings (عربي + إنجليزي)."""
import re

URGENCY_AR = ["فورا", "فوراً", "عاجل", "حسابك", "اتوقف", "موقوف", "محظور", "كسبت", "جايزة", "جائزة",
              "مبروك", "رصيد", "شحن", "اضغط", "ادخل", "سجل", "فعّل", "تفعيل", "تحديث", "بياناتك",
              "منحة", "دعم", "استلام", "حوالة", "تحويل", "فودافون", "انستا باي", "انستاباي"]
URGENCY_EN = ["urgent", "verify", "suspended", "locked", "account", "winner", "prize", "congratulations",
              "claim", "free", "click", "confirm", "update", "billing", "refund", "password", "expire"]
PHONE_RE = re.compile(r"(?:\+?\d[\d\s-]{7,}\d)")


def extract_sms_features(text: str, urls: list[str]) -> dict:
    lower = text.lower()
    return {
        "length": len(text),
        "num_urls": len(urls),
        "has_shortener": int(any(any(s in u for s in ("bit.ly", "t.co", "tinyurl", "cutt.ly")) for u in urls)),
        "caps_ratio": round(sum(c.isupper() for c in text) / max(sum(c.isalpha() for c in text), 1), 4),
        "has_phone": int(bool(PHONE_RE.search(text))),
        "urgency_ar_hits": sum(1 for w in URGENCY_AR if w in text),
        "urgency_en_hits": sum(1 for w in URGENCY_EN if w in lower),
        "has_currency": int(bool(re.search(r"(جنيه|ج\.م|egp|\$|usd|euro|يورو)", lower))),
        "num_exclaim": text.count("!"),
    }


def sms_findings(feats: dict) -> list[dict]:
    findings = []

    def add(rule, detail, weight):
        findings.append({"rule": rule, "detail": detail, "weight": weight})

    total_urgency = feats["urgency_ar_hits"] + feats["urgency_en_hits"]
    if total_urgency >= 3:
        add("SMS_URGENCY", f"{total_urgency} كلمة استعجال/تخويف في الرسالة", 25)
    elif total_urgency >= 1 and feats["num_urls"] > 0:
        add("SMS_URGENCY_LINK", "كلمات استعجال مع لينك في نفس الرسالة", 15)
    if feats["has_shortener"]:
        add("SMS_SHORTENER", "لينك مختصر جوه رسالة", 15)
    if feats["has_phone"] and feats["num_urls"] > 0:
        add("SMS_PHONE_AND_LINK", "رقم تليفون ولينك في نفس الرسالة", 10)
    if feats["has_currency"] and feats["num_urls"] > 0:
        add("SMS_MONEY_LINK", "مبلغ مالي مع لينك", 10)
    return findings
