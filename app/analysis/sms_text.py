"""SMS analysis: features + findings (عربي + إنجليزي)."""
import json
import re
from pathlib import Path

import tldextract

_VOCAB: list[str] | None = None
_KNOWN: list[str] | None = None
_TOKEN_RE = re.compile(r"\w+")


def _load_vocab() -> list[str]:
    """TF-IDF vocab for sms_xgb >= 4.0.0. Missing file -> base features only."""
    global _VOCAB
    if _VOCAB is None:
        path = Path(__file__).resolve().parents[2] / "models" / "sms_tfidf_vocab.json"
        try:
            _VOCAB = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            _VOCAB = []
    return _VOCAB


def _load_known_domains() -> list[str]:
    """Well-known registered domains for sms_xgb >= 4.3.0. Missing file -> feature always 0."""
    global _KNOWN
    if _KNOWN is None:
        path = Path(__file__).resolve().parents[2] / "models" / "known_domains.json"
        try:
            _KNOWN = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            _KNOWN = []
    return _KNOWN


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    if not ext.suffix:
        return ""
    return f"{ext.domain}.{ext.suffix}".lower()

URGENCY_AR = ["فورا", "فوراً", "عاجل", "حسابك", "اتوقف", "موقوف", "محظور", "كسبت", "جايزة", "جائزة",
              "مبروك", "رصيد", "شحن", "اضغط", "ادخل", "سجل", "فعّل", "تفعيل", "تحديث", "بياناتك",
              "منحة", "دعم", "استلام", "حوالة", "تحويل", "فودافون", "انستا باي", "انستاباي"]
URGENCY_EN = ["urgent", "verify", "suspended", "locked", "account", "winner", "prize", "congratulations",
              "claim", "free", "click", "confirm", "update", "billing", "refund", "password", "expire"]
PHONE_RE = re.compile(r"(?:\+?\d[\d\s-]{7,}\d)")


def extract_sms_features(text: str, urls: list[str]) -> dict:
    lower = text.lower()
    feats = {
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
    vocab = _load_vocab()
    if vocab:
        toks = set(_TOKEN_RE.findall(lower))
        for w in vocab:
            if w in toks:
                feats[f"tok_{w}"] = 1
    known = set(_load_known_domains())
    feats["all_urls_known_domain"] = int(
        bool(urls) and bool(known) and
        all(_registered_domain(u) in known for u in urls))
    return feats


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


def is_arabic_sms(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    arabic = sum("\u0621" <= c <= "\u064a" for c in letters)
    return arabic >= 5 and arabic / max(len(letters), 1) >= 0.2


def sms_context_findings(text: str, urls: list[str], findings: list[dict]) -> list[dict]:
    """A money/prize lure corroborated by an unsafe destination, not keywords alone."""
    prize = any(w in text.lower() for w in ("جائزة", "جايزة", "ربحت", "كسبت", "prize", "winner"))
    money = bool(re.search(r"(جنيه|ج\.م|egp|\$|usd)", text.lower()))
    unsafe = any(f.get("rule") in {"NO_DNS", "SUSPICIOUS_TLD", "BRAND_SPOOF", "IP_HOST", "PUNYCODE"} for f in findings)
    if urls and prize and money and unsafe:
        return [{"rule": "SMS_PRIZE_UNSAFE_DESTINATION", "detail": "وعد بجائزة مالية مع رابط له مؤشرات خطورة مستقلة", "weight": 25}]
    return []
