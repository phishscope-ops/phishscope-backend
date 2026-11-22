"""URL lexical features (~35 feature) - من غير فتح الصفحة أبداً (مبدأ SSRF)."""
import math
import re
from urllib.parse import urlparse

import tldextract

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "link", "live", "country", "kim", "work", "gq", "tk", "ml", "cf", "ga"}
BRAND_KEYWORDS = ["paypal", "facebook", "instagram", "whatsapp", "telegram", "apple", "icloud", "microsoft",
                  "office365", "outlook", "google", "amazon", "netflix", "bank", "vodafone", "orange", "etisalat",
                  "we.eg", "nbe", "cbe", "banquemisr", "fawry", "instapay", "poste"]
SUSPICIOUS_WORDS = ["login", "verify", "verification", "secure", "account", "update", "confirm", "suspend",
                    "unlock", "billing", "wallet", "bonus", "winner", "prize", "gift", "free", "claim",
                    "support", "security", "alert", "refund"]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    labels = host.split(".")

    feats = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(parsed.path or ""),
        "num_dots_host": host.count("."),
        "num_subdomains": max(len(labels) - 2, 0),
        "num_params": len(parsed.query.split("&")) if parsed.query else 0,
        "num_digits": sum(c.isdigit() for c in url),
        "digit_ratio": round(sum(c.isdigit() for c in url) / max(len(url), 1), 4),
        "num_hyphens_host": host.count("-"),
        "has_at_symbol": int("@" in url),
        "has_double_slash_redirect": int("//" in (parsed.path or "")),
        "has_ip_host": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "is_punycode": int("xn--" in host),
        "has_port": int(parsed.port is not None and parsed.port not in (80, 443)),
        "uses_https": int(parsed.scheme == "https"),
        "host_entropy": round(_entropy(ext.domain), 4),
        "path_entropy": round(_entropy(parsed.path or ""), 4),
        "pct_encoded": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
        "non_ascii": int(any(ord(c) > 127 for c in url)),
        "is_shortener": int(domain in SHORTENERS),
        "suspicious_tld": int(ext.suffix.lower() in SUSPICIOUS_TLDS),
        "tld_length": len(ext.suffix),
        "url_depth": len([p for p in (parsed.path or "").split("/") if p]),
    }
    host_and_path = (host + " " + path_q).lower()
    for kw in BRAND_KEYWORDS:
        feats[f"brand_{kw.replace('.', '_')}"] = int(kw in host_and_path)
    for w in SUSPICIOUS_WORDS:
        feats[f"word_{w}"] = int(w in host_and_path)
    # علامة مهمة: اسم براند في ساب دومين مش في الدومين الأساسي
    feats["brand_in_subdomain_not_domain"] = int(
        any(kw in host and kw not in domain for kw in BRAND_KEYWORDS))
    return feats


def static_url_findings(url: str, feats: dict) -> list[dict]:
    """Findings deterministic من الـ static analysis (قواعد مكتوبة وقابلة للمراجعة)."""
    findings = []

    def add(rule, detail, weight):
        findings.append({"rule": rule, "detail": detail, "weight": weight})

    if feats["has_ip_host"]:
        add("IP_HOST", "اللينك بيستخدم IP بدل اسم دومين", 35)
    if feats["has_at_symbol"]:
        add("AT_SYMBOL", "وجود @ في اللينك بيخفي الوجهة الحقيقية", 30)
    if feats["brand_in_subdomain_not_domain"]:
        add("BRAND_SPOOF", "اسم براند معروف في subdomain مش في الدومين الأساسي", 40)
    if feats["is_punycode"]:
        add("PUNYCODE", "دومين punycode ممكن يقلد حروف مواقع حقيقية", 30)
    if feats["is_shortener"]:
        add("SHORTENER", "خدمة اختصار روابط بتخفي الوجهة", 15)
    if feats["suspicious_tld"]:
        add("SUSPICIOUS_TLD", "امتداد دومين كتير بيستخدم في التصيد", 15)
    if feats["url_length"] > 100:
        add("LONG_URL", f"طول اللينك غير معتاد ({feats['url_length']} حرف)", 10)
    if feats["num_subdomains"] >= 3:
        add("DEEP_SUBDOMAINS", f"{feats['num_subdomains']} subdomains", 10)
    if feats["host_entropy"] > 4.2:
        add("HIGH_ENTROPY_HOST", "اسم الدومين عشوائي الشكل (DGA-like)", 20)
    if feats["word_verify"] or feats["word_suspend"] or feats["word_confirm"]:
        add("URGENCY_WORDS", "كلمات تصيد شائعة في اللينك (verify/suspend/confirm)", 10)
    return findings
