"""Threat Intelligence providers (كلها مجانية) + cache بـ TTL.

قواعد ثابتة (متطلبات 27/28):
- تعطل أي provider أو غياب نتيجته ≠ الرابط آمن → state = unavailable/inconclusive.
- كل lookup بيتكاش في threat_intel_cache عشان نحترم الكوتا المجانية
  (VirusTotal 500/يوم، urlscan 50 private/يوم).
- Timeout لكل provider من settings.http_timeout_seconds.
"""
import base64
import hashlib
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import IocType, ThreatIntelCache, Verdict


def _cache_key(provider: str, indicator: str) -> str:
    return hashlib.sha256(indicator.lower().encode()).hexdigest()


def _from_cache(db: Session, provider: str, indicator: str) -> dict | None:
    row = db.get(ThreatIntelCache, (provider, _cache_key(provider, indicator)))
    if row and row.expires_at > datetime.now(timezone.utc).replace(tzinfo=row.expires_at.tzinfo):
        return {"provider": provider, "verdict": row.verdict.value if row.verdict else None,
                "data": row.raw or {}, "state": "confirmed", "cached": True}
    return None


def _to_cache(db: Session, provider: str, indicator: str, ioc_type: IocType,
              verdict: Verdict | None, raw: dict) -> None:
    key = _cache_key(provider, indicator)
    now = datetime.now(timezone.utc)
    row = db.get(ThreatIntelCache, (provider, key)) or ThreatIntelCache(
        provider=provider, indicator=key, indicator_type=ioc_type)
    row.verdict = verdict
    row.raw = raw
    row.fetched_at = now
    row.expires_at = now + timedelta(hours=settings.ti_cache_ttl_hours)
    db.merge(row)


def _unavailable(provider: str, reason: str) -> dict:
    return {"provider": provider, "verdict": None, "data": {"reason": reason},
            "state": "unavailable"}


async def check_phishtank(client: httpx.AsyncClient, db: Session, url: str) -> dict:
    """PhishTank check-url API (مجاني بمفتاح تطبيق)."""
    p = "phishtank"
    if not settings.phishtank_app_key:
        return _unavailable(p, "no_api_key")
    if (hit := _from_cache(db, p, url)):
        return hit
    try:
        r = await client.post("https://checkurl.phishtank.com/checkurl/",
                              data={"url": url, "format": "json",
                                    "app_key": settings.phishtank_app_key},
                              headers={"User-Agent": "phishtank/phishscope"})
        r.raise_for_status()
        res = r.json()["results"]
        in_db, verified = res.get("in_database"), res.get("verified") == "y"
        verdict = Verdict.MALICIOUS if (in_db and verified) else (
            Verdict.SUSPICIOUS if in_db else Verdict.SAFE)
        out = {"provider": p, "verdict": verdict.value, "data": res, "state": "confirmed"}
        _to_cache(db, p, url, IocType.url, verdict, res)
        return out
    except Exception as exc:
        return _unavailable(p, type(exc).__name__)


async def check_urlhaus(client: httpx.AsyncClient, db: Session, url: str) -> dict:
    """URLhaus Community API (مجاني بـ Auth-Key)."""
    p = "urlhaus"
    if not settings.urlhaus_auth_key:
        return _unavailable(p, "no_api_key")
    if (hit := _from_cache(db, p, url)):
        return hit
    try:
        r = await client.post("https://urlhaus-api.abuse.ch/v1/url/",
                              data={"url": url},
                              headers={"Auth-Key": settings.urlhaus_auth_key})
        r.raise_for_status()
        res = r.json()
        listed = res.get("query_status") == "ok"
        verdict = Verdict.MALICIOUS if listed else Verdict.SAFE
        data = {k: res.get(k) for k in ("query_status", "threat", "tags", "date_added")}
        out = {"provider": p, "verdict": verdict.value, "data": data, "state": "confirmed"}
        _to_cache(db, p, url, IocType.url, verdict, data)
        return out
    except Exception as exc:
        return _unavailable(p, type(exc).__name__)


async def check_safe_browsing(client: httpx.AsyncClient, db: Session, url: str) -> dict:
    """Google Safe Browsing Lookup API v4 (كوتا مجانية لكل مشروع)."""
    p = "safe_browsing"
    if not settings.safe_browsing_api_key:
        return _unavailable(p, "no_api_key")
    if (hit := _from_cache(db, p, url)):
        return hit
    try:
        body = {"client": {"clientId": "phishscope", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]}}
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.safe_browsing_api_key}",
            json=body)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        verdict = Verdict.MALICIOUS if matches else Verdict.SAFE
        data = {"matches": [m.get("threatType") for m in matches]}
        out = {"provider": p, "verdict": verdict.value, "data": data, "state": "confirmed"}
        _to_cache(db, p, url, IocType.url, verdict, data)
        return out
    except Exception as exc:
        return _unavailable(p, type(exc).__name__)


async def check_urlscan(client: httpx.AsyncClient, db: Session, url: str) -> dict:
    """urlscan.io search (من غير submit: الـ search مجاني وبيكفي لو الرابط اتفحص قبل كده)."""
    p = "urlscan"
    if (hit := _from_cache(db, p, url)) and hit.get("data", {}).get("verdict_source") == "result_api":
        return hit
    try:
        headers = {"API-Key": settings.urlscan_api_key} if settings.urlscan_api_key else {}
        r = await client.get("https://urlscan.io/api/v1/search/",
                             params={"q": f'page.url:"{url}"', "size": 1}, headers=headers)
        r.raise_for_status()
        results = r.json().get("results", [])
        if not results:
            return {"provider": p, "verdict": None, "data": {"reason": "no_prior_scan"},
                    "state": "inconclusive"}  # مفيش فحص سابق ≠ آمن
        # Search results contain scan metadata, not the verdict. Read the result API.
        import uuid
        scan_id = str(uuid.UUID(results[0]["_id"]))
        detail = await client.get(f"https://urlscan.io/api/v1/result/{scan_id}/", headers=headers)
        detail.raise_for_status()
        verdicts = detail.json().get("verdicts", {}).get("overall", {})
        if "malicious" not in verdicts:
            return {"provider": p, "verdict": None, "data": {"reason": "no_verdict"},
                    "state": "inconclusive"}
        malicious = verdicts["malicious"]
        score = verdicts.get("score", 0)
        verdict = Verdict.MALICIOUS if malicious else (Verdict.SUSPICIOUS if score >= 50 else Verdict.SAFE)
        data = {"score": score, "malicious": malicious, "tags": verdicts.get("tags", []),
                "verdict_source": "result_api"}
        out = {"provider": p, "verdict": verdict.value, "data": data, "state": "confirmed"}
        _to_cache(db, p, url, IocType.url, verdict, data)
        return out
    except Exception as exc:
        return _unavailable(p, type(exc).__name__)


async def check_virustotal(client: httpx.AsyncClient, db: Session, url: str) -> dict:
    """VirusTotal Public API: 500 طلب/يوم و4/دقيقة - آخر provider في السلسلة."""
    p = "virustotal"
    if not settings.virustotal_api_key:
        return _unavailable(p, "no_api_key")
    if (hit := _from_cache(db, p, url)):
        return hit
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": settings.virustotal_api_key})
        if r.status_code == 404:
            return {"provider": p, "verdict": None, "data": {"reason": "unknown_url"},
                    "state": "inconclusive"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        verdict = Verdict.MALICIOUS if mal >= 3 else (
            Verdict.SUSPICIOUS if (mal >= 1 or sus >= 3) else Verdict.SAFE)
        data = {"stats": stats, "engines_flagging": mal + sus}
        out = {"provider": p, "verdict": verdict.value, "data": data, "state": "confirmed"}
        _to_cache(db, p, url, IocType.url, verdict, data)
        return out
    except Exception as exc:
        return _unavailable(p, type(exc).__name__)


# الترتيب من الأرخص للأغلى كوتا
PROVIDERS = [check_phishtank, check_urlhaus, check_safe_browsing, check_urlscan, check_virustotal]


async def gather_threat_intel(db: Session, urls: list[str]) -> list[dict]:
    """فحص كل اللينكات (حد 5 للفحص الواحد) على كل الـ providers المتاحة."""
    import asyncio
    evidence = []
    async with httpx.AsyncClient(timeout=settings.http_timeout_seconds) as client:
        for url in urls[:5]:
            results = await asyncio.gather(*[p(client, db, url) for p in PROVIDERS])
            for res in results:
                res["indicator"] = url
            evidence.extend(results)
    return evidence


def ti_findings(results: list[dict]) -> list[dict]:
    """تحويل نتايج الـ providers لـ Findings. الوزن حسب قوة المصدر."""
    weight_by_provider = {"virustotal": 45, "safe_browsing": 40, "urlhaus": 40,
                          "phishtank": 35, "urlscan": 30}
    findings = []
    for res in results:
        if res.get("state") != "confirmed" or not res.get("verdict"):
            continue
        if res["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            w = weight_by_provider.get(res["provider"], 25)
            if res["verdict"] == "SUSPICIOUS":
                w = max(w - 15, 10)
            findings.append({
                "rule": f"TI_{res['provider'].upper()}_{res['verdict']}",
                "detail": f"{res['provider']} صنّف الرابط كـ {res['verdict']}",
                "weight": w})
    return findings
