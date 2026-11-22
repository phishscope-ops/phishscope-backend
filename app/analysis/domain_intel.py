"""Domain Intelligence: DNS + RDAP (مجاني بدون مفاتيح) + فحص الـ IP الخاص (SSRF)."""
import asyncio
import ipaddress
import json
from urllib.parse import urlparse

import dns.resolver
import httpx
import tldextract


def _host_of(url: str) -> str:
    return (urlparse(url if "://" in url else f"http://{url}").hostname or "").lower()


async def resolve_host(host: str, timeout: float) -> dict:
    """DNS records + رفض لو الدومين بيحل على IP داخلي/خاص (SSRF Protection)."""
    result = {"host": host, "a_records": [], "has_mx": False, "has_txt": False,
              "resolves_private": False, "error": None}
    loop = asyncio.get_running_loop()

    def _q(rtype):
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            return [str(r) for r in resolver.resolve(host, rtype)]
        except Exception:
            return []

    a, mx, txt = await asyncio.gather(
        loop.run_in_executor(None, _q, "A"),
        loop.run_in_executor(None, _q, "MX"),
        loop.run_in_executor(None, _q, "TXT"),
    )
    result["a_records"] = a[:5]
    result["has_mx"] = bool(mx)
    result["has_txt"] = bool(txt)
    for ip in a:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                result["resolves_private"] = True
        except ValueError:
            pass
    if not a:
        result["error"] = "no_dns"
    return result


async def rdap_domain_age(url: str, timeout: float) -> dict:
    """عمر الدومين من RDAP (rdap.org مجاني). دومين جديد = علامة خطورة."""
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    out = {"domain": domain, "registered_at": None, "age_days": None, "registrar": None, "error": None}
    if not domain or "." not in domain:
        out["error"] = "no_domain"
        return out
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}")
            if r.status_code != 200:
                out["error"] = f"rdap_http_{r.status_code}"
                return out
            data = r.json()
        from datetime import datetime, timezone
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                reg = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                out["registered_at"] = reg.isoformat()
                out["age_days"] = (datetime.now(timezone.utc) - reg).days
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                vcard = ent.get("vcardArray", [None, []])[1]
                for row in vcard:
                    if row and row[0] == "fn":
                        out["registrar"] = row[3]
    except Exception as exc:  # تعطل مصدر خارجي ≠ الرابط آمن
        out["error"] = type(exc).__name__
    return out


def domain_findings(dns_info: dict, rdap_info: dict) -> list[dict]:
    findings = []

    def add(rule, detail, weight):
        findings.append({"rule": rule, "detail": detail, "weight": weight})

    if dns_info.get("resolves_private"):
        add("PRIVATE_IP_RESOLVE", "الدومين بيحل على عنوان داخلي/خاص", 60)
    if dns_info.get("error") == "no_dns":
        add("NO_DNS", "الدومين ملوش سجلات DNS", 25)
    if not dns_info.get("has_mx"):
        add("NO_MX", "الدومين مفيهوش MX (مش بيستقبل إيميلات، شائع في دومينات التصيد)", 5)
    age = rdap_info.get("age_days")
    if age is not None:
        if age < 30:
            add("DOMAIN_VERY_NEW", f"الدومين عمره {age} يوم بس", 35)
        elif age < 180:
            add("DOMAIN_NEW", f"الدومين عمره {age} يوم", 15)
    return findings


async def gather_domain_intel(url: str, timeout: float) -> dict:
    host = _host_of(url)
    dns_info, rdap_info = await asyncio.gather(
        resolve_host(host, timeout), rdap_domain_age(url, timeout))
    return {"dns": dns_info, "rdap": rdap_info,
            "findings": domain_findings(dns_info, rdap_info)}


def domain_as_json(domain_info: dict) -> str:
    return json.dumps(domain_info, ensure_ascii=False, default=str)
