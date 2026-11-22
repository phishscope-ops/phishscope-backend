"""Normalization + Defanging + SSRF guards (متطلبات 4, 10, 13)."""
import ipaddress
import re
from urllib.parse import urlparse, urlunparse

ALLOWED_SCHEMES = {"http", "https"}
MAX_INPUT_LEN = 20_000


def defang(value: str) -> str:
    """أي URL/IOC يتخزن أو يتعرض لازم يكون defanged وغير قابل للضغط."""
    value = re.sub(r"(?i)^https?://", lambda m: "hxxps://" if "s" in m.group(0).lower() else "hxxp://", value)
    return value.replace(".", "[.]")


def refang(value: str) -> str:
    value = value.replace("[.]", ".")
    return re.sub(r"(?i)^hxxp(s?)://", lambda m: f"http{m.group(1).lower()}://", value)


def normalize_url(url: str) -> str:
    url = refang(url.strip())
    parsed = urlparse(url if "://" in url else f"http://{url}")
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Scheme '{scheme}' not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("URL has no host")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    # نشيل الـ fragment ونرتب: scheme://host[:port]/path?query
    return urlunparse((scheme, host + port, path, "", parsed.query, ""))


def is_private_host(host: str) -> bool:
    """SSRF Protection (متطلب 10): رفض العناوين الداخلية والخاصة."""
    host = host.strip("[]").lower()
    if host in {"localhost"} or host.endswith((".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return False  # دومين عادي، الـ DNS resolution بيتحقق منه في domain_intel


def extract_urls(text: str) -> list[str]:
    pattern = re.compile(r"(?i)\b(?:https?://|hxxps?://|www\.)[^\s<>\"']+")
    found = pattern.findall(text)
    bare = re.findall(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|xyz|top|info|biz|me|eg|sa|ae)(?:/[^\s<>\"']*)?", text)
    out, seen = [], set()
    for u in found + bare:
        u = u.rstrip(".,);]")
        key = refang(u).lower()
        if key not in seen:
            seen.add(key)
            out.append(u)
    return out[:20]  # حد أقصى للينكات في الرسالة الواحدة
