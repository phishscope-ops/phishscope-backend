"""Major platforms whose own hosts should not be flagged by the lexical URL model.

Scope is deliberately small and exact: a host qualifies only if it IS one of these
domains or a subdomain of one, over https, with no userinfo. User-content and
generic hosting domains (google docs/sites, github.io, blogspot, firebase, ...) are
NOT listed. Redirector links (l.instagram.com, l.facebook.com, t.co, ...) only
qualify when the target they carry is also on a listed platform.
The discount applies to the ML (URL lexical model) finding only; threat-intel and
every other rule still apply in full.
"""
from urllib.parse import parse_qsl, unquote, urlparse

TRUSTED_PLATFORMS = (
    "instagram.com", "cdninstagram.com", "instagr.am",
    "youtube.com", "youtu.be", "ytimg.com",
    "facebook.com", "fb.watch", "fbcdn.net", "fb.com",
    "tiktok.com", "tiktokv.com",
    "x.com", "twitter.com", "t.co",
    "whatsapp.com", "wa.me", "whatsapp.net",
)


def _platform_of(host: str) -> str | None:
    host = host.lower().rstrip(".")
    for d in TRUSTED_PLATFORMS:
        if host == d or host.endswith("." + d):
            return d
    return None


def _embedded_urls(parsed) -> list[str]:
    out = []
    for _, v in parse_qsl(parsed.query + "&" + parsed.fragment, keep_blank_values=True):
        v = unquote(v)
        if v.startswith(("http://", "https://", "//")) or "://" in v:
            out.append(v if "://" in v else "https:" + v)
    return out


def trusted_platform(url: str) -> str | None:
    """Return the matched platform domain, or None if the URL must be scored normally."""
    try:
        p = urlparse(url)
    except ValueError:
        return None
    if p.scheme != "https" or "@" in p.netloc or not p.hostname:
        return None
    plat = _platform_of(p.hostname)
    if not plat:
        return None
    for target in _embedded_urls(p):
        try:
            th = urlparse(target).hostname or ""
        except ValueError:
            return None
        if not _platform_of(th):
            return None  # redirector/continue= carrying a foreign target: no discount
    return plat
