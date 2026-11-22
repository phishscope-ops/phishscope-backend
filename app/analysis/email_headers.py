"""Email analysis: headers (SPF/DKIM/DMARC) + mismatch checks. المرفقات مبتتفتحش أبداً."""
import email
import email.policy
import re
from email.message import Message


def parse_eml(raw: str) -> Message:
    return email.message_from_string(raw, policy=email.policy.default)


def header_checks(msg: Message) -> dict:
    auth = (msg.get("Authentication-Results") or "").lower()

    def spf():
        m = re.search(r"spf=(pass|fail|softfail|none)", auth)
        return m.group(1) if m else "unknown"

    def dkim():
        m = re.search(r"dkim=(pass|fail|none)", auth)
        return m.group(1) if m else "unknown"

    def dmarc():
        m = re.search(r"dmarc=(pass|fail|none)", auth)
        return m.group(1) if m else "unknown"

    from_addr = msg.get("From") or ""
    reply_to = msg.get("Reply-To") or ""

    def domain_of(header: str) -> str:
        m = re.search(r"@([\w.-]+)", header)
        return m.group(1).lower() if m else ""

    from_dom, reply_dom = domain_of(from_addr), domain_of(reply_to)
    display = re.sub(r"<[^>]+>", "", from_addr).strip().strip('"')
    return {
        "from": from_addr, "reply_to": reply_to, "subject": msg.get("Subject") or "",
        "spf": spf(), "dkim": dkim(), "dmarc": dmarc(),
        "from_domain": from_dom, "reply_to_domain": reply_dom,
        "reply_to_mismatch": bool(reply_dom and from_dom and reply_dom != from_dom),
        "display_name_has_email": bool(re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", display)),
        "attachment_count": sum(1 for part in msg.walk()
                                if part.get_content_disposition() == "attachment"),
    }


def email_findings(checks: dict) -> list[dict]:
    findings = []

    def add(rule, detail, weight):
        findings.append({"rule": rule, "detail": detail, "weight": weight})

    if checks["spf"] in ("fail", "softfail"):
        add("SPF_FAIL", f"نتيجة SPF: {checks['spf']}", 35)
    if checks["dkim"] == "fail":
        add("DKIM_FAIL", "توقيع DKIM فشل", 35)
    if checks["dmarc"] == "fail":
        add("DMARC_FAIL", "فحص DMARC فشل", 40)
    if checks["reply_to_mismatch"]:
        add("REPLY_TO_MISMATCH", f"الرد بيروح لدومين مختلف ({checks['reply_to_domain']})", 30)
    if checks["display_name_has_email"]:
        add("DISPLAY_NAME_SPOOF", "الاسم المعروض فيه إيميل مختلف (محاولة تقليد)", 20)
    return findings
