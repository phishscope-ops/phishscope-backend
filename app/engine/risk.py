"""Risk Engine: Findings → Risk Score → Severity → Verdict (الوحيد اللي بيقرر).

مبادئ من الدليل والمتطلبات:
- HTTPS لوحده مش دليل أمان (مفيش وزن سالب ليه).
- غياب الأدلة → INSUFFICIENT_DATA مش SAFE (متطلب 26).
- أدلة متعارضة → بناخد الأعلى خطورة وبنسجل التعارض (متطلب 24).
- Thresholds مبدئية وهتتعاير على داتا حقيقية.
"""
from app.models import Severity, Verdict

# دليل واحد قوي يكفي يقفل الحكم
HARD_MALICIOUS_RULES = {"TI_VIRUSTOTAL_MALICIOUS", "TI_SAFE_BROWSING_MALICIOUS",
                        "TI_URLHAUS_MALICIOUS", "TI_PHISHTANK_MALICIOUS",
                        "PRIVATE_IP_RESOLVE", "DMARC_FAIL"}

SAFE = "SAFE"
CAP = 100


def score_findings(findings: list[dict]) -> int:
    total = sum(f.get("weight", 0) for f in findings)
    return max(0, min(CAP, total))


def severity_of(score: int) -> Severity:
    if score >= 80:
        return Severity.critical
    if score >= 60:
        return Severity.high
    if score >= 35:
        return Severity.medium
    return Severity.low


def decide(score: int, findings: list[dict], evidence: list[dict]) -> tuple[Verdict, str, list[str]]:
    """بيرجع (verdict, explanation, recommended_actions)."""
    rules = {f.get("rule") for f in findings}

    # 1) Conflicting evidence handling: لو فيه مصدر TI قال SAFE وآخر قال MALICIOUS
    #    بنسجل التعارض وبناخد الأخطر (مش بنرجح الأمان أبداً).
    ti = [e for e in evidence if e.get("source") == "threat_intel"
          and e.get("state") == "confirmed" and e.get("verdict")]
    ti_verdicts = {e["verdict"] for e in ti}
    conflicting = "MALICIOUS" in ti_verdicts and "SAFE" in ti_verdicts
    if conflicting:
        findings.append({"rule": "TI_CONFLICT",
                         "detail": "مصادر Threat Intel متعارضة - تم اعتماد التصنيف الأخطر",
                         "weight": 10})

    # 2) Hard block rules
    if rules & HARD_MALICIOUS_RULES:
        return (Verdict.MALICIOUS,
                "مصدر موثوق أكد إن ده محتوى خبيث. متفتحوش وامسح الرسالة.",
                ["Block", "Report"])

    # 3) بالسكور
    if score >= 80:
        return (Verdict.MALICIOUS,
                "أدلة كتيرة قوية على إن ده تصيد. متتفاعلش معاه خالص.",
                ["Block", "Report"])
    if score >= 60:
        return (Verdict.HIGH_RISK,
                "خطر: ده الأرجح رابط تصيد. متفتحوش ومتدخلش أي بيانات.",
                ["Block with Review"])
    if score >= 35:
        return (Verdict.SUSPICIOUS,
                "مشبوه: فيه علامات غير مطمئنة. متفتحش اللينك ولا تدخل بيانات.",
                ["Manual Review"])

    # 4) Unknown Verdict Handling: أدلة مش كفاية ≠ آمن
    confirmed = [e for e in evidence if e.get("state") == "confirmed"]
    if len(confirmed) < 2:
        return (Verdict.INSUFFICIENT_DATA,
                "مقدرناش نتأكد من مصادر كفاية. اعتبره مشبوه لحد ما تتأكد من المصدر بنفسك.",
                ["Collect More Evidence", "Monitor"])

    if score > 0:
        return (Verdict.LOW_RISK,
                "علامات بسيطة بس مفيش دليل خطر واضح.", ["Monitor"])
    return (Verdict.SAFE,
            "مفيش دليل على خطر. (التطبيق مبيفتحش الصفحة نفسها فمش ضمان 100%)",
            ["Allow"])
