"""Pipeline: Orchestration من الإدخال للنتيجة (قلب الـ Backend)."""
import hashlib
import json
import time
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.analysis.classifier import classify
from app.analysis.domain_intel import gather_domain_intel
from app.analysis.email_headers import email_findings, header_checks, parse_eml
from app.analysis.normalize import (defang, extract_urls, is_private_host, normalize_url)
from app.analysis.sms_text import extract_sms_features, sms_findings, is_arabic_sms, sms_context_findings
from app.analysis.url_features import extract_url_features, static_url_findings
from app.engine import ml_client
from app.engine.risk import decide, score_findings, severity_of
from app.engine.threat_types import classify_threat
from app.intel.providers import gather_threat_intel, ti_findings
import logging
log = logging.getLogger(__name__)
from app.integrations.n8n import send_alert_event
from app.models import (Analysis, AnalysisEvidence, EvidenceSource, EvidenceState,
                        Ioc, IocType, MessageInbox, ScanStatus, ScanType, Verdict,
                        audit)

DANGEROUS = {Verdict.SUSPICIOUS, Verdict.HIGH_RISK, Verdict.MALICIOUS}


def _hash(data: dict) -> bytes:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).digest()


def _add_evidence(db: Session, analysis_id, source, provider, etype, state, data, weight=0):
    db.add(AnalysisEvidence(
        analysis_id=analysis_id, source=source, provider=provider,
        evidence_type=etype, state=state, data=data, weight=weight,
        content_hash=_hash(data)))


async def run_analysis(db: Session, analysis: Analysis) -> Analysis:
    start = time.perf_counter()
    analysis.status = ScanStatus.processing
    db.flush()
    content = analysis.raw_input
    itype = analysis.input_type or classify(content)
    analysis.input_type = itype
    findings: list[dict] = []
    evidence_rows: list[dict] = []
    urls: list[str] = []
    iocs: list[dict] = []

    try:
        # ---------- Classification + static analysis ----------
        if itype in (ScanType.url, ScanType.qr):
            normalized = normalize_url(content)
            urls = [normalized]
            analysis.normalized_input = normalized
            feats = extract_url_features(normalized)
            findings += static_url_findings(normalized, feats)
            _add_evidence(db, analysis.id, EvidenceSource.static_analysis, "static",
                          "url_lexical_features", EvidenceState.confirmed, feats)
            host_private = is_private_host(normalized.split("/")[2])
            if host_private:
                findings.append({"rule": "PRIVATE_HOST",
                                 "detail": "اللينك بيشاور على عنوان داخلي/خاص", "weight": 60})

        elif itype == ScanType.sms:
            urls = [normalize_url(u) for u in extract_urls(content) if _safe_url(u)]
            analysis.normalized_input = content[:2000]
            feats = extract_sms_features(content, urls)
            findings += sms_findings(feats)
            _add_evidence(db, analysis.id, EvidenceSource.static_analysis, "static",
                          "sms_text_features", EvidenceState.confirmed, feats)
            for u in urls:
                ufeats = extract_url_features(u)
                findings += static_url_findings(u, ufeats)

        elif itype == ScanType.email:
            msg = parse_eml(content)
            checks = header_checks(msg)
            findings += email_findings(checks)
            _add_evidence(db, analysis.id, EvidenceSource.static_analysis, "static",
                          "email_headers", EvidenceState.confirmed, checks)
            body = msg.get_body(preferencelist=("plain",))
            text = body.get_content() if body else ""
            urls = [normalize_url(u) for u in extract_urls(text) if _safe_url(u)]
            analysis.normalized_input = (msg.get("Subject") or "")[:500]
            for u in urls:
                findings += static_url_findings(u, extract_url_features(u))

        analysis.redirect_chain = urls  # redirect resolution بيتضاف مع الـ sandbox لاحقاً

        # ---------- Domain intelligence (URL inputs) ----------
        if urls and itype in (ScanType.url, ScanType.qr, ScanType.sms, ScanType.email):
            dinfo = await gather_domain_intel(urls[0], timeout=8.0)
            findings += dinfo["findings"]
            _add_evidence(db, analysis.id, EvidenceSource.static_analysis, "rdap_dns",
                          "domain_intel",
                          EvidenceState.confirmed if not dinfo["dns"].get("error")
                          else EvidenceState.inconclusive,
                          {"dns": dinfo["dns"], "rdap": dinfo["rdap"]})

        if itype == ScanType.sms:
            findings += sms_context_findings(content, urls, findings)

        # ---------- Threat intelligence ----------
        if urls:
            ti_results = await gather_threat_intel(db, urls)
            for res in ti_results:
                _add_evidence(db, analysis.id, EvidenceSource.threat_intel,
                              res["provider"], "ti_lookup",
                              EvidenceState(res["state"]), res)
                evidence_rows.append({"source": "threat_intel", "state": res["state"],
                                      "verdict": res.get("verdict")})
            findings += ti_findings(ti_results)

        # ---------- ML ----------
        if itype in (ScanType.url, ScanType.qr) and urls:
            ml_ev = ml_client.predict(db, analysis.id, ScanType.url,
                                      extract_url_features(urls[0]))
        elif itype == ScanType.sms:
            if is_arabic_sms(content):
                # sms_xgb is trained on English text. It is not calibrated for Arabic.
                # Score embedded URLs with the URL model; never let the English SMS
                # model alone label a normal Arabic message as malicious.
                if urls:
                    ml_ev = ml_client.predict(db, analysis.id, ScanType.url, extract_url_features(urls[0]))
                    ml_ev["data"]["context"] = "arabic_sms_url_model"
                else:
                    ml_ev = {"source": "ml_model", "provider": "ml", "evidence_type": "ml_prediction",
                             "state": "unavailable", "data": {"reason": "unsupported_sms_language", "language": "ar"}}
            else:
                ml_ev = ml_client.predict(db, analysis.id, ScanType.sms, feats)
        else:
            ml_ev = None
        if ml_ev:
            _add_evidence(db, analysis.id, EvidenceSource.ml_model, "ml",
                          "ml_prediction", EvidenceState(ml_ev["state"]), ml_ev["data"])
            evidence_rows.append({"source": "ml_model", "state": ml_ev["state"],
                                  "verdict": None})
            mf = ml_client.ml_finding(ml_ev)
            if mf:
                findings.append(mf)

        # ---------- Decision ----------
        score = score_findings(findings)
        verdict, explanation, actions = decide(score, findings, evidence_rows)
        ttext = analysis.normalized_input or content
        tfeats = feats if itype == ScanType.sms else (extract_url_features(urls[0]) if urls else {})
        analysis.threat_type = classify_threat(itype, verdict, findings, ttext, tfeats)
        analysis.risk_score = score
        analysis.severity = severity_of(score)
        analysis.verdict = verdict
        analysis.findings = findings
        analysis.explanation = explanation
        analysis.recommended_action = actions[0] if actions else None
        analysis.status = ScanStatus.done
        analysis.completed_at = datetime.now(timezone.utc)
        analysis.processing_ms = int((time.perf_counter() - start) * 1000)

        # ---------- IOCs (defanged دايماً) ----------
        for u in urls:
            iocs.append({"type": IocType.url.value, "value": defang(u)})
        analysis.iocs = iocs
        for ioc in iocs:
            db.add(Ioc(analysis_id=analysis.id, type=IocType(ioc["type"]), value=ioc["value"]))

        # ---------- SOC alert للمستخدم + n8n ----------
        if verdict in DANGEROUS and analysis.user_id:
            titles = {Verdict.SUSPICIOUS: "⚠️ تحذير: محتوى مشبوه",
                      Verdict.HIGH_RISK: "🔴 خطر: الأرجح تصيد",
                      Verdict.MALICIOUS: "🔴 خطر مؤكد: محتوى خبيث"}
            db.add(MessageInbox(
                user_id=analysis.user_id, alert_id=analysis.id,
                title=titles[verdict], body=explanation, severity=analysis.severity))
        audit(db, "analyze", user_id=analysis.user_id, entity="analyses",
              entity_id=str(analysis.id), verdict=verdict.value, score=score)

    except ValueError as exc:  # input validation / normalization failures
        analysis.status = ScanStatus.failed
        analysis.error_message = str(exc)[:500]
        analysis.verdict = Verdict.INSUFFICIENT_DATA
        analysis.explanation = "المدخل غير صالح أو غير مدعوم."
    except Exception as exc:  # أي فشل غير متوقع: مش بنعتبر الرابط آمن
        analysis.status = ScanStatus.failed
        analysis.error_message = type(exc).__name__
        analysis.verdict = Verdict.INSUFFICIENT_DATA
        analysis.explanation = "حصلت مشكلة أثناء الفحص. اعتبر الرابط مشبوه لحد ما نراجع."

    db.flush()

    # n8n event بعد اكتمال التحليل (automation فقط، مش بيقرر)
    if analysis.status == ScanStatus.done:
        prefs = None
        try:
            from app.engine.alerts import dispatch, get_prefs
            prefs = get_prefs(db, analysis.user_id)
            await dispatch(db, analysis)
        except Exception as exc:  # التنبيهات مش بتكسر التحليل
            log.warning("alert dispatch failed: %s", type(exc).__name__)
        n8n_on = prefs is None or prefs.n8n_enabled
        over = prefs is not None and (analysis.risk_score or 0) >= prefs.threshold
        if n8n_on and (analysis.verdict in DANGEROUS or over):
            await send_alert_event(analysis, prefs.threshold if prefs else None)
    return analysis


def _safe_url(u: str) -> bool:
    try:
        normalize_url(u)
        return True
    except ValueError:
        return False
