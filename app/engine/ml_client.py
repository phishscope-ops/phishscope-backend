"""ML client: استدعاء الموديل النشط من model_registry مع validation (متطلبات 9, 25).

القواعد:
- الموديل دليل، مش حكم. النتيجة بتتخزن في ml_predictions مع النسخة.
- موديل مش موجود أو فشل → state = unavailable (مش SAFE أبداً).
- probability خارج [0,1] أو نسخة مش active → النتيجة مرفوضة (AI/ML Result Validation).
"""
import json
import time
from pathlib import Path

import joblib  # موجود ضمن scikit-learn dependencies
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import EvidenceSource, EvidenceState, ModelRegistry, MLPrediction, ScanType

_cache: dict[str, object] = {}


def _load(artifact_uri: str):
    if artifact_uri not in _cache:
        path = Path(artifact_uri)
        if not path.is_absolute():
            path = Path(__file__).resolve().parents[2] / artifact_uri
        _cache[artifact_uri] = joblib.load(path)
    return _cache[artifact_uri]


def active_model(db: Session, task: ScanType) -> ModelRegistry | None:
    stmt = select(ModelRegistry).where(ModelRegistry.task == task,
                                       ModelRegistry.is_active.is_(True)).limit(1)
    return db.execute(stmt).scalar_one_or_none()


def predict(db: Session, analysis_id, task: ScanType, features: dict) -> dict:
    """بيرجع evidence dict. عقدة الإخراج: {label, probability, threshold, model_version}."""
    model = active_model(db, task)
    if not model:
        return {"source": EvidenceSource.ml_model.value, "provider": "ml",
                "evidence_type": "ml_prediction",
                "state": EvidenceState.unavailable.value,
                "data": {"reason": "no_active_model", "task": task.value}, "weight": 0}
    start = time.perf_counter()
    try:
        clf = _load(model.artifact_uri)
        names = (model.metrics or {}).get("feature_names")
        row = [[features.get(n, 0) for n in names]] if names else [list(features.values())]
        proba = float(clf.predict_proba(row)[0][1])
        # AI/ML Result Validation
        if not (0.0 <= proba <= 1.0):
            raise ValueError(f"probability out of range: {proba}")
        threshold = float((model.metrics or {}).get("threshold", 0.5))
        label = "phishing" if proba >= threshold else "legit"
        latency = int((time.perf_counter() - start) * 1000)
        pred = MLPrediction(analysis_id=analysis_id, model_id=model.id, label=label,
                            probability=proba, threshold=threshold, features=features,
                            latency_ms=latency)
        db.add(pred)
        return {"source": EvidenceSource.ml_model.value, "provider": "ml",
                "evidence_type": "ml_prediction",
                "state": EvidenceState.confirmed.value,
                "data": {"label": label, "probability": round(proba, 4),
                         "threshold": threshold, "model_name": model.name,
                         "model_version": model.version},
                "weight": 0}  # الوزن بيتحسب في الـ risk engine
    except FileNotFoundError:
        return {"source": EvidenceSource.ml_model.value, "provider": "ml",
                "evidence_type": "ml_prediction",
                "state": EvidenceState.unavailable.value,
                "data": {"reason": "artifact_missing", "model": f"{model.name}@{model.version}"},
                "weight": 0}
    except Exception as exc:
        return {"source": EvidenceSource.ml_model.value, "provider": "ml",
                "evidence_type": "ml_prediction",
                "state": EvidenceState.unavailable.value,
                "data": {"reason": type(exc).__name__,
                         "model": f"{model.name}@{model.version}"}, "weight": 0}


def ml_finding(ml_evidence: dict) -> dict | None:
    """تحويل توقع الموديل لـ Finding بوزن متدرج حسب الـ probability."""
    if ml_evidence["state"] != "confirmed":
        return None
    proba = ml_evidence["data"]["probability"]
    label = ml_evidence["data"]["label"]
    ver = ml_evidence["data"]["model_version"]
    if label == "phishing":
        # توقع تصيد من الموديل لازم يبقى حاسم: لوحده يوصل لـ SUSPICIOUS/HIGH_RISK على الأقل
        threshold = float(ml_evidence["data"].get("threshold", 0.5))
        if proba < 0.8:
            fraction = max(0.0, min(1.0, (proba - threshold) / max(0.8 - threshold, 0.01)))
            weight = 45 + round(14 * fraction)
        else:
            weight = 60 + round(19 * min(1.0, (proba - 0.8) / 0.2))
        return {"rule": "ML_PHISHING",
                "detail": f"موديل {ver} متوقع تصيد باحتمال {proba:.0%}", "weight": weight}
    if proba <= 0.05:
        # تنبيه معلوماتي فقط - وزن صفر: توقع "سليم" من الموديل مش بيقلل أدلة تانية أبداً
        return {"rule": "ML_CLEAN_HIGH_CONF",
                "detail": f"موديل {ver} واثق إن الرابط سليم ({1 - proba:.0%})", "weight": 0}
    return None
