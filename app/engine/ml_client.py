"""ML client: Ø§Ø³ØªØ¯Ø¹Ø§Ø¡ Ø§ÙÙÙØ¯ÙÙ Ø§ÙÙØ´Ø· ÙÙ model_registry ÙØ¹ validation (ÙØªØ·ÙØ¨Ø§Øª 9, 25).

Ø§ÙÙÙØ§Ø¹Ø¯:
- Ø§ÙÙÙØ¯ÙÙ Ø¯ÙÙÙØ ÙØ´ Ø­ÙÙ. Ø§ÙÙØªÙØ¬Ø© Ø¨ØªØªØ®Ø²Ù ÙÙ ml_predictions ÙØ¹ Ø§ÙÙØ³Ø®Ø©.
- ÙÙØ¯ÙÙ ÙØ´ ÙÙØ¬ÙØ¯ Ø£Ù ÙØ´Ù â state = unavailable (ÙØ´ SAFE Ø£Ø¨Ø¯Ø§Ù).
- probability Ø®Ø§Ø±Ø¬ [0,1] Ø£Ù ÙØ³Ø®Ø© ÙØ´ active â Ø§ÙÙØªÙØ¬Ø© ÙØ±ÙÙØ¶Ø© (AI/ML Result Validation).
"""
import json
import time
from pathlib import Path

import joblib  # ÙÙØ¬ÙØ¯ Ø¶ÙÙ scikit-learn dependencies
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
    """Ø¨ÙØ±Ø¬Ø¹ evidence dict. Ø¹ÙØ¯Ø© Ø§ÙØ¥Ø®Ø±Ø§Ø¬: {label, probability, threshold, model_version}."""
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
                "weight": 0}  # Ø§ÙÙØ²Ù Ø¨ÙØªØ­Ø³Ø¨ ÙÙ Ø§ÙÙ risk engine
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
    """ØªØ­ÙÙÙ ØªÙÙØ¹ Ø§ÙÙÙØ¯ÙÙ ÙÙ Finding Ø¨ÙØ²Ù ÙØªØ¯Ø±Ø¬ Ø­Ø³Ø¨ Ø§ÙÙ probability."""
    if ml_evidence["state"] != "confirmed":
        return None
    proba = ml_evidence["data"]["probability"]
    label = ml_evidence["data"]["label"]
    ver = ml_evidence["data"]["model_version"]
    if label == "phishing":
        weight = 45 if proba < 0.8 else (60 if proba < 0.95 else 75)
        return {"rule": "ML_PHISHING",
                "detail": f"ÙÙØ¯ÙÙ {ver} ÙØªÙÙØ¹ ØªØµÙØ¯ Ø¨Ø§Ø­ØªÙØ§Ù {proba:.0%}", "weight": weight}
    if proba <= 0.05:
        return {"rule": "ML_CLEAN_HIGH_CONF",
                "detail": f"ÙÙØ¯ÙÙ {ver} ÙØ§Ø«Ù Ø¥Ù Ø§ÙØ±Ø§Ø¨Ø· Ø³ÙÙÙ ({1 - proba:.0%})", "weight": 0}
    return None
