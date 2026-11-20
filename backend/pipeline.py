import pandas as pd
from .features import FEATURES, window_features
from .rules import apply_rules, MITRE
from .ml import iso_score

def severity(rf_proba, iso, n_rule_hits):
    """Combined 0-100 score: supervised model, anomaly score, and rule hits."""
    rule = min(1.0, n_rule_hits / 2 + (0.5 if n_rule_hits else 0))
    return round(100 * (0.5 * rf_proba + 0.2 * iso + 0.3 * rule), 1)

def label_sev(score):
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"

def detect(raw: pd.DataFrame, iso, rf, min_score=40):
    feats = apply_rules(window_features(raw))
    X = feats[FEATURES].values
    feats["rf_proba"] = rf.predict_proba(X)[:, 1]
    feats["iso"] = iso_score(iso, X)
    alerts = []
    for _, r in feats.iterrows():
        s = severity(r.rf_proba, r.iso, len(r.rule_hits))
        if s < min_score and not r.rule_hits:
            continue
        kind = r.rule_hits[0] if r.rule_hits else "anomaly"
        alerts.append({
            "timestamp": str(r.win), "src_ip": r.src_ip, "attack_type": kind,
            "mitre": MITRE.get(kind, "Unmapped (ML anomaly)"),
            "severity_score": s, "severity": label_sev(s),
            "detected_by": ("rules+ml" if r.rule_hits and r.rf_proba > .5 else "rules" if r.rule_hits else "ml"),
            "status": "open",
        })
    return alerts
