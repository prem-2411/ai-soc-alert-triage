import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import precision_score, recall_score, confusion_matrix
from sklearn.model_selection import train_test_split
from .features import FEATURES
from .rules import apply_rules

def _fpr(y, p):
    tn, fp, fn, tp = confusion_matrix(y, p, labels=[0, 1]).ravel()
    return fp / (fp + tn) if (fp + tn) else 0.0

def train_and_evaluate(feats):
    """Trains both models; returns (iso, rf, results table)."""
    y = (~feats["label"].isin(["benign", "unknown"])).astype(int).values
    X = feats[FEATURES].values
    Xtr, Xte, ytr, yte, ftr, fte = train_test_split(X, y, feats, test_size=0.3, stratify=y, random_state=0)

    iso = IsolationForest(contamination=max(ytr.mean(), 0.01), random_state=0).fit(Xtr)
    iso_pred = (iso.predict(Xte) == -1).astype(int)
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=0).fit(Xtr, ytr)
    rf_pred = rf.predict(Xte)
    rule_pred = apply_rules(fte)["rule_hits"].apply(lambda h: int(len(h) > 0)).values

    results = {}
    for name, p in [("Rules only", rule_pred), ("Isolation Forest", iso_pred), ("Random Forest", rf_pred)]:
        results[name] = {"precision": precision_score(yte, p, zero_division=0),
                         "recall": recall_score(yte, p, zero_division=0),
                         "fpr": _fpr(yte, p)}
    return iso, rf, results

def iso_score(iso, X):
    """Higher = more anomalous, scaled to roughly 0..1."""
    raw = -iso.score_samples(X)
    return np.clip((raw - 0.3) / 0.4, 0, 1)
