"""Prints the model comparison table (your resume numbers come from here)."""
import pandas as pd
from backend.synth import generate
from backend.features import window_features
from backend.ml import train_and_evaluate
raw = generate(); feats = window_features(raw)
print(f"{len(raw)} log records -> {len(feats)} IP/minute windows")
_, _, res = train_and_evaluate(feats)
print(pd.DataFrame(res).T.round(3))
