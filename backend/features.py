import pandas as pd

FEATURES = ["n_flows", "distinct_ports", "failed_logins", "total_bytes", "avg_duration"]

def window_features(df: pd.DataFrame, window: str = "1min") -> pd.DataFrame:
    """Aggregate raw flow/auth logs into one row per (src_ip, time window)."""
    df = df.copy()
    df["ts"] = pd.to_datetime(df["timestamp"])
    df["win"] = df["ts"].dt.floor(window)
    if "label" not in df:
        df["label"] = "unknown"
    g = df.groupby(["src_ip", "win"]).agg(
        n_flows=("dst_port", "size"),
        distinct_ports=("dst_port", "nunique"),
        failed_logins=("failed_login", "sum"),
        total_bytes=("bytes", "sum"),
        avg_duration=("duration", "mean"),
        label=("label", lambda s: next((x for x in s if x not in ("benign", "unknown")), s.iloc[0])),
    ).reset_index()
    return g
