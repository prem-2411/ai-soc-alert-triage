import pandas as pd

# Thresholds are deliberately simple and tunable; document them in your README.
THRESHOLDS = {"brute_force": 10, "port_scan": 20, "traffic_spike": 5_000_000}

MITRE = {
    "brute_force": "T1110 Brute Force",
    "port_scan": "T1046 Network Service Discovery",
    "traffic_spike": "T1498 Network Denial of Service",
}

def apply_rules(feats: pd.DataFrame, t: dict = THRESHOLDS) -> pd.DataFrame:
    """Return the features frame with a `rule_hits` list column."""
    out = feats.copy()
    def hits(r):
        h = []
        if r["failed_logins"] >= t["brute_force"]: h.append("brute_force")
        if r["distinct_ports"] >= t["port_scan"]: h.append("port_scan")
        if r["total_bytes"] >= t["traffic_spike"]: h.append("traffic_spike")
        return h
    out["rule_hits"] = out.apply(hits, axis=1)
    return out
