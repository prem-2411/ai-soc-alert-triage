import pandas as pd
from backend.rules import apply_rules

def row(**kw):
    base = dict(n_flows=5, distinct_ports=2, failed_logins=0, total_bytes=1000, avg_duration=1)
    return pd.DataFrame([{**base, **kw}])

def hits(**kw): return apply_rules(row(**kw))["rule_hits"].iloc[0]

def test_benign_has_no_hits(): assert hits() == []
def test_brute_force(): assert hits(failed_logins=15) == ["brute_force"]
def test_port_scan(): assert hits(distinct_ports=50) == ["port_scan"]
def test_traffic_spike(): assert hits(total_bytes=9_000_000) == ["traffic_spike"]
def test_boundary_below_threshold(): assert hits(failed_logins=9) == []
