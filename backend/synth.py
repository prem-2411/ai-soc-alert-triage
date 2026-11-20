"""Synthetic log generator so the project runs offline.
Swap in CIC-IDS2017 / UNSW-NB15 later by mapping columns to the same schema:
timestamp, src_ip, dst_ip, dst_port, bytes, duration, failed_login, label."""
import numpy as np, pandas as pd

def generate(n_benign=6000, seed=42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2026-01-01 00:00:00")
    rows = []
    ips = [f"10.0.0.{i}" for i in range(1, 40)]
    for _ in range(n_benign):
        rows.append((t0 + pd.Timedelta(seconds=int(rng.integers(0, 6*3600))), rng.choice(ips),
                     "192.168.1.10", int(rng.choice([22, 80, 443, 53, 3306])),
                     int(rng.lognormal(8, 1)), float(rng.exponential(2)),
                     int(rng.random() < 0.02), "benign"))
    def burst(ip, minute, n, port_fn, bytes_fn, fails, label):
        for i in range(n):
            rows.append((t0 + pd.Timedelta(minutes=minute, seconds=int(rng.integers(0, 60))), ip,
                         "192.168.1.10", port_fn(i), bytes_fn(), 0.1, fails, label))
    for k in range(15):   # brute force
        burst(f"203.0.113.{k+1}", 30 + k*20, 40, lambda i: 22, lambda: 300, 1, "brute_force")
    for k in range(15):   # port scan
        burst(f"198.51.100.{k+1}", 40 + k*20, 60, lambda i: 1000 + i, lambda: 60, 0, "port_scan")
    for k in range(10):   # volumetric spike
        burst(f"192.0.2.{k+1}", 50 + k*25, 120, lambda i: 80, lambda: 90_000, 0, "traffic_spike")
    for k in range(15):   # stealthy slow scan the rules miss (12 ports)
        burst(f"100.64.0.{k+1}", 60 + k*20, 14, lambda i: 2000 + i, lambda: 80, 0, "stealth_scan")
    df = pd.DataFrame(rows, columns=["timestamp", "src_ip", "dst_ip", "dst_port", "bytes", "duration", "failed_login", "label"])
    return df.sort_values("timestamp").reset_index(drop=True)
