import io, sqlite3, pandas as pd
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .synth import generate
from .features import window_features
from .ml import train_and_evaluate
from .pipeline import detect

app = FastAPI(title="SOC Alert Triage API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db = sqlite3.connect("alerts.db", check_same_thread=False)
db.row_factory = sqlite3.Row
db.execute("""CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
  src_ip TEXT, attack_type TEXT, mitre TEXT, severity_score REAL, severity TEXT, detected_by TEXT, status TEXT)""")

iso, rf, RESULTS = train_and_evaluate(window_features(generate()))

class StatusUpdate(BaseModel):
    status: str  # open | investigating | closed

def _insert(alerts):
    db.executemany("""INSERT INTO alerts(timestamp,src_ip,attack_type,mitre,severity_score,severity,detected_by,status)
      VALUES(:timestamp,:src_ip,:attack_type,:mitre,:severity_score,:severity,:detected_by,:status)""", alerts)
    db.commit()

@app.post("/upload-logs")
async def upload_logs(file: UploadFile):
    raw = pd.read_csv(io.BytesIO(await file.read()))
    missing = {"timestamp", "src_ip", "dst_port", "bytes", "duration", "failed_login"} - set(raw.columns)
    if missing:
        raise HTTPException(400, f"Missing columns: {sorted(missing)}")
    alerts = detect(raw, iso, rf)
    _insert(alerts)
    return {"records": len(raw), "alerts_created": len(alerts)}

@app.get("/alerts")
def list_alerts(severity: str | None = None, status: str | None = None, src_ip: str | None = None, limit: int = 200):
    q, args = "SELECT * FROM alerts WHERE 1=1", []
    for col, v in (("severity", severity), ("status", status), ("src_ip", src_ip)):
        if v: q += f" AND {col}=?"; args.append(v)
    return [dict(r) for r in db.execute(q + " ORDER BY severity_score DESC LIMIT ?", (*args, limit))]

@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    r = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    if not r: raise HTTPException(404, "Alert not found")
    return dict(r)

@app.patch("/alerts/{alert_id}")
def update_status(alert_id: int, body: StatusUpdate):
    if body.status not in ("open", "investigating", "closed"):
        raise HTTPException(400, "Invalid status")
    db.execute("UPDATE alerts SET status=? WHERE id=?", (body.status, alert_id)); db.commit()
    return get_alert(alert_id)

@app.get("/stats")
def stats():
    q = lambda s: [dict(r) for r in db.execute(s)]
    return {
        "by_severity": q("SELECT severity, COUNT(*) n FROM alerts GROUP BY severity"),
        "by_status": q("SELECT status, COUNT(*) n FROM alerts GROUP BY status"),
        "top_ips": q("SELECT src_ip, COUNT(*) n FROM alerts GROUP BY src_ip ORDER BY n DESC LIMIT 10"),
        "timeline": q("SELECT substr(timestamp,1,13) hour, COUNT(*) n FROM alerts GROUP BY hour ORDER BY hour"),
        "model_results": RESULTS,
    }
