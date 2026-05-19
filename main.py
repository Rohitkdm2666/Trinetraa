import os
import json
import pickle
import asyncio
import requests
import subprocess
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from collections import deque
from typing import List
from supabase import create_client
from defense import (
    apply_defense, get_defense_stats, blocked_ips,
    # Phase 2
    generate_fingerprint, check_fingerprint_match, get_fingerprint_db,
    update_threat_level, get_threat_level, get_threat_stats,
    detect_attack_sequence, get_apt_detections,
    check_honeypot, log_honeypot_trigger, get_honeypot_log,
)

# ─────────────────────────────────────────────
# Supabase
# ─────────────────────────────────────────────
# Supabase config — replace with your credentials
# ─────────────────────────────────────────────
SUPABASE_URL = "https://pwilushygtrjzludihja.supabase.co"   # your URL
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InB3aWx1c2h5Z3RyanpsdWRpaGphIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzQ1MTM4ODcsImV4cCI6MjA5MDA4OTg4N30.V1u5b5a106IVZHOULpKvxbw0x6yqACiiS51MIRUukFU"              # your key
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ─────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────
MODEL_DIR     = "./model_artifacts"
model         = pickle.load(open(f"{MODEL_DIR}/model.pkl",         "rb"))
scaler        = pickle.load(open(f"{MODEL_DIR}/scaler.pkl",        "rb"))
encoder       = pickle.load(open(f"{MODEL_DIR}/label_encoder.pkl", "rb"))
feature_names = json.load(open(f"{MODEL_DIR}/features.json"))
print("[*] Model loaded")

# ─────────────────────────────────────────────
# In-memory
# ─────────────────────────────────────────────
recent_alerts = deque(maxlen=100)
stats = {"total_flows": 0, "total_attacks": 0, "attack_counts": {}}

# ─────────────────────────────────────────────
# WebSocket Manager
# ─────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"[WS] Client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)
        print(f"[WS] Client disconnected. Total: {len(self.active)}")

    async def broadcast(self, data: dict):
        for ws in self.active.copy():
            try:
                await ws.send_json(data)
            except Exception:
                self.disconnect(ws)

manager = ConnectionManager()

# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────
app = FastAPI(title="Cyber Attack Prediction API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────
class FlowFeatures(BaseModel):
    src_ip: str
    features: dict

# ─────────────────────────────────────────────
# Predict + Defend
# ─────────────────────────────────────────────
def rule_based_detection(features: dict):
    syn  = float(features.get("SYN Flag Count", 0))
    pps  = float(features.get("Flow Packets/s", 0))
    bwd  = float(features.get("Total Backward Packets", 0))
    fwd  = float(features.get("Total Fwd Packets", 0))
    port = int(features.get("Destination Port", 0))
    dur  = float(features.get("Flow Duration", 0))
    bps  = float(features.get("Flow Bytes/s", 0))
    ack  = float(features.get("ACK Flag Count", 0))
    psh  = float(features.get("PSH Flag Count", 0))
    fwd_mean = float(features.get("Fwd Packet Length Mean", 0))
    bwd_mean = float(features.get("Bwd Packet Length Mean", 0))

    if syn > 30 and bwd_mean == 0 and fwd > 10:
        return "PortScan", 100.0
    if syn > 80 and ack == 0 and pps > 200:
        return "DDoS", 100.0
    if pps > 2000 and fwd_mean > 100:
        return "DoS Hulk", 100.0
    if pps > 2000 and port in {80, 443, 8080}:
        return "DoS GoldenEye", 100.0
    if dur > 500000 and fwd_mean < 50 and pps < 5 and fwd > 10:
        return "DoS slowloris", 100.0
    if port == 22 and fwd_mean > 50 and psh > 10:
        return "SSH-Patator", 100.0
    if port == 21 and fwd > 30 and psh > 5:
        return "FTP-Patator", 100.0
    if port in {80, 443, 8080} and psh > 10 and bwd == 0:
        return "Web Attack  Brute Force", 100.0
    if bps > 1000000 and pps > 500:
        return "DDoS", 100.0
    return None, None

def predict_flow(features: dict, src_ip: str) -> dict:
    rule_label, rule_conf = rule_based_detection(features)
    
    if rule_label:
        label = rule_label
        confidence = rule_conf
        is_attack = True
        detection = "RULE"
    else:
        row    = [features.get(f, 0) for f in feature_names]
        scaled = scaler.transform(pd.DataFrame([row], columns=feature_names))

        pred       = model.predict(scaled)[0]
        proba      = model.predict_proba(scaled)[0]
        label      = encoder.inverse_transform([pred])[0]
        confidence = round(float(np.max(proba)) * 100, 2)
        is_attack  = label.strip().upper() != "BENIGN"
        detection  = "ML"

    defense = apply_defense(
        src_ip        = src_ip,
        label         = label,
        is_attack     = is_attack,
        ml_confidence = confidence,
        features      = features
    )

    result = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "src_ip":        src_ip,
        "label":         label,
        "is_attack":     is_attack,
        "confidence":    confidence,
        "risk_score":    defense["risk_score"],
        "action":        defense["action"],
        "threat_type":   defense["threat_type"],
        "block_reasons": defense["reason"],
        "blocked":       defense["action"] == "BLOCK",
    }

    # ── Phase 2 Novel Defenses ──
    fingerprint  = generate_fingerprint(features, src_ip)
    fp_match     = check_fingerprint_match(fingerprint)
    honeypot     = check_honeypot(features)

    # Honeypot override: any connection to a honeypot port = immediate block
    if honeypot:
        label      = "HONEYPOT_PROBE"
        confidence = 100.0
        is_attack  = True
        log_honeypot_trigger(src_ip, features)
        result["label"]      = label
        result["is_attack"]  = True
        result["confidence"] = 100.0
        result["action"]     = "BLOCK"
        result["blocked"]    = True
        result["block_reasons"] = ["Honeypot port targeted"]

    threat_level = update_threat_level(is_attack)
    apt          = detect_attack_sequence(src_ip, label) if is_attack else None

    result["fingerprint"]        = fingerprint
    result["fp_rotation"]        = fp_match
    result["apt_detected"]       = apt
    result["honeypot_triggered"] = honeypot
    result["threat_level"]       = threat_level

    stats["total_flows"] += 1

    if is_attack:
        stats["total_attacks"] += 1
        stats["attack_counts"][label] = stats["attack_counts"].get(label, 0) + 1
        recent_alerts.appendleft(result)
        print(f"  🚨 {label} ({confidence}%) risk={defense['risk_score']} src={src_ip}")

        # Push to all WebSocket clients instantly
        asyncio.create_task(manager.broadcast({
            "type": "alert",
            "data": result
        }))

        # Push updated stats too
        asyncio.create_task(manager.broadcast({
            "type": "stats",
            "data": {
                "total_flows":   stats["total_flows"],
                "total_attacks": stats["total_attacks"],
                "benign":        stats["total_flows"] - stats["total_attacks"],
                "attack_counts": stats["attack_counts"],
            }
        }))

        # Save to Supabase
        try:
            supabase.table("alerts").insert({
                "timestamp":  result["timestamp"],
                "src_ip":     src_ip,
                "label":      label,
                "is_attack":  is_attack,
                "confidence": confidence,
                "blocked":    result["blocked"],
            }).execute()
        except Exception as e:
            print(f"  [!] Supabase error: {e}")

    return result

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "running", "classes": list(encoder.classes_)}


@app.post("/predict")
async def predict(flow: FlowFeatures):
    result = predict_flow(flow.features, flow.src_ip)
    # Phase 3: update network topology graph on every prediction
    _update_network_graph(
        src_ip     = flow.src_ip,
        features   = flow.features,
        label      = result.get("label", "BENIGN"),
        is_attack  = result.get("is_attack", False),
        is_blocked = result.get("blocked", False),
    )
    return result


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Send current stats immediately on connect
    await websocket.send_json({
        "type": "stats",
        "data": {
            "total_flows":   stats["total_flows"],
            "total_attacks": stats["total_attacks"],
            "benign":        stats["total_flows"] - stats["total_attacks"],
            "attack_counts": stats["attack_counts"],
        }
    })
    try:
        while True:
            await websocket.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/alerts")
def get_alerts(limit: int = 20):
    try:
        res = supabase.table("alerts").select("*").order("timestamp", desc=True).limit(limit).execute()
        return res.data
    except Exception:
        return list(recent_alerts)[:limit]


@app.get("/stats")
def get_stats():
    defense = get_defense_stats()
    return {
        "total_flows":    stats["total_flows"],
        "total_attacks":  stats["total_attacks"],
        "benign":         stats["total_flows"] - stats["total_attacks"],
        "attack_counts":  stats["attack_counts"],
        "blocked_ips":    list(blocked_ips),
        "high_risk_ips":  defense["high_risk_ips"],
        "total_ips_seen": defense["total_ips_seen"],
    }


@app.get("/defense")
def defense_status():
    return get_defense_stats()


@app.post("/block/{ip}")
def manual_block(ip: str):
    from defense import _do_block, get_record, BASE_BLOCK_DURATION
    record = get_record(ip)
    _do_block(ip, record, BASE_BLOCK_DURATION)
    return {"blocked": ip}


@app.delete("/block/{ip}")
def unblock(ip: str):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.discard(ip)
        return {"unblocked": ip}
    except Exception as e:
        return {"error": str(e)}

# ─────────────────────────────────────────────
# New Evaluation & Simulation Endpoints
# ─────────────────────────────────────────────
@app.get("/metrics")
def get_model_metrics():
    try:
        with open("reports/metrics.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": "Metrics file not found. Run generate_reports.py first."}

@app.post("/simulate/{attack_type}")
async def simulate_attack(attack_type: str):
    try:
        # Run attack simulator in background
        cmd = ["python3", "attack_simulator.py", "--attack", attack_type]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"message": f"Simulation started for {attack_type}."}
    except Exception as e:
        return {"error": str(e)}

@app.get("/victim/logs")
def get_victim_logs():
    try:
        r = requests.get("http://localhost:8080/logs", timeout=2)
        return r.json()
    except Exception as e:
        return {"error": "Victim server unreachable or offline", "details": str(e)}


# ─────────────────────────────────────────────
# Phase 2 — Threat Intelligence Endpoints
# ─────────────────────────────────────────────

@app.get("/threat-level")
def threat_level_endpoint():
    """Returns current adaptive threat level and attack frequency stats."""
    return get_threat_stats()


@app.get("/fingerprints")
def fingerprints_endpoint():
    """Returns the behavioral fingerprint database.
    Fingerprints matching multiple IPs indicate IP-rotation botnet attacks."""
    db = get_fingerprint_db()
    rotation_attacks = [f for f in db if f["is_rotation"]]
    return {
        "total_fingerprints":   len(db),
        "rotation_attacks":     len(rotation_attacks),
        "fingerprints":         sorted(db, key=lambda x: -x["ip_count"]),
    }


@app.get("/apt-detections")
def apt_detections_endpoint():
    """Returns detected Advanced Persistent Threat (APT) attack sequences."""
    detections = get_apt_detections()
    return {
        "total_apt_events": len(detections),
        "detections":       detections,
    }


@app.get("/honeypot-log")
def honeypot_log_endpoint():
    """Returns honeypot trigger log — any connection to honeypot ports."""
    log_entries = get_honeypot_log()
    return {
        "total_triggers": len(log_entries),
        "log":            log_entries,
    }


# ─────────────────────────────────────────────
# Phase 3 — Network Graph
# ─────────────────────────────────────────────
network_graph: dict = {
    "nodes": {},   # ip -> {id, ip, type, attack_count, is_blocked, last_seen}
    "edges": [],   # {source, target, label, timestamp, is_attack}
}

_VICTIM_IPS = {"10.0.0.1", "192.168.1.1", "172.16.0.1"}   # internal victim pool


def _update_network_graph(src_ip: str, features: dict, label: str, is_attack: bool, is_blocked: bool):
    """Maintain in-memory network graph node/edge list updated on every predict call."""
    dst_port = int(features.get("Destination Port", 0))
    # create a synthetic deterministic victim IP from the port (for demo realism)
    dst_ip = f"10.0.{dst_port // 256}.{dst_port % 256}" if dst_port else "10.0.0.1"

    now = datetime.now(timezone.utc).isoformat()

    # ── src node ──
    if src_ip not in network_graph["nodes"]:
        network_graph["nodes"][src_ip] = {
            "id":           src_ip,
            "ip":           src_ip,
            "type":         "normal",
            "attack_count": 0,
            "is_blocked":   False,
            "last_seen":    now,
            "traffic":      0,
        }
    node = network_graph["nodes"][src_ip]
    node["last_seen"] = now
    node["traffic"]  += 1
    if is_attack:
        node["attack_count"] += 1
        node["type"] = "blocked" if is_blocked else "attacker"
    if is_blocked:
        node["is_blocked"] = True
        node["type"]       = "blocked"

    # ── dst node ──
    if dst_ip not in network_graph["nodes"]:
        network_graph["nodes"][dst_ip] = {
            "id":           dst_ip,
            "ip":           dst_ip,
            "type":         "victim",
            "attack_count": 0,
            "is_blocked":   False,
            "last_seen":    now,
            "traffic":      0,
        }
    network_graph["nodes"][dst_ip]["last_seen"] = now
    network_graph["nodes"][dst_ip]["traffic"]  += 1

    # ── edge ──
    network_graph["edges"].append({
        "source":    src_ip,
        "target":    dst_ip,
        "label":     label,
        "timestamp": now,
        "is_attack": is_attack,
    })
    # Keep only the last 100 edges
    if len(network_graph["edges"]) > 100:
        network_graph["edges"] = network_graph["edges"][-100:]


@app.get("/network-graph")
def get_network_graph():
    """Returns current network topology graph — nodes and edges for D3 force layout."""
    nodes = list(network_graph["nodes"].values())
    edges = network_graph["edges"][-100:]
    return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}


# (network graph update is called from the /predict endpoint above)


# ─────────────────────────────────────────────
# Phase 3 — Incident Report Endpoints
# ─────────────────────────────────────────────
from fastapi.responses import FileResponse as _FileResponse

@app.post("/generate-report")
async def generate_report():
    """Fetch current data, generate PDF incident report, return filename."""
    try:
        from reports.incident_report import generate_incident_report

        # Gather data from in-memory state (same as the API endpoints return)
        current_alerts = list(recent_alerts)
        current_stats  = {
            "total_flows":   stats["total_flows"],
            "total_attacks": stats["total_attacks"],
            "benign":        stats["total_flows"] - stats["total_attacks"],
            "attack_counts": stats["attack_counts"],
            "blocked_ips":   list(blocked_ips),
        }
        current_defense = get_defense_stats()

        filepath = generate_incident_report(current_alerts, current_stats, current_defense)
        filename = os.path.basename(filepath)
        return {
            "status":   "generated",
            "filename": filename,
            "path":     f"reports/{filename}",
        }
    except Exception as e:
        import traceback
        return {"status": "error", "message": str(e), "trace": traceback.format_exc()}


@app.get("/download-report/{filename}")
async def download_report(filename: str):
    """Serve a generated PDF report for download."""
    # Sanitise: only allow incident_*.pdf
    if not filename.startswith("incident_") or not filename.endswith(".pdf"):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = os.path.join("reports", filename)
    if not os.path.exists(path):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Report not found")
    return _FileResponse(
        path,
        media_type    = "application/pdf",
        filename      = filename,
        headers       = {"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/reports-list")
def list_reports():
    """Return list of all generated PDF reports in the reports/ folder."""
    try:
        files = [
            {
                "filename": f,
                "size_kb":  round(os.path.getsize(os.path.join("reports", f)) / 1024, 1),
                "created":  datetime.fromtimestamp(
                    os.path.getmtime(os.path.join("reports", f)), tz=timezone.utc
                ).isoformat(),
            }
            for f in sorted(os.listdir("reports"), reverse=True)
            if f.startswith("incident_") and f.endswith(".pdf")
        ]
        return {"reports": files, "count": len(files)}
    except Exception as e:
        return {"reports": [], "count": 0, "error": str(e)}