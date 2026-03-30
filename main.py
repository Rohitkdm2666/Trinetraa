import json
import pickle
import asyncio
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from collections import deque
from typing import List
from supabase import create_client
from defense import apply_defense, get_defense_stats, blocked_ips

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
def predict_flow(features: dict, src_ip: str) -> dict:
    row    = [features.get(f, 0) for f in feature_names]
    scaled = scaler.transform(pd.DataFrame([row], columns=feature_names))

    pred       = model.predict(scaled)[0]
    proba      = model.predict_proba(scaled)[0]
    label      = encoder.inverse_transform([pred])[0]
    confidence = round(float(np.max(proba)) * 100, 2)
    is_attack  = label.strip().upper() != "BENIGN"

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
    return predict_flow(flow.features, flow.src_ip)


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
    import subprocess
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        blocked_ips.discard(ip)
        return {"unblocked": ip}
    except Exception as e:
        return {"error": str(e)}