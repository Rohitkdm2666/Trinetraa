import json
import pickle
import requests
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from feature_extractor import extract_from_pcap
from packet_capture import capture_loop

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
API_URL   = "http://localhost:8000/predict"   # FastAPI endpoint
MODEL_DIR = "./model_artifacts"

# ─────────────────────────────────────────────
# Load model artifacts
# ─────────────────────────────────────────────
model         = pickle.load(open(f"{MODEL_DIR}/model.pkl",         "rb"))
scaler        = pickle.load(open(f"{MODEL_DIR}/scaler.pkl",        "rb"))
encoder       = pickle.load(open(f"{MODEL_DIR}/label_encoder.pkl", "rb"))
feature_names = json.load(open(f"{MODEL_DIR}/features.json"))

print("[*] Model loaded")
print(f"    Classes: {list(encoder.classes_)}")


# ─────────────────────────────────────────────
# Predict locally + POST result to FastAPI
# ─────────────────────────────────────────────
def on_flow(features: dict, src_ip: str):
    # Align features
    row    = [features.get(f, 0) for f in feature_names]
    scaled = scaler.transform(pd.DataFrame([row], columns=feature_names))

    pred       = model.predict(scaled)[0]
    proba      = model.predict_proba(scaled)[0]
    label      = encoder.inverse_transform([pred])[0]
    confidence = round(float(np.max(proba)) * 100, 2)
    is_attack  = label.strip().upper() != "BENIGN"

    status = "🚨 ATTACK" if is_attack else "✅ BENIGN"
    print(f"  {status} | {label} ({confidence}%) | src={src_ip}")

    # POST to FastAPI → FastAPI saves to Supabase + handles blocking
    try:
        requests.post(API_URL, json={
            "src_ip":   src_ip,
            "features": features
        }, timeout=5)
    except Exception as e:
        print(f"  [!] Could not reach FastAPI: {e}")


# ─────────────────────────────────────────────
# Mode 1: Test on saved .pcap
# ─────────────────────────────────────────────
def run_on_pcap(pcap_file: str):
    print(f"[*] Running on {pcap_file}")
    extract_from_pcap(pcap_file, callback=on_flow)


# ─────────────────────────────────────────────
# Mode 2: Live pipeline (runs forever)
# ─────────────────────────────────────────────
def run_live():
    print("[*] Starting live prediction pipeline...")

    def on_new_pcap(filepath):
        extract_from_pcap(filepath, callback=on_flow)

    capture_loop(on_new_pcap=on_new_pcap)


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run_on_pcap(sys.argv[1])   # python predictor.py test.pcap
    else:
        run_live()                 # sudo python predictor.py   