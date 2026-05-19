# 🛡️ AEGIS: AI-Based Cyber Attack Prediction & Defense

**AEGIS** is a research-grade, active Intrusion Prevention System (IPS). It captures live network packets, reconstructs flows, evaluates them against a hybrid `RandomForest` machine learning model and rule-based heuristics, and automatically implements dynamic kernel-level `iptables` defense actions.

![Dashboard Preview](dashboard/screenshot.png) <!-- Update this later -->

## 🛠️ Features
- **Live Flow Inference**: Extracts 18 unencrypted metadata parameters directly mimicking CICFlowMeter.
- **Hybrid Detection**: Couples a robust `RandomForestClassifier` trained on CICIDS2017 with unyielding deterministic network rules.
- **Microservice Architecture**: Python (`FastAPI`), NodeJS (`React`), PostgreSQL (`Supabase`), OS Ring-0 (`iptables`, `tcpdump`).
- **6-Layer Defense Pipeline**:
  - IP Reputation (AbuseIPDB Integration)
  - Adaptive Sliding Window Rate Limiting
  - Geofence Drops
  - Heuristic + Model Confidence Scoring
  - Automatic Exponential Backoff Unblocks
  - Temporal Distributed Attack Correlation
- **Integrated Simulator**: Test the model without launching live botnets.

---

## 🚀 Setup & Execution

### 1. Requirements & System
- **OS**: Linux (Ubuntu/Kali recommended) to support `iptables` and `tcpdump`.
- **Software**: Node.js v16+, Python 3.10+, pip.

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Dashboard dependencies
cd dashboard && npm install
npm rebuild esbuild # If running on distinct architecture
```

### 2. Generate Model Artifacts
Before running the server, the Random Forest model must be generated (or synthesized if the 4GB dataset is absent).
```bash
python3 reports/generate_reports.py
```
*This populates `/reports` with diagnostic graphs and `/model_artifacts` with `model.pkl` and `scaler.pkl`.*

### 3. Run the Stack
Run all necessary web services using the execution shell:
```bash
chmod +x run_all.sh
sudo ./run_all.sh
```
*(Requires `sudo` to authorize `tcpdump` sniffing and `iptables` blocking).*

If executing modules individually:
1. `uvicorn main:app --reload --port 8000` (Backend API).
2. `python3 victim_server.py` (Local vulnerable target application on port 8080).
3. `cd dashboard && npm run dev -- --port 5173 --host` (React UI).
4. `python3 packet_capture.py` (Sniffer, dumps pcaps).
5. `python3 predictor.py` (Relays parsed features to the API).

---

## 💥 Testing: Attack Simulator
Do not launch actual denial-of-service tools over institutional networks. Use our provided synthetic flow injector:

```bash
# Valid arguments: portscan, ddos, dos_hulk, dos_slowloris, ssh_brute, ftp_brute, web_brute
python3 attack_simulator.py --attack ddos
```
Or launch simulations immediately via the **Simulator Dashboard Tab** inside the React UI.

## 📁 Architecture Tree

```text
├── docs/                      # Extensive theory, feature selection, and Viva Q&As
├── reports/                   # Model performance graphs and metrics
├── dashboard/                 # React frontend
├── main.py                    # FastAPI orchestrator and WebSocket multiplexer
├── defense.py                 # Multi-layered heuristic risk-scoring IPS
├── predictor.py               # ML Pipeline feature ingestor
├── feature_extractor.py       # Replicates CICFlowMeter behavior using Scapy
├── packet_capture.py          # tcpdump wrapper
├── run_all.sh                 # Background system startup logic
├── attack_simulator.py        # Fuzzer and test suite
├── filter.py / Trinetraa      # (Legacy components / Working Dirs)
└── requirements.txt
```

---
*AEGIS was created to bridge the theoretical limits of CSV-based ML classifications and practical inline software-defined networking.*
