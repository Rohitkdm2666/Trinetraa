# AEGIS Core Architecture

AEGIS is built on an event-driven, microservice-inspired architecture designed to bridge the gap between low-level network manipulation and high-level predictive modeling.

## System Diagram

```text
       [External Network / Attacker]
                  |  (Raw Packets)
                  v
 +-----------------------------------+
 | 1. tcpdump + pcap buffer (OSi L2) | <- packet_capture.py
 +-----------------------------------+
                  |  (.pcap chunks)
                  v
 +-----------------------------------+
 | 2. Scapy Feature Extractor        | <- feature_extractor.py
 |    (Extracts the 18 parameters)   |
 +-----------------------------------+
                  |  (Flow JSON)
                  v
 +-----------------------------------+
 | 3. Predictor / Relay Node         | <- predictor.py
 |    (Batches JSON -> POST)         |
 +-----------------------------------+
                  |  (HTTP POST /predict)
                  v
 +===================================+
 | 4. FastAPI Backend (main.py)      |
 |  |                                |
 |  |-- [ ML Model Inference ]       | (RandomForest)
 |  |-- [ Rule-Based Heuristics ]    |
 |  |-- [ Defense Engine (L1-L6) ]   | -> Blocks via `iptables -A INPUT -s ...`
 |  +================================+
          |               |
   (WebSocket Push)  (Supabase Insert)
          |               |
          v               v
 +-----------------+ +-------------------+
 | 5. React UI     | | 6. Cloud Database |
 | (Dashboard)     | | (Persistent Logs) |
 +-----------------+ +-------------------+
```

## Component Responsibilities

1. **`packet_capture.py`**: Intercepts packets asynchronously. Spawns `tcpdump` subprocesses to collect PCAPs in short rolling buffers without saturating RAM.
2. **`feature_extractor.py`**: Consumes PCAPs and compiles stateful flow logic (session recreation). Recreates exactly what CICFlowMeter did for the model's training data.
3. **`main.py (Backend)`**: The brain. Normalizes ingress JSON, runs StandardScaler transformations, and executes the `RandomForestClassifier`. Integrates the AI output with the hardcoded network rules for hybrid detection.
4. **`defense.py (IPS)`**: Implements the 6-layer defense pipeline. Talks directly to the Linux Kernel via `subprocess` to manipulate `iptables` rules dynamically.
5. **`dashboard` (React)**: React 18 + Recharts UI providing a Security Operations Center (SOC) graphical environment via live WebSocket bindings.
