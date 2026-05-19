import argparse
import requests
import json
import random
import time
from datetime import datetime

# ─────────────────────────────────────────────
# Feature Templates Based on CICIDS2017 Profiles
# ─────────────────────────────────────────────
ATTACK_PROFILES = {
    "portscan": {
        "Destination Port": 0,           # randomized in loop
        "Flow Duration": 50,
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,
        "Fwd Packet Length Max": 0,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 40,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,     # Condition: bwd == 0
        "Flow Bytes/s": 800000,
        "Flow Packets/s": 20000,
        "Fwd IAT Mean": 20,
        "Bwd IAT Mean": 0,
        "PSH Flag Count": 0,
        "SYN Flag Count": 35,            # Condition: syn > 30
        "ACK Flag Count": 0,
        "Packet Length Mean": 40
    },
    "ddos": {
        "Destination Port": 80,
        "Flow Duration": 10000,
        "Total Fwd Packets": 50,
        "Total Backward Packets": 50,
        "Fwd Packet Length Max": 800,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 400,
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Flow Bytes/s": 10000000,
        "Flow Packets/s": 500,           # Condition: pps > 200
        "Fwd IAT Mean": 100,
        "Bwd IAT Mean": 100,
        "PSH Flag Count": 0,
        "SYN Flag Count": 85,            # Condition: syn > 80
        "ACK Flag Count": 0,             # Condition: ack == 0
        "Packet Length Mean": 400
    },
    "dos_hulk": {
        "Destination Port": 80,
        "Flow Duration": 20000,
        "Total Fwd Packets": 100,
        "Total Backward Packets": 100,
        "Fwd Packet Length Max": 500,
        "Fwd Packet Length Min": 100,
        "Fwd Packet Length Mean": 200,   # Condition: fwd_mean > 100
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Flow Bytes/s": 50000000,
        "Flow Packets/s": 2500,          # Condition: pps > 2000
        "Fwd IAT Mean": 50,
        "Bwd IAT Mean": 50,
        "PSH Flag Count": 1,
        "SYN Flag Count": 0,
        "ACK Flag Count": 1,
        "Packet Length Mean": 200
    },
    "dos_goldeneye": {
        "Destination Port": 80,          # Condition: port in 80,443,8080
        "Flow Duration": 15000,
        "Total Fwd Packets": 80,
        "Total Backward Packets": 80,
        "Fwd Packet Length Max": 300,
        "Fwd Packet Length Min": 100,
        "Fwd Packet Length Mean": 150,
        "Bwd Packet Length Max": 50,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 20,
        "Flow Bytes/s": 40000000,
        "Flow Packets/s": 2100,          # Condition: pps > 2000
        "Fwd IAT Mean": 60,
        "Bwd IAT Mean": 60,
        "PSH Flag Count": 1,
        "SYN Flag Count": 0,
        "ACK Flag Count": 1,
        "Packet Length Mean": 150
    },
    "dos_slowloris": {
        "Destination Port": 80,
        "Flow Duration": 600000,         # Condition: dur > 500000
        "Total Fwd Packets": 5,
        "Total Backward Packets": 5,
        "Fwd Packet Length Max": 40,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 30,    # Condition: fwd_mean < 50, fwd > 10 (Wait, main.py checks fwd > 10 for fwd packet length mean!)
        "Bwd Packet Length Max": 0,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 0,
        "Flow Bytes/s": 10,
        "Flow Packets/s": 2,             # Condition: pps < 5
        "Fwd IAT Mean": 100000,
        "Bwd IAT Mean": 100000,
        "PSH Flag Count": 0,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1,
        "Packet Length Mean": 30
    },
    "ssh_brute": {
        "Destination Port": 22,          # Condition: port == 22
        "Flow Duration": 50000,
        "Total Fwd Packets": 20,
        "Total Backward Packets": 20,
        "Fwd Packet Length Max": 200,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 60,    # Condition: fwd > 50
        "Bwd Packet Length Max": 300,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 150,
        "Flow Bytes/s": 5000,
        "Flow Packets/s": 100,
        "Fwd IAT Mean": 500,
        "Bwd IAT Mean": 500,
        "PSH Flag Count": 15,            # Condition: psh > 10 (SSH-Patator)
        "SYN Flag Count": 1,
        "ACK Flag Count": 20,
        "Packet Length Mean": 105
    },
    "ftp_brute": {
        "Destination Port": 21,
        "Flow Duration": 60000,
        "Total Fwd Packets": 15,
        "Total Backward Packets": 15,
        "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 50,
        "Bwd Packet Length Max": 200,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 100,
        "Flow Bytes/s": 4000,
        "Flow Packets/s": 50,
        "Fwd IAT Mean": 800,
        "Bwd IAT Mean": 800,
        "PSH Flag Count": 5,
        "SYN Flag Count": 1,
        "ACK Flag Count": 14,
        "Packet Length Mean": 75
    },
    "web_brute": {
        "Destination Port": 80,
        "Flow Duration": 45000,
        "Total Fwd Packets": 25,
        "Total Backward Packets": 25,
        "Fwd Packet Length Max": 500,
        "Fwd Packet Length Min": 50,
        "Fwd Packet Length Mean": 250,
        "Bwd Packet Length Max": 1500,
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": 700,
        "Flow Bytes/s": 15000,
        "Flow Packets/s": 80,
        "Fwd IAT Mean": 400,
        "Bwd IAT Mean": 400,
        "PSH Flag Count": 10,
        "SYN Flag Count": 1,
        "ACK Flag Count": 24,
        "Packet Length Mean": 475
    }
}

API_URL = "http://127.0.0.1:8000/predict"

def get_random_ip():
    return f"{random.randint(11, 250)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"

def add_noise(value):
    """Adds +/- 10% noise to numeric features to look realistic."""
    if value == 0:
        return 0
    noise_ratio = random.uniform(0.9, 1.1)
    if isinstance(value, int):
        return int(value * noise_ratio)
    return float(value * noise_ratio)

def simulate_attack(attack_type):
    if attack_type not in ATTACK_PROFILES:
        print(f"[-] Unknown attack type: {attack_type}")
        return

    base_profile = ATTACK_PROFILES[attack_type]
    num_requests = random.randint(10, 20)
    print(f"\n[🚀] Launching '{attack_type}' simulation ({num_requests} requests)")
    print("-" * 50)

    target_ip = get_random_ip()

    for i in range(num_requests):
        features = {}
        for k, v in base_profile.items():
            features[k] = add_noise(v)
            
        # Specific overrides to prevent breaking rules
        if attack_type == "portscan":
            features["Destination Port"] = random.randint(23, 65000)
            features["SYN Flag Count"] = max(31, int(features["SYN Flag Count"]))
            features["Bwd Packet Length Mean"] = 0
            features["Fwd Packet Length Mean"] = max(11, float(features["Fwd Packet Length Mean"]))
            features["Total Fwd Packets"] = max(11, int(features["Total Fwd Packets"]))
        elif attack_type == "ddos":
            features["SYN Flag Count"] = max(81, int(features["SYN Flag Count"]))
            features["ACK Flag Count"] = 0
            features["Flow Packets/s"] = max(201, float(features["Flow Packets/s"]))
        elif attack_type == "dos_hulk":
            features["Flow Packets/s"] = max(2001, float(features["Flow Packets/s"]))
            features["Fwd Packet Length Mean"] = max(101, float(features["Fwd Packet Length Mean"]))
        elif attack_type == "dos_goldeneye":
            features["Destination Port"] = random.choice([80, 443, 8080])
            features["Flow Packets/s"] = max(2001, float(features["Flow Packets/s"]))
        elif attack_type == "dos_slowloris":
            features["Flow Duration"] = max(500001, float(features["Flow Duration"]))
            features["Fwd Packet Length Mean"] = random.uniform(11, 49) # >10 and <50
            features["Flow Packets/s"] = random.uniform(1, 4) # <5
        elif attack_type == "ssh_brute":
            features["Destination Port"] = 22
            features["Fwd Packet Length Mean"] = max(51, float(features["Fwd Packet Length Mean"]))
            features["PSH Flag Count"] = max(11, int(features["PSH Flag Count"]))
        elif attack_type == "honeypot":
            # MUST pin port — add_noise() would randomize it away from the honeypot set
            features["Destination Port"] = 9999

        # Payload structure expected by main.py
        payload = {
            "src_ip": target_ip,
            "features": features
        }

        try:
            start = time.time()
            resp = requests.post(API_URL, json=payload, timeout=10)
            elapsed = time.time() - start
            data = resp.json()
            
            label = data.get("label", "Unknown")
            action = data.get("action", "ALLOW")
            risk = data.get("risk_score", 0)
            
            # Formatted console output
            color = "\033[91m" if action == "BLOCK" else "\033[93m"
            reset = "\033[0m"
            print(f"[{i+1}/{num_requests}] {payload['src_ip']:<15} -> {label:<15} | Risk: {risk:>5.1f} | Action: {color}{action:<5}{reset} ({elapsed*1000:.0f}ms)")
            
        except requests.exceptions.ConnectionError:
            print("[-] Error: Could not connect to AEGIS API at 127.0.0.1:8000")
            break
            
        # Small realistic delay between flows
        time.sleep(random.uniform(0.05, 0.3))

    print("-" * 50)
    print("[+] Simulation complete.\n")

# ─────────────────────────────────────────────
# Phase 2 Attack Profiles
# ─────────────────────────────────────────────
ATTACK_PROFILES["honeypot"] = {
    "Destination Port": 9999,       # Honeypot port — triggers immediate permanent block
    "Flow Duration": 5000,
    "Total Fwd Packets": 3,
    "Total Backward Packets": 0,
    "Fwd Packet Length Max": 60,
    "Fwd Packet Length Min": 40,
    "Fwd Packet Length Mean": 50,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0,
    "Flow Bytes/s": 3000,
    "Flow Packets/s": 600,
    "Fwd IAT Mean": 5000,
    "Bwd IAT Mean": 0,
    "PSH Flag Count": 1,
    "SYN Flag Count": 1,
    "ACK Flag Count": 0,
    "Packet Length Mean": 50
}


def simulate_apt_sequence():
    """
    Simulate a multi-stage APT attack:
      Phase 1 — PortScan  (reconnaissance)
      Wait    — 10 seconds (simulating attacker analysis pause)
      Phase 2 — SSH Brute Force (exploitation)
    Uses the SAME source IP to trigger APT sequence detection in the backend.
    """
    target_ip = get_random_ip()
    print(f"\n[🎯] Launching APT SEQUENCE simulation")
    print(f"     Target IP: {target_ip}")
    print("=" * 50)

    # Phase 1: Reconnaissance (PortScan)
    print("\n[Phase 1/2] RECONNAISSANCE — PortScan (5 flows)")
    print("-" * 50)
    base = ATTACK_PROFILES["portscan"]
    for i in range(5):
        features = {k: add_noise(v) for k, v in base.items()}
        features["Destination Port"]     = random.randint(23, 65000)
        features["SYN Flag Count"]       = max(31, int(features["SYN Flag Count"]))
        features["Bwd Packet Length Mean"] = 0
        features["Fwd Packet Length Mean"] = max(11, float(features["Fwd Packet Length Mean"]))
        features["Total Fwd Packets"]    = max(11, int(features["Total Fwd Packets"]))
        payload = {"src_ip": target_ip, "features": features}
        try:
            start = time.time()
            resp  = requests.post(API_URL, json=payload, timeout=10)
            data  = resp.json()
            elapsed = time.time() - start
            print(f"  [{i+1}/5] {target_ip:<15} -> {data.get('label','?'):<15} | Risk: {data.get('risk_score',0):>5.1f} | \033[93m{data.get('action','?')}\033[0m ({elapsed*1000:.0f}ms)")
        except Exception as e:
            print(f"  [{i+1}/5] Error: {e}")
        time.sleep(random.uniform(0.1, 0.3))

    # Simulated pause between attack phases
    print(f"\n[⏳] Attacker pausing 10 seconds (simulating recon analysis)...")
    time.sleep(10)

    # Phase 2: Exploitation (SSH Brute Force)
    print("\n[Phase 2/2] EXPLOITATION — SSH-Patator (5 flows)")
    print("-" * 50)
    base2 = ATTACK_PROFILES["ssh_brute"]
    for i in range(5):
        features = {k: add_noise(v) for k, v in base2.items()}
        features["Destination Port"]     = 22
        features["Fwd Packet Length Mean"] = max(51, float(features["Fwd Packet Length Mean"]))
        features["PSH Flag Count"]       = max(11, int(features["PSH Flag Count"]))
        payload = {"src_ip": target_ip, "features": features}
        try:
            start = time.time()
            resp  = requests.post(API_URL, json=payload, timeout=10)
            data  = resp.json()
            elapsed = time.time() - start
            apt = data.get("apt_detected", None)
            apt_str = f" \033[35m🔥 {apt}\033[0m" if apt else ""
            print(f"  [{i+1}/5] {target_ip:<15} -> {data.get('label','?'):<15} | Risk: {data.get('risk_score',0):>5.1f} | \033[91m{data.get('action','?')}\033[0m ({elapsed*1000:.0f}ms){apt_str}")
        except Exception as e:
            print(f"  [{i+1}/5] Error: {e}")
        time.sleep(random.uniform(0.1, 0.3))

    print("=" * 50)
    print("[+] APT Sequence simulation complete.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Realistic Attack Simulator")
    parser.add_argument("--attack", type=str, required=True,
                        choices=list(ATTACK_PROFILES.keys()) + ["apt_sequence"],
                        help="Type of attack to simulate")

    args = parser.parse_args()

    if args.attack == "apt_sequence":
        simulate_apt_sequence()
    else:
        simulate_attack(args.attack)
