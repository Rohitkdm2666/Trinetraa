import json
import time
import numpy as np
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP

# ─────────────────────────────────────────────
# Flow storage: groups packets by 5-tuple
# ─────────────────────────────────────────────
flows = defaultdict(lambda: {
    "fwd_packets": [], "bwd_packets": [],
    "fwd_iat": [],    "bwd_iat": [],
    "start_time": None, "last_fwd_time": None, "last_bwd_time": None,
    "syn": 0, "ack": 0, "psh": 0,
    "dst_port": 0,
})

FLOW_TIMEOUT = 60  # seconds — finalize flow after this


def get_flow_key(pkt):
    if IP not in pkt:
        return None
    proto = "TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
    layer = pkt[TCP] if TCP in pkt else (pkt[UDP] if UDP in pkt else None)
    if layer is None:
        return None
    return (pkt[IP].src, pkt[IP].dst, layer.sport, layer.dport, proto)


def extract_features(flow, dst_port) -> dict:
    """Convert raw flow data into 18 model features."""
    fwd = flow["fwd_packets"]
    bwd = flow["bwd_packets"]

    all_pkts  = fwd + bwd
    duration  = max((flow["start_time"] and (time.time() - flow["start_time"])) or 1e-6, 1e-6)

    def safe(arr, fn):
        return fn(arr) if arr else 0.0

    total_bytes = sum(all_pkts)
    features = {
        "Destination Port":       dst_port,
        "Flow Duration":          duration * 1e6,                        # microseconds
        "Total Fwd Packets":      len(fwd),
        "Total Backward Packets": len(bwd),
        "Fwd Packet Length Max":  safe(fwd, max),
        "Fwd Packet Length Min":  safe(fwd, min),
        "Fwd Packet Length Mean": safe(fwd, np.mean),
        "Bwd Packet Length Max":  safe(bwd, max),
        "Bwd Packet Length Min":  safe(bwd, min),
        "Bwd Packet Length Mean": safe(bwd, np.mean),
        "Flow Bytes/s":           total_bytes / duration,
        "Flow Packets/s":         len(all_pkts) / duration,
        "Fwd IAT Mean":           safe(flow["fwd_iat"], np.mean),
        "Bwd IAT Mean":           safe(flow["bwd_iat"], np.mean),
        "PSH Flag Count":         flow["psh"],
        "SYN Flag Count":         flow["syn"],
        "ACK Flag Count":         flow["ack"],
        "Packet Length Mean":     safe(all_pkts, np.mean),
    }
    return features


def process_packet(pkt, callback=None):
    """Called for every captured packet."""
    key = get_flow_key(pkt)
    if key is None:
        return

    src_ip, dst_ip, sport, dport, proto = key
    flow = flows[key]
    now  = time.time()
    size = len(pkt)

    if flow["start_time"] is None:
        flow["start_time"] = now
        flow["dst_port"]   = dport

    # Determine direction: forward = src matches flow origin
    is_fwd = (pkt[IP].src == src_ip)

    if is_fwd:
        if flow["last_fwd_time"]:
            flow["fwd_iat"].append((now - flow["last_fwd_time"]) * 1e6)
        flow["last_fwd_time"] = now
        flow["fwd_packets"].append(size)
    else:
        if flow["last_bwd_time"]:
            flow["bwd_iat"].append((now - flow["last_bwd_time"]) * 1e6)
        flow["last_bwd_time"] = now
        flow["bwd_packets"].append(size)

    # TCP flags
    if TCP in pkt:
        flags = pkt[TCP].flags
        if flags & 0x02: flow["syn"] += 1
        if flags & 0x10: flow["ack"] += 1
        if flags & 0x08: flow["psh"] += 1

    # Finalize flow if timed out
    if now - flow["start_time"] >= FLOW_TIMEOUT:
        features = extract_features(flow, flow["dst_port"])
        del flows[key]
        if callback:
            callback(features, src_ip)


def start_capture(interface="eth0", callback=None, packet_count=0):
    """
    Start live packet capture.
    callback(features: dict, src_ip: str) is called per completed flow.
    packet_count=0 means capture indefinitely.
    """
    print(f"[*] Capturing on {interface} ...")
    sniff(
        iface=interface,
        prn=lambda pkt: process_packet(pkt, callback=callback),
        count=packet_count,
        store=False
    )


def extract_from_pcap(pcap_file, callback=None):
    """
    Extract features from a saved .pcap file (for testing without live traffic).
    Usage: extract_from_pcap("capture.pcap", callback=my_fn)
    """
    print(f"[*] Reading {pcap_file} ...")
    sniff(
        offline=pcap_file,
        prn=lambda pkt: process_packet(pkt, callback=callback),
        store=False
    )
    # Flush remaining flows
    for key, flow in list(flows.items()):
        if flow["fwd_packets"] or flow["bwd_packets"]:
            features = extract_features(flow, flow["dst_port"])
            src_ip = key[0]
            if callback:
                callback(features, src_ip)
    flows.clear()


# ─────────────────────────────────────────────
# Quick test — run directly to verify features
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import json, pickle

    model   = pickle.load(open("model_artifacts/model.pkl",  "rb"))
    scaler  = pickle.load(open("model_artifacts/scaler.pkl", "rb"))
    encoder = pickle.load(open("model_artifacts/label_encoder.pkl", "rb"))
    feature_names = json.load(open("model_artifacts/features.json"))

    def on_flow(features, src_ip):
        row    = [features.get(f, 0) for f in feature_names]
        scaled = scaler.transform([row])
        pred   = model.predict(scaled)[0]
        label  = encoder.inverse_transform([pred])[0]
        print(f"  [{src_ip}] → {label}  | features: {features}")

    # Test on pcap file
    extract_from_pcap("test.pcap", callback=on_flow)

    # OR live capture (requires root):
    # start_capture(interface="eth0", callback=on_flow)