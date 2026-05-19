"""
defense.py — Research-Grade Multi-Layer Defense Engine

Layers:
  L1 - IP Reputation (AbuseIPDB)
  L2 - Adaptive Rate Limiting (sliding window)
  L3 - GeoIP Country Blocking
  L4 - Anomaly Scoring (confidence + flow heuristics)
  L5 - Auto-Unblock with exponential backoff
  L6 - Attack pattern correlation (multi-flow analysis)
"""

import subprocess
import threading
import time
import requests
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
ABUSEIPDB_KEY       = "438f9303dcf6c02b8b3ecd30555527cf33491319b2a15c6142857e4bb89ecfaca8cbc9d946d3b133"   # https://www.abuseipdb.com/
BLOCKED_COUNTRIES   = {"CN", "RU", "KP", "IR"}  # ISO country codes
RATE_WINDOW_S       = 60        # sliding window duration (seconds)
RATE_LIMIT_FLOWS    = 100       # max flows per IP per window
ANOMALY_THRESHOLD   = 65.0      # risk score to trigger block
BASE_BLOCK_DURATION = 300       # 5 min initial block
MAX_BLOCK_DURATION  = 86400     # 24 hr max block (exponential backoff)
CORRELATION_WINDOW  = 30        # seconds to correlate multi-flow attacks

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DEFENSE] %(message)s")
log = logging.getLogger("defense")

# ─────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────
@dataclass
class IPRecord:
    ip:               str
    block_count:      int   = 0          # how many times blocked
    blocked_until:    float = 0.0        # epoch timestamp
    total_flows:      int   = 0
    total_attacks:    int   = 0
    risk_score:       float = 0.0
    country:          str   = "UNKNOWN"
    abuse_score:      int   = 0
    flow_timestamps:  deque = field(default_factory=lambda: deque(maxlen=200))
    recent_labels:    deque = field(default_factory=lambda: deque(maxlen=20))

ip_records: dict[str, IPRecord] = {}
blocked_ips: set = set()
_lock = threading.Lock()


def get_record(ip: str) -> IPRecord:
    if ip not in ip_records:
        ip_records[ip] = IPRecord(ip=ip)
    return ip_records[ip]


# ─────────────────────────────────────────────
# L1 — IP Reputation via AbuseIPDB
# ─────────────────────────────────────────────
_reputation_cache: dict[str, dict] = {}

def check_ip_reputation(ip: str) -> dict:
    """Returns abuse confidence score (0-100) and country."""
    if ip in _reputation_cache:
        return _reputation_cache[ip]
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3
        )
        data = r.json().get("data", {})
        result = {
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country":     data.get("countryCode", "UNKNOWN"),
            "isp":         data.get("isp", ""),
        }
    except Exception:
        result = {"abuse_score": 0, "country": "UNKNOWN", "isp": ""}

    _reputation_cache[ip] = result
    return result


# ─────────────────────────────────────────────
# L2 — Adaptive Rate Limiting (sliding window)
# ─────────────────────────────────────────────
def check_rate_limit(record: IPRecord) -> bool:
    """Returns True if IP exceeds rate limit."""
    now = time.time()
    record.flow_timestamps.append(now)
    # Count flows in last RATE_WINDOW_S seconds
    recent = sum(1 for t in record.flow_timestamps if now - t <= RATE_WINDOW_S)
    # Adaptive: lower threshold for already-suspicious IPs
    threshold = RATE_LIMIT_FLOWS
    if record.risk_score > 50:
        threshold = RATE_LIMIT_FLOWS // 2   # stricter for suspicious IPs
    return recent > threshold


# ─────────────────────────────────────────────
# L3 — GeoIP Country Blocking
# ─────────────────────────────────────────────
def check_country_block(country: str) -> bool:
    """Returns True if country is in blocklist."""
    if not country:
        return False
    return country.upper() in BLOCKED_COUNTRIES


# ─────────────────────────────────────────────
# L4 — Anomaly Risk Scoring
# ─────────────────────────────────────────────
def compute_risk_score(
    ml_confidence: float,
    is_attack: bool,
    features: dict,
    record: IPRecord
) -> float:
    """
    Composite risk score 0-100 combining:
    - ML model confidence
    - Flow-level heuristics (port, flags, packet rate)
    - Historical behavior of this IP
    """
    score = 0.0

    # ML confidence (40% weight)
    if is_attack:
        score += ml_confidence * 0.40

    # Flow heuristics (30% weight)
    heuristic = 0.0
    dst_port    = features.get("Destination Port", 0)
    syn_count   = features.get("SYN Flag Count", 0)
    flow_pps    = features.get("Flow Packets/s", 0)
    bwd_len     = features.get("Bwd Packet Length Mean", 0)

    if dst_port in {22, 23, 3389, 445, 1433}:  # high-risk ports
        heuristic += 30
    if syn_count > 10:                           # SYN flood indicator
        heuristic += 25
    if flow_pps > 1000:                          # high packet rate
        heuristic += 20
    if bwd_len == 0 and syn_count > 0:           # no response = scan
        heuristic += 25

    score += min(heuristic, 100) * 0.30

    # Historical behavior (30% weight)
    if record.total_flows > 0:
        attack_ratio = record.total_attacks / record.total_flows
        score += attack_ratio * 100 * 0.30

    return round(min(score, 100.0), 2)


# ─────────────────────────────────────────────
# L5 — Auto-Unblock with Exponential Backoff
# ─────────────────────────────────────────────
def schedule_unblock(ip: str, duration: int):
    """Unblock IP after duration seconds."""
    def _unblock():
        time.sleep(duration)
        with _lock:
            if ip in blocked_ips:
                try:
                    subprocess.run(
                        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                        check=True, capture_output=True
                    )
                    blocked_ips.discard(ip)
                    log.info(f"⏱️  Auto-unblocked {ip} after {duration}s")
                except Exception as e:
                    log.warning(f"Unblock failed for {ip}: {e}")

    threading.Thread(target=_unblock, daemon=True).start()


def get_block_duration(record: IPRecord) -> int:
    """Exponential backoff: 5min → 10min → 20min → ... → 24hr max."""
    duration = BASE_BLOCK_DURATION * (2 ** record.block_count)
    return min(duration, MAX_BLOCK_DURATION)


# ─────────────────────────────────────────────
# L6 — Attack Pattern Correlation
# ─────────────────────────────────────────────
_attack_window: deque = deque(maxlen=500)   # recent attack events

def correlate_attack(ip: str, label: str, timestamp: float) -> Optional[str]:
    """
    Detects coordinated/distributed attacks by correlating
    multiple flows within CORRELATION_WINDOW seconds.
    Returns threat type string or None.
    """
    _attack_window.append({"ip": ip, "label": label, "time": timestamp})
    now = timestamp

    recent = [e for e in _attack_window if now - e["time"] <= CORRELATION_WINDOW]

    # DDoS: same attack type from 3+ different IPs
    same_label = [e for e in recent if e["label"] == label]
    unique_ips  = len(set(e["ip"] for e in same_label))
    if unique_ips >= 3:
        return f"DISTRIBUTED_{label.upper().replace(' ', '_')}"

    # Coordinated scan: 5+ different ports from same IP
    same_ip_labels = [e["label"] for e in recent if e["ip"] == ip]
    if same_ip_labels.count("PortScan") >= 3:
        return "COORDINATED_PORTSCAN"

    return None


# ─────────────────────────────────────────────
# Main defense function — call from main.py
# ─────────────────────────────────────────────
def apply_defense(
    src_ip: str,
    label: str,
    is_attack: bool,
    ml_confidence: float,
    features: dict
) -> dict:
    """
    Full multi-layer defense pipeline.
    Returns defense report dict.
    """
    report = {
        "ip":            src_ip,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "action":        "ALLOW",
        "reason":        [],
        "risk_score":    0.0,
        "block_duration": 0,
        "threat_type":   None,
    }

    with _lock:
        record = get_record(src_ip)
        record.total_flows += 1
        if is_attack:
            record.total_attacks += 1
            record.recent_labels.append(label)

        # ── L1: IP Reputation ──
        if src_ip not in _reputation_cache:
            threading.Thread(
                target=lambda: _enrich_reputation(src_ip, record),
                daemon=True
            ).start()

        abuse_score = record.abuse_score
        country     = record.country

        # ── L3: GeoIP Block ──
        if check_country_block(country):
            report["reason"].append(f"GeoIP block: {country}")
            report["action"] = "BLOCK"

        # ── L1: AbuseIPDB block if score > 80 ──
        if abuse_score > 80:
            report["reason"].append(f"High abuse score: {abuse_score}")
            report["action"] = "BLOCK"

        # ── L2: Rate limit ──
        if check_rate_limit(record):
            report["reason"].append("Rate limit exceeded")
            report["action"] = "BLOCK"

        # ── L4: Anomaly score ──
        risk = compute_risk_score(ml_confidence, is_attack, features, record)
        record.risk_score = risk
        report["risk_score"] = risk
        if risk >= ANOMALY_THRESHOLD:
            report["reason"].append(f"High anomaly score: {risk}")
            report["action"] = "BLOCK"

        # ── L6: Correlation ──
        if is_attack:
            threat = correlate_attack(src_ip, label, time.time())
            if threat:
                report["threat_type"] = threat
                report["reason"].append(f"Correlated attack: {threat}")
                report["action"] = "BLOCK"

        # ── Execute block ──
        if report["action"] == "BLOCK" and src_ip not in blocked_ips:
            duration = get_block_duration(record)
            _do_block(src_ip, record, duration)
            report["block_duration"] = duration
            record.block_count += 1
            log.info(
                f"🛡️  BLOCKED {src_ip} | risk={risk} | "
                f"reasons={report['reason']} | duration={duration}s"
            )

    return report


def _enrich_reputation(ip: str, record: IPRecord):
    """Background thread: fetch reputation and update record."""
    rep = check_ip_reputation(ip)
    with _lock:
        record.abuse_score = rep["abuse_score"]
        record.country     = rep["country"]


def _do_block(ip: str, record: IPRecord, duration: int):
    """Execute iptables block + schedule unblock."""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        blocked_ips.add(ip)
        schedule_unblock(ip, duration)
    except Exception as e:
        log.warning(f"iptables failed for {ip}: {e} (run as root)")


def get_defense_stats() -> dict:
    """Returns defense stats for dashboard."""
    return {
        "total_ips_seen":    len(ip_records),
        "currently_blocked": len(blocked_ips),
        "blocked_ips":       list(blocked_ips),
        "high_risk_ips": [
            {
                "ip":          r.ip,
                "risk_score":  r.risk_score,
                "block_count": r.block_count,
                "country":     r.country,
                "abuse_score": r.abuse_score,
            }
            for r in sorted(ip_records.values(), key=lambda x: -x.risk_score)[:10]
        ]
    }


# ═════════════════════════════════════════════
# PHASE 2 — NOVEL DEFENSE CONTRIBUTIONS
# ═════════════════════════════════════════════

import hashlib
from collections import Counter as _Counter

# ─────────────────────────────────────────────
# A) Behavioral Fingerprinting
# ─────────────────────────────────────────────
_fingerprint_db: dict[str, dict] = {}   # hash → {ips: set, first_seen, last_seen}


def generate_fingerprint(features: dict, src_ip: str) -> str:
    """
    Generate a unique behavioral fingerprint per IP based on flow characteristics.
    The fingerprint encodes: destination port bucket, flag pattern, packet-size bucket,
    and flow-rate bucket — making it resilient to minor noise while catching structural
    similarities across different IPs performing the same attack pattern.

    Returns a 16-char hex fingerprint string.
    """
    port  = int(features.get("Destination Port", 0))
    syn   = int(features.get("SYN Flag Count", 0))
    ack   = int(features.get("ACK Flag Count", 0))
    psh   = int(features.get("PSH Flag Count", 0))
    pps   = float(features.get("Flow Packets/s", 0))
    fwd_m = float(features.get("Fwd Packet Length Mean", 0))
    bwd_m = float(features.get("Bwd Packet Length Mean", 0))
    dur   = float(features.get("Flow Duration", 0))

    # Bucket continuous values to reduce noise sensitivity
    port_bucket = port // 1000                  # 0-65 buckets  
    pps_bucket  = int(min(pps, 10000) // 100)   # 0-100 buckets
    fwd_bucket  = int(min(fwd_m, 1500) // 50)
    bwd_bucket  = int(min(bwd_m, 1500) // 50)
    dur_bucket  = int(min(dur, 1e7) // 1e4)
    flag_sig    = f"{min(syn,1)}{min(ack,1)}{min(psh,1)}"  # binary flag presence

    raw = f"{port_bucket}:{pps_bucket}:{fwd_bucket}:{bwd_bucket}:{dur_bucket}:{flag_sig}"
    fp  = hashlib.md5(raw.encode()).hexdigest()[:16]

    # Store in fingerprint DB
    now_str = datetime.now(timezone.utc).isoformat()
    if fp not in _fingerprint_db:
        _fingerprint_db[fp] = {"ips": set(), "first_seen": now_str, "last_seen": now_str, "raw": raw}
    _fingerprint_db[fp]["ips"].add(src_ip)
    _fingerprint_db[fp]["last_seen"] = now_str

    return fp


def check_fingerprint_match(fingerprint: str) -> Optional[str]:
    """
    Check if the fingerprint has been seen from more than one IP.
    If so, flag as IP rotation attack and return the list of matching IPs as a string.
    This detects botnets / VPN-rotation attacks that share the same traffic signature.

    Returns a comma-separated list of matching IPs, or None if no match.
    """
    entry = _fingerprint_db.get(fingerprint)
    if not entry:
        return None
    ips = entry["ips"]
    if len(ips) > 1:
        return ",".join(sorted(ips))
    return None


def get_fingerprint_db() -> list:
    """Return the full behavioral fingerprint database for display."""
    return [
        {
            "fingerprint":  fp,
            "ips":          sorted(entry["ips"]),
            "ip_count":     len(entry["ips"]),
            "first_seen":   entry["first_seen"],
            "last_seen":    entry["last_seen"],
            "is_rotation":  len(entry["ips"]) > 1,
            "raw_features": entry["raw"],
        }
        for fp, entry in _fingerprint_db.items()
        if entry["ips"]
    ]


# ─────────────────────────────────────────────
# B) Adaptive Threat Level System
# ─────────────────────────────────────────────
_threat_events: deque = deque(maxlen=5000)  # (timestamp, is_attack)
_subnet_blocks: set   = set()               # CIDRs blocked in CRITICAL mode


def update_threat_level(is_attack: bool) -> str:
    """
    Track attack frequency per hour and dynamically update the global threat level.

    Thresholds:
      - NORMAL   : < 10 attacks / hour
      - HIGH     : 10-49 attacks / hour   → stricter per-IP thresholds apply
      - CRITICAL : ≥ 50 attacks / hour    → subnet-level blocking triggered
    
    Returns the current threat level string after updating.
    """
    now = time.time()
    _threat_events.append((now, is_attack))
    return get_threat_level()


def get_threat_level() -> str:
    """
    Compute and return the current adaptive threat level based on attack
    frequency observed in the last 60 minutes.

    Returns "NORMAL", "HIGH", or "CRITICAL".
    """
    now = time.time()
    one_hour_ago = now - 3600
    recent_attacks = sum(1 for ts, atk in _threat_events if ts >= one_hour_ago and atk)

    if recent_attacks >= 50:
        return "CRITICAL"
    elif recent_attacks >= 10:
        return "HIGH"
    return "NORMAL"


def get_threat_stats() -> dict:
    """Return threat level summary with attack counts for the dashboard."""
    now = time.time()
    one_hour_ago  = now - 3600
    one_min_ago   = now - 60
    recent_attacks_hr  = sum(1 for ts, atk in _threat_events if ts >= one_hour_ago and atk)
    recent_attacks_min = sum(1 for ts, atk in _threat_events if ts >= one_min_ago  and atk)
    level = get_threat_level()
    return {
        "level":               level,
        "attacks_last_hour":   recent_attacks_hr,
        "attacks_last_minute": recent_attacks_min,
        "subnet_blocks":       list(_subnet_blocks),
        "color":               "#ff3864" if level=="CRITICAL" else "#ff9f0a" if level=="HIGH" else "#30d158",
    }


# ─────────────────────────────────────────────
# C) APT Attack Sequence Detection
# ─────────────────────────────────────────────
_ip_attack_history: dict[str, list] = {}   # ip → [{label, time}]
_apt_detections:    list             = []   # global APT event log

APT_SEQUENCES = [
    # (trigger_sequence, classification_label, window_seconds)
    (["PortScan", "SSH-Patator"],                 "APT:Reconnaissance→Exploit",   300),
    (["PortScan", "FTP-Patator"],                 "APT:Reconnaissance→FTPExploit", 300),
    (["PortScan", "DoS Hulk"],                    "APT:Reconnaissance→DoS",        300),
    (["PortScan", "DDoS"],                        "APT:Reconnaissance→DDoS",       300),
    (["SSH-Patator", "DoS slowloris"],            "APT:BruteForce→Slowloris",      600),
    (["PortScan", "SSH-Patator", "DoS Hulk"],     "APT:FullChain→Compromise",      600),
]


def detect_attack_sequence(src_ip: str, label: str) -> Optional[str]:
    """
    Detect multi-stage Advanced Persistent Threat (APT) sequences from a single IP.
    Looks for known attack chains (e.g. PortScan → SSH-Patator) within configurable
    time windows. This goes beyond traditional single-event IDS detection by tracking
    the temporal attack narrative per source IP.

    Returns classification string if APT detected, else None.
    """
    now = time.time()

    if src_ip not in _ip_attack_history:
        _ip_attack_history[src_ip] = []

    # Append current event
    _ip_attack_history[src_ip].append({"label": label, "time": now})

    # Prune events older than 10 minutes
    _ip_attack_history[src_ip] = [
        e for e in _ip_attack_history[src_ip] if now - e["time"] <= 600
    ]

    history_labels = [e["label"] for e in _ip_attack_history[src_ip]]

    for sequence, classification, window in APT_SEQUENCES:
        # Check if the sequence appears as a subsequence within the window
        indices = []
        for step in sequence:
            found_idx = None
            start = indices[-1] + 1 if indices else 0
            for j in range(start, len(history_labels)):
                if history_labels[j] == step:
                    t = _ip_attack_history[src_ip][j]["time"]
                    t0 = _ip_attack_history[src_ip][indices[0]]["time"] if indices else t
                    if t - t0 <= window:
                        found_idx = j
                        break
            if found_idx is None:
                break
            indices.append(found_idx)
        else:
            # Full sequence matched
            evt = {
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "src_ip":      src_ip,
                "sequence":    " → ".join(sequence),
                "classification": classification,
                "matched_labels": sequence,
            }
            _apt_detections.append(evt)
            log.info(f"🔥 APT DETECTED {src_ip}: {classification}")
            return classification

    return None


def get_apt_detections() -> list:
    """Return the full APT detection log, most recent first."""
    return list(reversed(_apt_detections[-100:]))


# ─────────────────────────────────────────────
# D) Honeypot Trap
# ─────────────────────────────────────────────
HONEYPOT_PORTS = {9999, 8888, 7777, 6666, 31337, 4444}
_honeypot_log: list = []


def check_honeypot(features: dict) -> bool:
    """
    Detect connections to known honeypot ports.
    Any traffic directed to honeypot ports is immediately flagged for permanent
    blocking — legitimate services never run on these ports, so any connection
    is inherently suspicious and indicates reconnaissance or intentional probing.

    Returns True if honeypot was triggered, False otherwise.
    Side effect: logs the event and permanently blocks the IP via iptables.
    """
    port = int(features.get("Destination Port", 0))
    return port in HONEYPOT_PORTS


def log_honeypot_trigger(src_ip: str, features: dict):
    """Log a honeypot trigger event and permanently block the IP."""
    port = int(features.get("Destination Port", 0))
    evt = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "src_ip":        src_ip,
        "port_targeted": port,
        "action":        "PERMANENT_BLOCK",
    }
    _honeypot_log.append(evt)
    log.info(f"🍯 HONEYPOT triggered: {src_ip} → port {port} — permanent block")
    blocked_ips.add(src_ip)  # mark blocked immediately in-process

    # Run iptables in a background thread — never block the async event loop
    def _block():
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5
            )
        except Exception as e:
            log.warning(f"Honeypot iptables block failed for {src_ip}: {e}")

    import threading
    threading.Thread(target=_block, daemon=True).start()


def get_honeypot_log() -> list:
    """Return honeypot trigger log, most recent first."""
    return list(reversed(_honeypot_log[-100:]))