import subprocess
import threading
import time
import os

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
INTERFACE   = "wlp0s20f3"   # your WiFi interface
PCAP_DIR    = "./pcap_files"
ROTATION_S  = 30            # new pcap every 30 seconds
os.makedirs(PCAP_DIR, exist_ok=True)


def capture_loop(on_new_pcap=None):
    """
    Continuously captures packets in 30s chunks.
    Calls on_new_pcap(filepath) after each chunk is saved.
    """
    print(f"[*] Starting capture on {INTERFACE} (rotating every {ROTATION_S}s)")
    while True:
        timestamp = int(time.time())
        filepath  = f"{PCAP_DIR}/capture_{timestamp}.pcap"

        # Capture for ROTATION_S seconds
        cmd = [
            "tcpdump",
            "-i", INTERFACE,
            "-w", filepath,
            "-G", str(ROTATION_S),   # rotate every N seconds
            "-W", "1",               # only 1 file per run (we loop manually)
            "--immediate-mode",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(ROTATION_S + 1)   # wait for capture to finish
        proc.terminate()

        if os.path.exists(filepath) and os.path.getsize(filepath) > 24:
            print(f"[+] Saved: {filepath}")
            if on_new_pcap:
                threading.Thread(
                    target=on_new_pcap,
                    args=(filepath,),
                    daemon=True
                ).start()
        else:
            print(f"[!] Empty capture, skipping: {filepath}")


# ─────────────────────────────────────────────
# Run standalone to test capture only
# ─────────────────────────────────────────────
if __name__ == "__main__":
    def on_new_pcap(filepath):
        print(f"    → Ready to process: {filepath}")
        # In full pipeline: feature_extractor.extract_from_pcap(filepath, callback)

    try:
        capture_loop(on_new_pcap=on_new_pcap)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped.")