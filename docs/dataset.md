# Dataset Information: CICIDS2017

AEGIS is trained specifically on the **Intrusion Detection Evaluation Dataset (CICIDS2017)** provided by the Canadian Institute for Cybersecurity. 

## Dataset Profile
The CICIDS2017 dataset is considered the gold-standard benchmark in modern net-sec ML because:
- It includes realistic background traffic patterns (B-Profile system).
- It contains up-to-date attack vectors (unlike the severely outdated KDD99 or NSL-KDD).
- It maps pcap files to labeled CSV flows generated via CICFlowMeter.

## Preprocessing Pipeline applied in AEGIS

1. **Null/Infinity Purging**: Real-world packets occasionally generate mathematically infinite flow ratios. These are stripped via `df.replace([np.inf, -np.inf], np.nan).dropna()`.
2. **Feature Condensation**: CICFlowMeter exports 78 parameters. Features prone to ID-leakage (IPs) or spatial variance (MAC addresses) were discarded in favor of 18 strictly numerical interaction parameters.
3. **Data Imbalance & Class Balancing**:
   - The unadulterated dataset exhibits a 9:1 ratio of `BENIGN` to `ATTACK` flows.
   - Without balancing, the RF Model overfits to predicting benign.
   - **Solution**: We implement targeted Undersampling. We dynamically cap `BENIGN` samples at a maximum of `3 * total_attacks`. Furthermore, the `class_weight='balanced'` parameter inside the SKLearn RandomForest tree penalizes errors made on under-represented classes (like Slowloris).

## Attack Classes Supported

| Vector        | Description |
|---------------|-------------|
| BENIGN        | Whitelisted, authorized corporate network traffic. |
| DDoS          | Distributed Denial of Service (massive packet floods). |
| PortScan      | Reconnaissance via TCP protocol fuzzing across multiple ports. |
| DoS Hulk      | HTTP-based application-level floods causing rapid pool exhaustion. |
| DoS GoldenEye | Stealthy HTTP get-requests bypassing traditional caching thresholds. |
| Slowloris     | Extremely low-PPS headers-only keepalives designed to starve sockets. |
| SSH-Patator   | Bruteforcing on TCP Port 22. |
| FTP-Patator   | Bruteforcing on TCP Port 21. |
| Web Brute     | Sequential GET/POST application login attempts. |
