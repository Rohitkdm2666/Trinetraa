# AEGIS Viva Questions & Answers

## Sec 1: Dataset & Data Representation 
**Q1: What dataset did you use for training, and why?**
A: We used the CICIDS2017 dataset from the Canadian Institute for Cybersecurity because it contains modern threat vectors, unlike older legacy datasets (KDD99), and provides realistic background noise.

**Q2: What was the primary format of your data?**
A: The data was strictly tabular CSV files processed into feature arrays, extracted from the underlying PCAP dumps.

**Q3: Explain the class imbalance problem in your data.**
A: Over 85% of traffic in CICIDS2017 is benign. If a model was trained directly, it would just predict "BENIGN" 100% of the time to achieve 85% accuracy. We undersampled the BENIGN class and utilized `class_weight='balanced'` to correct for this.

**Q4: Which extraction library was used for network flow generation?**
A: Originally `CICFlowMeter` was used by the researchers, but for real-time extraction we utilized the Python `scapy` library.

**Q5: Why reduce 78 features to 18 features?**
A: Real-time execution latency. Scapy cannot linearly compute complex derivatives across massive rolling flow windows in real-time. We picked 18 statistically significant, uncorrelated, and O(1) computationally cheap features.

## Sec 2: Machine Learning Architecture
**Q6: What specific ML algorithm drives AEGIS?**
A: A supervised `RandomForestClassifier`.

**Q7: Differentiate Deep Learning from Random Forest in this context.**
A: Deep learning required excessive parameters and slow sequential inference times unsuited for inline execution. Random Forests evaluate hundreds of threshold trees in parallel natively on the CPU, achieving sub-15ms latencies.

**Q8: What is StandardScaler and why is it mandatory?**
A: ML models optimize weights via distance algebra. If `Duration` is bounded at `1,000,000` and `PPS` at `10`, the model assumes `Duration` is artificially more critical. StandardScaler standardizes variables to mean=0, variance=1.

**Q9: Can the ML model adapt dynamically to new unheard-of traffic?**
A: No, it is a supervised model. It interpolates between the specific parameters it mapped to known threats during its training split.

**Q10: Explain what Gini Impurity implies for Feature Selection.**
A: Gini tracks the probability of incorrect classification. Nodes that heavily reduce Gini impurity are deemed highly critical "features".

**Q11: Why is Precision vs Recall a tradeoff?**
A: Because catching *every* attack (Recall=100) mathematically forces the model to be extremely sensitive, leading to falsely classifying benign users as threats (Precision plummets).

**Q12: Is your model susceptible to adversarial noise?**
A: Yes. Attackers padding payloads with junk bytes can synthetically alter the statistical flow signatures (like Mean Packet Length) to manipulate inference outputs.

**Q13: How big is your model in memory?**
A: The serialized `model.pkl` is roughly 15MB. 

## Sec 3: Backend & Deployment Stack
**Q14: Explain the role of FastAPI.**
A: FastAPI is the asynchronous web broker routing `.json` from the packet sniffer into the ML model and executing defense algorithms.

**Q15: Why Python? Isn't it slow?**
A: True raw python loops are slow. However, FastAPI is built on `uvloop` (C-optimized), and our ML runs via heavily vectorized Numpy operations in C.

**Q16: How does the Dashboard get instant ML alerts?**
A: We implemented WebSockets (`ws://`). Instead of the frontend requesting data every second (polling), the server leaves a persistent multiplexed tunnel open and instantly pushes JSON objects upon inference via `await ws.send_json(data)`.

**Q17: Describe your Database schema.**
A: We utilize Supabase (PostgreSQL). The primary `alerts` table logs Timestamp, IP, Label, Confidence, and Action required for system auditing.

## Sec 4: Deep Defense Engine & Firewall integration 
**Q18: What is Layer 1 of your defense?**
A: Reputation verification against the RESTful AbuseIPDB API for crowdsourced blacklist validation.

**Q19: How do you manipulate traffic routing inside python?**
A: We don't. Python has no network permissions. We spawn OS-level binaries using the `subprocess` module to manually inject rules into `iptables`.

**Q20: Explain your Hybrid Approach. (Rules vs ML)**
A: The ML model excels at zero-day generalizations. Rules excel at unambiguous brute force identifiers. If a known static threshold is exceeded (e.g., 20,000 SYN packets with 0 Acks), the rule immediately overrides the ML prediction with a 'DDoS' claim.

**Q21: Provide an example of a Layer 4 Anomaly heuristic.**
A: If a flow exclusively queries destination port 1433 (MSSQL) and the ML confidence returns >60% threat probability, the composite heuristic pushes the Risk Score into the red threshold.

**Q22: Why not just block malicious IPs forever?**
A: Consumer IP addresses rotate dynamically via DHCP. Blocking an IP forever might lock legitimate neighboring users out later. We use Exponential Backoff.

**Q23: Describe the Exponential Backoff.**
A: First block is 5 mins, then 10, then 20... capping at 24 hours.

**Q24: How does AEGIS Correlate network events? (L6)**
A: It analyzes incoming flags. If 5 localized ports are queried by 1 IP linearly, it identifies "COORDINATED_PORTSCAN".

## Sec 5: Challenges & Development
**Q25: What was the absolute hardest hurdle during development?**
A: Migrating static PCAP training workflows into live Scapy sniffing. CICFlowMeter generates 78 features entirely offline. Mimicking its mathematical output identically in real-time python was incredibly volatile.

**Q26: How do you bypass missing features in real-time?**
A: Variables like `Idle Time Max` require sniffing the entire flow session to its death. We abandoned them, extracting only instantaneous subset metrics (`Flow PPS`, `Packet Length Mean`).

**Q27: How can we replicate this model's success on enterprise streams (10 Gbps)?**
A: Native python sniffers crash at 10 Gbps. We would need to migrate the flow extraction logic natively inside hardware switching ASICs (like P4) or use eBPF / DPDK pipelines.

**Q28: Why use `tcpdump` instead of purely streaming via Scapy?**
A: Scapy consumes enormous structural overhead constructing raw bytes into python class objects. Writing raw bitstreams to a `.pcap` by `tcpdump` (C binary) and post-parsing it locally keeps memory entirely flat.

**Q29: Explain the simulator logic in testing.**
A: Since launching live DDoS attacks against our router is dangerous, we wrote `attack_simulator.py`. It injects procedurally generated 18-float arrays mirroring CICIDS2017 behaviors directly into the `POST /predict` API.

## Sec 6: General Networking (Core InfoSec)
**Q30: What is a SYN Flood?**
A: 3-Way Handshake abuse. Send infinite SYNs, the server allocates RAM for SYN-ACKs, and the attacker never responds. RAM suffocates.

**Q31: Distinguish DoS Hulk from Slowloris.**
A: DoS Hulk attempts volumetric HTTP request blasting. Slowloris sends malformed HTTP Headers infinitesimally slowly, forcing Apache servers to keep the thread open indefinitely.

**Q32: Distinguish PortScan vs Bruteforcing.**
A: PortScans horizontally query ports (21, 22, 80) on a single IP to identify blind spots. Bruteforce queries 1 discrete port (22) vertically pushing infinite credentials.

**Q33: How does the React UI parse Recharts data?**
A: The backend normalizes the SQL threat volume data into aggregated dictionary arrays `{name: atk, value: frequency}`, which Recharts interprets natively.

## Sec 7: Future Vision
**Q34: How could AEGIS be upgraded?**
A: Implementation of Unsupervised learning (Autoencoders) to flag anomalies completely absent from the CICIDS2017 dataset.

**Q35: Is your model biased?**
A: By definition, yes. It is purely trained on the network configurations, web topologies, and internal software stack used by the Canadian Cybersecurity Institute lab during 2017.

**Q36: Why didn't you use PcapPlusPlus?**
A: Scapy provided faster prototyping and cleaner dictionary abstraction in Python natively, albeit at slower speeds than C++.

**Q37: Could an attacker trigger an auto-block of a benign service?**
A: Yes (IP Spoofing). If an attacker sends DDoS packets but spoofs their source IP as `8.8.8.8` (Google DNS), our `iptables` rule will immediately block Google. (This is known as IPS black-holing).

**Q38: Can your software inspect HTTPS payloads?**
A: No. AEGIS strictly relies on Statistical Flow Metadata (L3/L4), which is entirely protocol and encryption agnostic. We do not run DPI (Deep Packet Inspection), which respects user privacy.

**Q39: What is SMOTE and did you use it?**
A: SMOTE (Synthetic Minority Over-sampling Technique) injects artificial noise to balance extreme minority classes. We tested it, but found raw undersampling yielded equal or better F1 results without runtime distortion.

**Q40: Final summary of AEGIS's main accomplishment?**
A: Creating a functional, end-to-end framework translating theoretical CSV ML research into a practical inline firewall daemon with a high-end UI interface, functioning natively without enterprise infrastructure.
