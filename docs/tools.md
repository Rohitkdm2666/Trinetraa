# AEGIS Tool Stack

AEGIS relies heavily on a deeply integrated stack of Python tools and external databases to seamlessly unify the OS network card with the graphical UI.

## `tcpdump` & PCAP Management
**Core function:** `tcpdump -i eth0 -w dump.pcap`
Rather than keeping infinite buffers in RAM, AEGIS runs shell subprocesses of `tcpdump` to capture packets natively at ring-0. It writes short 5-10 second cyclical buffers (`.pcap`) and purges them to prevent the drive from filling up.

## `Scapy` (Feature Extractor)
Scapy is a powerful interactive packet manipulation library. AEGIS utilizes Scapy to iterate through the PCAP buffers dumped by `tcpdump`.
- Groups independent packets into continuous sessions using `(src_ip, src_port, dst_ip, dst_port, protocol)` tuples.
- Generates temporal mathematics (IAT - Inter-Arrival Time).

## `iptables` (Defense Linux Firewall)
The absolute defense floor. When our Python model dictates a threat is present, it issues `subprocess.run(["iptables", "-A", "INPUT", "-s", IP, "-j", "DROP"])`. 
This is a ring-zero instruction that terminates the packet inside the Linux kernel *before* it even reaches the FastAPI WebServer, rendering the attack physically impossible to execute.

## `AbuseIPDB`
Cloud-native crowdsourced IP blacklist API. Serves as Layer 1 defense to rapidly terminate connections from known-botnets to save CPU load for the ML model.

## `FastAPI` & `Uvicorn`
Asynchronous python web framework. Extremely fast. 
- Utilizes `Pydantic` models to strictly validate incoming `.json` flow vectors from the Scapy extractor.
- Exposes `WebSocket` endpoints natively to push JSON to the Dashboard with sub-millisecond latency.

## `React` & `Recharts`
Dashboard ecosystem decoupled from the python environment. Relies entirely on `WebSocket` streams and REST polling for analytics representation.

## `Supabase` (Database)
Managed PostgreSQL backend.
- Permanently stores triggered AI Alerts (`alerts` table) with the IP footprint and Timestamp, rendering the data auditable.
