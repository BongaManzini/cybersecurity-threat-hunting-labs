# Network PCAP Forensics & C2 Hunting Laboratory

An advanced network security laboratory focused on **Deep Packet Inspection (DPI)**, **Statistical C2 Beacon Hunting**, and **Protocol Exfiltration Analysis**. Designed for Incident Responders and Network Security Engineers to dissect malicious PCAPs and uncover stealthy adversary infrastructure.

---

## Architecture & Tooling

```
Network-PCAP-Forensics-and-C2-Hunting/
├── tools/
│   ├── pcap_c2_beacon_analyzer.py   # Statistical delta-time & jitter beacon detector
│   └── dns_tunnel_detector.py       # Shannon entropy DNS exfiltration detector
├── cheatsheets/
│   └── wireshark_df_incident_response.md # Production Wireshark display filter cheat sheet
└── README.md                        # Master lab walkthrough
```

---

## Core Detection Heuristics

```mermaid
flowchart LR
    A["Raw PCAP / Flow Timestamps"] --> B["pcap_c2_beacon_analyzer.py"]
    B -->|Calculate Mean & StDev Delta| C{"Jitter Ratio < 25%?"}
    C -->|Yes: High Regularity| D["ALERT: Periodic C2 Beaconing Detected"]
    C -->|No: Bursty| E["Classified as Benign Traffic"]

    F["DNS Query Log Stream"] --> G["dns_tunnel_detector.py"]
    G -->|Shannon Entropy H(X)| H{"H(X) >= 3.75 & Len >= 20?"}
    H -->|Yes: Encoded Payload| I["ALERT: DNS Tunneling Exfiltration"]
    H -->|No: Natural Language| J["Classified as Benign DNS Query"]
```

### 1. Shannon Entropy for DNS Exfiltration
Adversary tunneling utilities (Iodine, dnscat2, Cobalt Strike DNS) encode arbitrary binary data (Base64, Hex, Base32) into subdomain labels:
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
Natural language subdomains (e.g. `mail.google.com`) yield entropy around $2.1 - 2.8$. Encrypted or compressed exfiltration payloads consistently yield entropy $> 3.75$.

---

## Quickstart & Verification

```bash
# Run the C2 Beacon Analyzer simulation
python3 tools/pcap_c2_beacon_analyzer.py

# Run the DNS Tunneling Detector audit
python3 tools/dns_tunnel_detector.py
```
