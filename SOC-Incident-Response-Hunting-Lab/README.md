# SOC Incident Response & Threat Hunting Laboratory

A battle-tested Security Operations Center (SOC Tier 2/3) and Digital Forensics & Incident Response (DFIR) toolkit. This repository contains detection engineering rules, SIEM hunting queries, memory triage scripts, and endpoint telemetry configurations mapped to the **MITRE ATT&CK Framework**.

---

## Architecture & Detection Pipeline

```
SOC-Incident-Response-Hunting-Lab/
├── sigma_rules/                     # Portable vendor-agnostic detection rules
│   ├── cobalt_strike_named_pipes.yml       # Malleable C2 named pipe detection
│   ├── lsass_memory_dump_sysmon.yml        # Credential theft & LSASS handle queries
│   └── powershell_obfuscated_download_cradle.yml # Base64 & WebClient download cradle
│
├── queries/                         # Production SIEM hunting rule sets
│   ├── siem_threat_hunting_queries.spl     # Splunk SPL (Jitter, PPID anomalies, DCSync)
│   └── elastic_kql_queries.kql             # Elastic / Kibana KQL rules
│
├── forensics/                       # Memory & disk triage automation
│   └── volatility_memory_analysis.py       # Volatility 3 malfind & pslist analyzer
│
├── configs/                         # Telemetry collection profiles
│   └── sysmonconfig-soc-hardened.xml       # Battle-tested Sysmon schema
│
└── README.md                        # Master documentation
```

---

## Detection Engineering Coverage (MITRE ATT&CK Mapping)

| MITRE Technique | Technique Name | Detection Method | Artifact / Rule |
| :--- | :--- | :--- | :--- |
| **T1055** | Process Injection | Sysmon Event 8 & Volatility `malfind` | `lsass_memory_dump_sysmon.yml` & `volatility_memory_analysis.py` |
| **T1003.001** | OS Credential Dumping: LSASS Memory | Sysmon Event 10 `GrantedAccess` | `lsass_memory_dump_sysmon.yml` |
| **T1071.001** | Web Protocols: C2 Beaconing | Delta-Time Variance & Jitter Analysis | `siem_threat_hunting_queries.spl` (Hunt 1) |
| **T1059.001** | Command & Scripting: PowerShell | Process Command Line Regex Matching | `powershell_obfuscated_download_cradle.yml` |
| **T1570** | Lateral Tool Transfer | Pipe Creation Events (Sysmon Event 17) | `cobalt_strike_named_pipes.yml` |

---

## Threat Hunting Methodologies & Usage

### 1. Delta-Time Variance C2 Beaconing Hunt
Adversaries use automated C2 frameworks (Cobalt Strike, Mythic, Sliver) configured with sleep times and jitter percentages. Standard security devices miss these connections because individual requests appear benign.  
Running `siem_threat_hunting_queries.spl` (Hunt 1) calculates:
$$\text{Jitter Ratio} = \frac{\sigma(\Delta t)}{\mu(\Delta t)} \times 100$$
External destinations with low standard deviation ($\sigma < 5$) and consistent intervals are isolated for immediate firewall blocking.

### 2. Memory Forensic Triage (Volatility 3)
```bash
python3 forensics/volatility_memory_analysis.py
```
Parses memory dumps, flags non-disk-backed executable memory pages containing the `MZ` DOS executable signature, and identifies parent-child process spoofing.
