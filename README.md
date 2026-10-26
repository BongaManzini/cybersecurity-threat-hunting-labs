# Hands-On Security Engineering & Simulation Laboratories

A comprehensive, industry-standard suite of cybersecurity defense, threat hunting, and digital forensics laboratories. Built to demonstrate deep hands-on proficiency across **Active Directory Security**, **Enterprise SOC Detection Engineering**, **Network Packet Forensics**, and **Cloud/API Security**.

---

## Lab Modules Overview

```
Hands-On-Labs-and-Simulations/
├── Active-Directory-Kerberos-Defense-Lab/
│   ├── scripts/kerberos_ticket_auditor.py       # Audits SPNs, RC4 ciphers, and delegation risks
│   ├── scripts/spn_roast_detector.py            # Real-time Event ID 4769 RC4 anomaly detection
│   ├── telemetry/bloodhound_attack_path_analysis.json # SharpHound attack graph export
│   ├── configs/gpo_kerberos_hardening.md        # GPO AES-256 enforcement baseline
│   └── README.md
│
├── SOC-Incident-Response-Hunting-Lab/
│   ├── sigma_rules/                             # Portable Sigma rules (Cobalt Strike, LSASS, PowerShell)
│   ├── queries/siem_threat_hunting_queries.spl  # Splunk SPL hunting queries (Jitter, PPID, DCSync)
│   ├── queries/elastic_kql_queries.kql          # Elastic Security KQL rules
│   ├── forensics/volatility_memory_analysis.py  # Volatility 3 memory dump triage script
│   ├── configs/sysmonconfig-soc-hardened.xml    # SwiftOnSecurity-aligned Sysmon schema
│   └── README.md
│
├── Network-PCAP-Forensics-and-C2-Hunting/
│   ├── tools/pcap_c2_beacon_analyzer.py         # Delta-time variance & jitter C2 beacon detector
│   ├── tools/dns_tunnel_detector.py             # Shannon entropy DNS exfiltration detector
│   ├── cheatsheets/wireshark_df_incident_response.md # Incident responder Wireshark filter sheet
│   └── README.md
│
├── Cloud-Security-and-OWASP-Audit-Lab/
│   ├── audit_scripts/iam_privesc_auditor.py     # AWS IAM privilege escalation scanner (21 vectors)
│   ├── audit_scripts/jwt_security_auditor.py    # JWT algorithm confusion & token auditor
│   ├── guides/aws_imdsv2_ssrf_defense.md        # AWS IMDSv2 metadata SSRF defense blueprint
│   └── README.md
│
└── README.md                                    # This portfolio overview
```

---

## Target Security Competencies Demonstrated

| Discipline | Core Competencies Demonstrated |
| :--- | :--- |
| **Enterprise Identity & AD** | Kerberos protocol mechanics, SPN auditing, gMSA implementation, BloodHound graph analysis, tiered administrative access. |
| **SOC Detection Engineering** | Sigma rule authoring, Splunk SPL queries, Kibana KQL, Sysmon telemetry design, MITRE ATT&CK technique mapping. |
| **DFIR & Memory Analysis** | Volatility 3 PE extraction, injected RWX memory detection, parent-child process relationship validation. |
| **Network Security & DPI** | Shannon entropy calculations for DNS tunneling, statistical jitter analysis for C2 beacon detection, Wireshark filter mastery. |
| **Cloud & API Security** | AWS IAM privilege escalation identification, JWT vulnerability exploitation and hardening, IMDSv2 defense architecture. |
