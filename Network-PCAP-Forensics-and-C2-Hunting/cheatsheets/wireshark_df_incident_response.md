# Wireshark Display Filter Cheat Sheet for Incident Response & PCAP Forensics

Essential Wireshark display filters for rapid triage during network security investigations, malware analysis, and packet capture forensics.

---

## 1. Initial Reconnaissance & Threat Triage

| Investigative Goal | Wireshark Display Filter |
| :--- | :--- |
| **Cleartext Credentials** | `http.request.method == "POST" && (http contains "password" \|\| http contains "passwd" \|\| http contains "user")` |
| **HTTP Executable / DLL Downloads** | `http.response.code == 200 && (http.file_data contains "MZ" \|\| http.content_type contains "application/x-dosexec")` |
| **DNS TXT Queries (Common for C2 / Staging)** | `dns.qry.type == 16` |
| **DNS Queries with Long Subdomain Labels (> 30 chars)** | `dns.qry.name.len > 30` |
| **External Non-Standard Port Connections** | `!(tcp.port in {80 443 8080 8443}) && ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16` |

---

## 2. Lateral Movement & Active Directory Protocols

| Attack / Technique | Display Filter |
| :--- | :--- |
| **Kerberos Error Codes (e.g. Bad Password, Account Locked)** | `kerberos.error_code != 0` |
| **Kerberos RC4 TGS Requests (Kerberoasting)** | `kerberos.etype == 23 && kerberos.msg_type == 12` |
| **SMB2 File Transfers (PsExec, Lateral Movement)** | `smb2.cmd == 5 && (smb2.filename matches ".*\\.exe" \|\| smb2.filename matches ".*ADMIN\\$")` |
| **RDP Traffic Analysis** | `tcp.port == 3389` |
| **WMI Remote Execution** | `dcerpc.ver_major == 5 && dcerpc.opnum == 3` |

---

## 3. Command and Control (C2) & Beaconing

| Indicator | Display Filter |
| :--- | :--- |
| **TCP SYN Retransmissions (Dead C2 host)** | `tcp.analysis.retransmission` |
| **SSL/TLS Certificates with Self-Signed or Untrusted CN** | `tls.handshake.type == 11` |
| **TLS SNI Inspection** | `tls.handshake.extensions_server_name` |
| **HTTP User-Agents containing Suspicious Tools (curl, python, powershell)** | `http.user_agent matches "(?i)(curl\|python\|powershell\|winhttp\|go-http)"` |
