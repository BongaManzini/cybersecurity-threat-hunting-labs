#!/usr/bin/env python3
"""
Active Directory Kerberoasting Real-Time Detection Engine
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: Enterprise SIEM & SOC Detection Engineering

Analyzes Windows Security Log Event ID 4769 (A Kerberos service ticket was requested)
to detect automated Kerberoasting attack tools (Rubeus, Invoke-Kerberoast, Impacket)
via cipher suite profiling (0x17 / RC4-HMAC) and volumetric request clustering.
"""

import sys
import json
import time
from typing import List, Dict, Any
from collections import defaultdict

# Windows Event ID 4769 Constants
RC4_ENCRYPTION_HEX = "0x17"
AES256_ENCRYPTION_HEX = "0x18"
SUCCESS_TICKET_STATUS = "0x0"

class KerberoastDetector:
    def __init__(self, time_window_seconds: int = 60, threshold_rc4_requests: int = 3):
        self.time_window = time_window_seconds
        self.threshold = threshold_rc4_requests
        self.user_requests = defaultdict(list)

    def process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single Event ID 4769 log item.
        Returns an alert payload if suspicious activity is detected.
        """
        event_id = event.get("EventID")
        if event_id != 4769:
            return None

        event_data = event.get("EventData", {})
        status = event_data.get("Status")
        ticket_enc_type = event_data.get("TicketEncryptionType")
        target_spn = event_data.get("ServiceName", "")
        account_name = event_data.get("TargetUserName", "")
        ip_address = event_data.get("IpAddress", "127.0.0.1")
        timestamp = event.get("Timestamp", time.time())

        # Ignore machine accounts and krbtgt requests
        if target_spn.endswith("$") or target_spn.startswith("krbtgt"):
            return None

        # Filter for successful ticket requests using weak RC4-HMAC
        if status == SUCCESS_TICKET_STATUS and ticket_enc_type == RC4_ENCRYPTION_HEX:
            self.user_requests[account_name].append({
                "timestamp": timestamp,
                "spn": target_spn,
                "ip": ip_address
            })

            # Evict requests outside sliding window
            cutoff = timestamp - self.time_window
            self.user_requests[account_name] = [
                req for req in self.user_requests[account_name] if req["timestamp"] >= cutoff
            ]

            recent_count = len(self.user_requests[account_name])
            if recent_count >= self.threshold:
                spns_requested = list(set(r["spn"] for r in self.user_requests[account_name]))
                return {
                    "alert": "HIGH_CONFIDENCE_KERBEROASTING_DETECTED",
                    "severity": "CRITICAL",
                    "mitre_technique": "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting",
                    "actor_account": account_name,
                    "source_ip": ip_address,
                    "rc4_ticket_count": recent_count,
                    "time_window_sec": self.time_window,
                    "targeted_spns": spns_requested,
                    "recommended_action": [
                        f"Immediately isolate host {ip_address} using EDR network quarantine",
                        f"Disable or rotate Kerberos credentials for account {account_name}",
                        "Audit SPNs requested for offline brute force cracking attempts"
                    ]
                }

        return None

def run_simulation():
    detector = KerberoastDetector(time_window_seconds=30, threshold_rc4_requests=2)
    sample_events = [
        {
            "EventID": 4769,
            "Timestamp": 100.0,
            "EventData": {
                "TargetUserName": "john.doe@corp.internal",
                "ServiceName": "MSSQLSvc/db01.corp.internal:1433",
                "TicketEncryptionType": "0x17",
                "Status": "0x0",
                "IpAddress": "10.0.4.15"
            }
        },
        {
            "EventID": 4769,
            "Timestamp": 102.0,
            "EventData": {
                "TargetUserName": "john.doe@corp.internal",
                "ServiceName": "HTTP/intranet.corp.internal",
                "TicketEncryptionType": "0x17",
                "Status": "0x0",
                "IpAddress": "10.0.4.15"
            }
        }
    ]

    for ev in sample_events:
        alert = detector.process_event(ev)
        if alert:
            print("[!] SIEM ALERT FIRED:")
            print(json.dumps(alert, indent=2))

if __name__ == "__main__":
    run_simulation()
