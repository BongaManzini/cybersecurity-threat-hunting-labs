#!/usr/bin/env python3
"""
DNS Tunneling & Data Exfiltration Detector
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: Network Security & Threat Detection

Computes Shannon Entropy on DNS query labels and identifies exfiltration tunneling
tools (Iodine, dnscat2, Cobalt Strike DNS Malleable C2) and DGA domain lookups.
"""

import math
import json
from typing import List, Dict, Any

def calculate_shannon_entropy(data: str) -> float:
    """
    Computes Shannon entropy (bits per symbol) of a string.
    Random base64/hex encoded data yields entropy > 3.8.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 3)

class DNSTunnelDetector:
    def __init__(self, entropy_threshold: float = 3.75, max_subdomain_length: float = 35):
        self.entropy_threshold = entropy_threshold
        self.max_length = max_subdomain_length

    def evaluate_query(self, fqdn: str) -> Dict[str, Any]:
        fqdn = fqdn.strip().rstrip(".")
        parts = fqdn.split(".")
        if len(parts) < 2:
            return {"fqdn": fqdn, "verdict": "INVALID_QUERY"}

        # Extract deepest subdomain label (where encoded data is stashed)
        subdomain = ".".join(parts[:-2])
        longest_label = max(parts, key=len)
        entropy = calculate_shannon_entropy(longest_label)
        label_len = len(longest_label)

        is_tunneling = (entropy >= self.entropy_threshold and label_len >= 20) or (label_len > self.max_length)

        return {
            "query": fqdn,
            "longest_label": longest_label,
            "label_length": label_len,
            "shannon_entropy": entropy,
            "verdict": "CRITICAL_DNS_TUNNEL_EXFILTRATION" if is_tunneling else "BENIGN_DNS_QUERY",
            "mitre_id": "T1071.004 - Application Layer Protocol: DNS",
            "action": "Trigger SOC escalation, block domain at recursive resolver, capture full query payload" if is_tunneling else "Allow"
        }

def run_dns_audit():
    test_queries = [
        "www.google.com",
        "api.github.com",
        "a9f4c3b281e09c84d72e61a4f08c238b91a2.c2.darkadversary.net",
        "dGhpcyBpcyBhbiBleGZpbHRyYXRpb24gcGF5bG9hZCBpbiBiYXNlNjQ.tunnel.evilcorp.org",
        "cdn.jsdelivr.net"
    ]

    detector = DNSTunnelDetector()
    results = [detector.evaluate_query(q) for q in test_queries]
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_dns_audit()
