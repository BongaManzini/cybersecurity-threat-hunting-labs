#!/usr/bin/env python3
"""
PCAP & Network Flow C2 Beacon Analyzer
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: Network Security Forensics & C2 Hunting

Analyzes network packet flows, calculating delta-time standard deviation,
jitter percentage, and payload size uniformity to uncover automated C2 agents
(Cobalt Strike, Sliver, Brute Ratel, Mythic) communicating over HTTP/HTTPS/TCP.
"""

import math
import json
import statistics
from typing import List, Dict, Any
from collections import defaultdict

class NetworkBeaconAnalyzer:
    def __init__(self, min_flow_packets: int = 15, max_acceptable_jitter: float = 25.0):
        self.min_packets = min_flow_packets
        self.max_jitter = max_acceptable_jitter

    def analyze_flow_timings(self, timestamps: List[float], payload_sizes: List[int]) -> Dict[str, Any]:
        """
        Calculates timing delta metrics for a conversation flow.
        """
        if len(timestamps) < self.min_packets:
            return {"verdict": "INSUFFICIENT_PACKETS", "sample_size": len(timestamps)}

        # Compute delta times between consecutive packets
        deltas = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

        mean_delta = statistics.mean(deltas)
        stdev_delta = statistics.stdev(deltas) if len(deltas) > 1 else 0.0

        # Jitter percentage relative to mean interval
        jitter_pct = (stdev_delta / mean_delta * 100.0) if mean_delta > 0 else 0.0

        # Payload size uniformity
        mean_size = statistics.mean(payload_sizes)
        stdev_size = statistics.stdev(payload_sizes) if len(payload_sizes) > 1 else 0.0

        is_c2_candidate = (jitter_pct < self.max_jitter) and (mean_delta > 2.0)

        return {
            "verdict": "SUSPICIOUS_C2_BEACON" if is_c2_candidate else "BENIGN_BURSTY_TRAFFIC",
            "packet_count": len(timestamps),
            "mean_interval_sec": round(mean_delta, 3),
            "stdev_interval_sec": round(stdev_delta, 3),
            "jitter_percentage": round(jitter_pct, 2),
            "mean_payload_bytes": round(mean_size, 1),
            "stdev_payload_bytes": round(stdev_size, 1),
            "confidence_score": round(max(0, 100.0 - jitter_pct), 1) if is_c2_candidate else 15.0
        }

def run_sample_flow_analysis():
    # Synthetic beacon timestamps: sleep 10s with +/- 10% jitter (Cobalt Strike default)
    synthetic_c2_timestamps = [
        0.0, 9.8, 20.1, 29.7, 40.2, 50.5, 60.1, 70.4, 79.9, 90.2,
        100.5, 110.1, 120.3, 130.0, 140.2, 149.8, 160.4
    ]
    synthetic_payloads = [240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240, 240]

    analyzer = NetworkBeaconAnalyzer()
    report = analyzer.analyze_flow_timings(synthetic_c2_timestamps, synthetic_payloads)

    print(json.dumps({
        "flow": "10.0.1.45:49182 -> 198.51.100.77:443 (HTTPS)",
        "analysis": report
    }, indent=2))

if __name__ == "__main__":
    run_sample_flow_analysis()
