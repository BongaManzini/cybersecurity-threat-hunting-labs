#!/usr/bin/env python3
"""
JWT Security & Vulnerability Auditor
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: API Security & OWASP Top 10 API Security

Audits JSON Web Tokens (JWT) for signature algorithm flaws:
1. 'none' algorithm flaw (CVE-2015-9235)
2. Algorithm Confusion: RS256 (Asymmetric) to HS256 (Symmetric) using server public key
3. Missing expiration claim (exp) and token freshness
4. Sensitive plaintext PII leakage in payload claims
"""

import sys
import json
import base64
import time
from typing import Dict, Any, List

def base64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem > 0:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

class JWTSecurityAuditor:
    def __init__(self):
        pass

    def audit_token(self, token: str) -> Dict[str, Any]:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return {"error": "Invalid JWT format. Expected 3 dot-delimited parts."}

        header_b64, payload_b64, sig_b64 = parts
        vulnerabilities = []

        try:
            header = json.loads(base64url_decode(header_b64).decode("utf-8"))
        except Exception:
            header = {}

        try:
            payload = json.loads(base64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            payload = {}

        # 1. 'none' Algorithm Vulnerability Check
        alg = header.get("alg", "").lower()
        if alg == "none" or sig_b64 == "":
            vulnerabilities.append({
                "issue": "NONE_ALGORITHM_ACCEPTED",
                "severity": "CRITICAL",
                "cve": "CVE-2015-9235",
                "description": "Token specifies 'none' algorithm. Server may accept unauthenticated tokens with arbitrary payload privileges."
            })

        # 2. Key Confusion Susceptibility (RS256 vs HS256)
        if alg.startswith("rs"):
            vulnerabilities.append({
                "issue": "POTENTIAL_ASYMMETRIC_KEY_CONFUSION",
                "severity": "MEDIUM",
                "description": "Token uses RS256. Ensure server backend strictly enforces RS256 and does not accept HS256 signed with the public key."
            })

        # 3. Expiration Claim Verification
        exp = payload.get("exp")
        now = int(time.time())
        if exp is None:
            vulnerabilities.append({
                "issue": "MISSING_EXPIRATION_CLAIM",
                "severity": "HIGH",
                "description": "Token does not specify an 'exp' claim, allowing infinite lifetime replay attacks."
            })
        elif exp < now:
            vulnerabilities.append({
                "issue": "EXPIRED_TOKEN",
                "severity": "INFO",
                "description": f"Token expired {now - exp} seconds ago."
            })

        # 4. Sensitive Data Leakage Check
        sensitive_keys = ["password", "secret", "private_key", "ssn", "sa_id", "credit_card"]
        leaked = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]
        if leaked:
            vulnerabilities.append({
                "issue": "PII_OR_SECRET_EXPOSURE_IN_PAYLOAD",
                "severity": "HIGH",
                "description": f"Unencrypted sensitive fields found in JWT payload: {leaked}"
            })

        return {
            "header": header,
            "payload": payload,
            "signature_present": len(sig_b64) > 0,
            "findings_count": len(vulnerabilities),
            "findings": vulnerabilities
        }

def run_sample_jwt_audit():
    # Sample vulnerable JWT: {"alg": "none", "typ": "JWT"}.{"sub": "admin", "role": "SuperAdmin", "password": "cleartextPassword"}
    sample_vulnerable_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJTdXBlckFkbWluIiwicGFzc3dvcmQiOiJjbGVhcnRleHRQYXNzd29yZCJ9."

    auditor = JWTSecurityAuditor()
    report = auditor.audit_token(sample_vulnerable_jwt)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    run_sample_jwt_audit()
