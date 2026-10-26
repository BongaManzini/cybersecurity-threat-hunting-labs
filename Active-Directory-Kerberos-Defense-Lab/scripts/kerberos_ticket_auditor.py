#!/usr/bin/env python3
"""
Active Directory Kerberos & SPN Security Auditor
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: Enterprise Cybersecurity & Active Directory Defense

Audits Active Directory Service Principal Names (SPNs), ticket encryption algorithms,
unconstrained delegation flags, and identifies accounts susceptible to Kerberoasting
and AS-REP Roasting attacks.
"""

import sys
import json
import logging
from typing import List, Dict, Any
from dataclasses import dataclass, asdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("KerberosAuditor")

# Known Kerberos Encryption Types
ENCRYPTION_TYPES = {
    0x01: ("DES-CBC-CRC", "CRITICAL - Deprecated & Cracked"),
    0x03: ("DES-CBC-MD5", "CRITICAL - Deprecated & Cracked"),
    0x17: ("RC4-HMAC", "HIGH - Susceptible to Offline Kerberoasting"),
    0x18: ("AES256-CTS-HMAC-SHA1-96", "SECURE - Modern Standard"),
    0x12: ("AES128-CTS-HMAC-SHA1-96", "ACCEPTABLE - Modern Standard")
}

@dataclass
class ServiceAccountAudit:
    sam_account_name: str
    service_principal_names: List[str]
    pwd_last_set_days_ago: int
    admin_count: int
    encryption_types_supported: List[str]
    does_not_require_preauth: bool
    trusted_for_delegation: bool  # Unconstrained delegation
    trusted_to_auth_for_delegation: bool  # Constrained delegation
    risk_level: str
    vulnerabilities: List[str]
    remediation: str

class KerberosSecurityAnalyzer:
    def __init__(self, high_value_threshold_days: int = 180):
        self.threshold_days = high_value_threshold_days

    def evaluate_account(self, account: Dict[str, Any]) -> ServiceAccountAudit:
        vulnerabilities = []
        risk_score = 0
        sam = account.get("sAMAccountName", "UNKNOWN")
        spns = account.get("servicePrincipalNames", [])
        pwd_age = account.get("passwordAgeDays", 0)
        admin_count = account.get("adminCount", 0)
        preauth_disabled = account.get("dontRequirePreauth", False)
        unconstrained_delegation = account.get("trustedForDelegation", False)
        supported_enc_types = account.get("supportedEncryptionTypes", [])

        # 1. AS-REP Roasting Check
        if preauth_disabled:
            vulnerabilities.append("AS-REP Roasting: DONT_REQ_PREAUTH flag enabled. Attackers can request encrypted TGT offline.")
            risk_score += 40

        # 2. Kerberoasting Vulnerability Check
        if spns:
            # Check cipher suite
            has_rc4 = any("RC4" in enc or enc == "0x17" for enc in supported_enc_types)
            has_aes = any("AES" in enc or enc == "0x18" for enc in supported_enc_types)

            if has_rc4 or not has_aes:
                vulnerabilities.append("Kerberoasting: Service account lacks AES enforcement; TGS tickets can be requested with RC4-HMAC.")
                risk_score += 30

            if admin_count > 0:
                vulnerabilities.append("High-Privilege Kerberoasting: Account has adminCount=1 (Domain Admin or Enterprise Admin).")
                risk_score += 35

            if pwd_age > self.threshold_days:
                vulnerabilities.append(f"Stale Password: Password has not been rotated in {pwd_age} days (exceeds {self.threshold_days}d).")
                risk_score += 15

        # 3. Delegation Vulnerability Check
        if unconstrained_delegation:
            vulnerabilities.append("Unconstrained Delegation: Account stores cached TGTs in LSASS for connecting users, enabling silver/golden ticket pivots.")
            risk_score += 40

        # Assign risk level
        if risk_score >= 60:
            risk_level = "CRITICAL"
            remediation = "Migrate to Group Managed Service Account (gMSA), enforce AES-256 Kerberos encryption in msDS-SupportedEncryptionTypes, and revoke unconstrained delegation."
        elif risk_score >= 30:
            risk_level = "HIGH"
            remediation = "Rotate password to 30+ characters, configure msDS-SupportedEncryptionTypes=0x18 (AES256), and enable Kerberos Pre-Authentication."
        elif risk_score > 0:
            risk_level = "MEDIUM"
            remediation = "Enforce scheduled password rotation and review SPN assignment."
        else:
            risk_level = "LOW"
            remediation = "Account conforms to baseline Tier-1 security controls."

        return ServiceAccountAudit(
            sam_account_name=sam,
            service_principal_names=spns,
            pwd_last_set_days_ago=pwd_age,
            admin_count=admin_count,
            encryption_types_supported=supported_enc_types,
            does_not_require_preauth=preauth_disabled,
            trusted_for_delegation=unconstrained_delegation,
            trusted_to_auth_for_delegation=account.get("trustedToAuthForDelegation", False),
            risk_level=risk_level,
            vulnerabilities=vulnerabilities,
            remediation=remediation
        )

    def generate_report(self, accounts: List[Dict[str, Any]]) -> Dict[str, Any]:
        results = [self.evaluate_account(acc) for acc in accounts]
        critical_count = sum(1 for r in results if r.risk_level == "CRITICAL")
        high_count = sum(1 for r in results if r.risk_level == "HIGH")

        return {
            "audit_metadata": {
                "engine": "KerberosSecurityAnalyzer-v2.1",
                "total_accounts_analyzed": len(accounts),
                "critical_findings": critical_count,
                "high_findings": high_count,
            },
            "findings": [asdict(r) for r in results]
        }

def run_self_test():
    """Simulates an audit on synthetic enterprise Active Directory accounts."""
    test_directory = [
        {
            "sAMAccountName": "svc_mssql_prod",
            "servicePrincipalNames": ["MSSQLSvc/sql01.corp.internal:1433", "MSSQLSvc/sql01.corp.internal"],
            "passwordAgeDays": 420,
            "adminCount": 1,
            "supportedEncryptionTypes": ["RC4-HMAC"],
            "dontRequirePreauth": False,
            "trustedForDelegation": False
        },
        {
            "sAMAccountName": "svc_iis_legacy",
            "servicePrincipalNames": ["HTTP/portal.corp.internal"],
            "passwordAgeDays": 110,
            "adminCount": 0,
            "supportedEncryptionTypes": ["RC4-HMAC", "AES256-CTS-HMAC-SHA1-96"],
            "dontRequirePreauth": True,  # AS-REP Roastable
            "trustedForDelegation": True   # Unconstrained delegation
        },
        {
            "sAMAccountName": "gmsa_app_secure$",
            "servicePrincipalNames": ["HTTP/api.corp.internal"],
            "passwordAgeDays": 15,
            "adminCount": 0,
            "supportedEncryptionTypes": ["AES256-CTS-HMAC-SHA1-96"],
            "dontRequirePreauth": False,
            "trustedForDelegation": False
        }
    ]

    analyzer = KerberosSecurityAnalyzer()
    report = analyzer.generate_report(test_directory)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    run_self_test()
