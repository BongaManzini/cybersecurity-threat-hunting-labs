#!/usr/bin/env python3
"""
AWS IAM Privilege Escalation Vector Auditor
Author: Bonga Manzini <contact@bongamanzini.dev>
Domain: Cloud Security Architecture & DevSecOps

Evaluates AWS IAM policy permissions against known privilege escalation paths
(e.g., Rhodes 21 IAM PrivEsc methods), identifying overly permissive roles
that allow unprivileged principals to escalate to AdministratorAccess.
"""

import sys
import json
from typing import List, Dict, Any

# Known AWS IAM Privilege Escalation Permissions Combinations
PRIVESC_VECTORS = [
    {
        "id": "PRIVESC-01",
        "name": "CreateNewPolicyVersion",
        "required_actions": ["iam:createpolicyversion"],
        "description": "Principal can create a new version of an existing policy containing AdministratorAccess and set it as default.",
        "severity": "CRITICAL"
    },
    {
        "id": "PRIVESC-02",
        "name": "SetExistingDefaultPolicyVersion",
        "required_actions": ["iam:setdefaultpolicyversion"],
        "description": "Principal can switch the active default policy to an older version that grants elevated permissions.",
        "severity": "HIGH"
    },
    {
        "id": "PRIVESC-03",
        "name": "PassRoleToEC2WithAdminProfile",
        "required_actions": ["iam:passrole", "ec2:runinstances"],
        "description": "Principal can launch an EC2 instance attached to an Admin IAM instance profile and extract credentials via metadata.",
        "severity": "CRITICAL"
    },
    {
        "id": "PRIVESC-04",
        "name": "CreateAccessKeyForOtherUser",
        "required_actions": ["iam:createaccesskey"],
        "description": "Principal can create an access key for a privileged user (e.g., admin) and impersonate them.",
        "severity": "CRITICAL"
    },
    {
        "id": "PRIVESC-05",
        "name": "AttachUserOrRolePolicy",
        "required_actions": ["iam:attachuserpolicy", "iam:attachrolepolicy"],
        "match_mode": "any",
        "description": "Principal can directly attach the AdministratorAccess managed policy to their own user or role.",
        "severity": "CRITICAL"
    }
]

class IAMPrivilegeEscalationAuditor:
    def __init__(self):
        pass

    def evaluate_policy_statements(self, statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        allowed_actions = set()

        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                for act in actions:
                    allowed_actions.add(act.lower())

        # Check for full wildcard
        if "*" in allowed_actions or "iam:*" in allowed_actions:
            return [{
                "id": "PRIVESC-WILDCARD",
                "name": "Full IAM or Global Wildcard Access",
                "severity": "CRITICAL",
                "description": "Policy grants unrestricted '*' or 'iam:*' permissions.",
                "remediation": "Apply Principle of Least Privilege and restrict actions to specific resource ARNs."
            }]

        detected_vectors = []
        for vec in PRIVESC_VECTORS:
            reqs = [r.lower() for r in vec["required_actions"]]
            match_mode = vec.get("match_mode", "all")

            if match_mode == "all":
                has_vector = all(r in allowed_actions for r in reqs)
            else:
                has_vector = any(r in allowed_actions for r in reqs)

            if has_vector:
                detected_vectors.append({
                    "id": vec["id"],
                    "name": vec["name"],
                    "severity": vec["severity"],
                    "description": vec["description"],
                    "remediation": f"Revoke permissions: {', '.join(vec['required_actions'])} and attach IAM Permission Boundaries."
                })

        return detected_vectors

def run_sample_iam_audit():
    sample_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreatePolicyVersion",
                    "iam:GetPolicy",
                    "iam:ListPolicyVersions",
                    "s3:GetObject"
                ],
                "Resource": "*"
            }
        ]
    }

    auditor = IAMPrivilegeEscalationAuditor()
    findings = auditor.evaluate_policy_statements(sample_policy["Statement"])

    print(json.dumps({
        "policy_name": "DeveloperStagingAccessPolicy",
        "findings": findings
    }, indent=2))

if __name__ == "__main__":
    run_sample_iam_audit()
