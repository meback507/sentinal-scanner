import os
import json
import yaml
from typing import List, Dict, Any, Optional
from ..models import CustomRuleModel
from ..db import db


class RuleManager:
    def list_rules(self) -> List[Dict[str, Any]]:
        return db.get_all_rules()

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        return db.get_rule_by_id(rule_id)

    def save_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        return db.save_rule(rule_data)

    def delete_rule(self, rule_id: str) -> bool:
        return db.delete_rule(rule_id)

    def get_active_sast_rules(self) -> List[Dict[str, Any]]:
        all_rules = self.list_rules()
        active = []
        for r in all_rules:
            if r.get("is_active", True) and r.get("rule_category") == "sast":
                active.append(r)
        return active

    def get_active_sca_rules(self) -> List[Dict[str, Any]]:
        all_rules = self.list_rules()
        active = []
        for r in all_rules:
            if r.get("is_active", True) and r.get("rule_category") == "sca":
                active.append(r)
        return active

    def load_project_rules(self, workspace_dir: str = None) -> List[Dict[str, Any]]:
        """
        Discovers and loads project-level custom rules from .sentinel/rules.yaml
        or .aegissec/rules.yaml in the project directory.
        """
        target_dir = workspace_dir or os.getcwd()
        candidates = [
            os.path.join(target_dir, ".sentinel", "rules.yaml"),
            os.path.join(target_dir, ".sentinel", "rules.yml"),
            os.path.join(target_dir, ".sentinel", "rules.json"),
            os.path.join(target_dir, ".aegissec", "rules.yaml"),
            os.path.join(target_dir, ".aegissec", "rules.json"),
            os.path.join(target_dir, "sentinel.rules.yaml")
        ]

        rules = []
        for c in candidates:
            if os.path.exists(c):
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        if c.endswith(".json"):
                            data = json.load(f)
                        else:
                            data = yaml.safe_load(f)
                    
                    raw_rules = data.get("rules", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    for r in raw_rules:
                        if isinstance(r, dict) and "id" in r and "name" in r:
                            r["source"] = f"project:{os.path.relpath(c, target_dir)}"
                            r["is_project_custom"] = True
                            rules.append(r)
                    break  # Loaded primary config file
                except Exception as e:
                    print(f"Error loading project rules from {c}: {e}")

        return rules

    def get_complete_rule_catalog(self, workspace_dir: str = None) -> Dict[str, Any]:
        """
        Returns a unified catalog of all security rules:
        - Built-in SAST rules
        - Built-in IaC & Container rules
        - Built-in API Security rules
        - Platform Custom Rules (from DB)
        - Project Custom Rules (from .sentinel/rules.yaml)
        """
        from ..scanners.sast_engine import BUILTIN_SAST_RULES
        from ..scanners.iac_engine import IAC_RULES

        project_custom = self.load_project_rules(workspace_dir)
        platform_custom = self.list_rules()

        api_rules = [
            {
                "id": "API-BOLA-001",
                "name": "Broken Object Level Authorization (BOLA)",
                "type": "api",
                "severity": "HIGH",
                "cwe": "CWE-285",
                "standards": ["OWASP:API1:2023", "ISO-27001:A.8.28"],
                "description": "Object identifier endpoint without explicit authentication or authorization scopes.",
                "remediation": "Declare authorization security schemes on all resource identifier routes."
            },
            {
                "id": "API-AUTH-001",
                "name": "Unauthenticated Administrative / Internal Endpoint",
                "type": "api",
                "severity": "CRITICAL",
                "cwe": "CWE-306",
                "standards": ["OWASP:API2:2023", "ISO-27001:A.8.25"],
                "description": "Sensitive administrative routes exposed with security disabled.",
                "remediation": "Enforce mandatory bearer token or OAuth2 scopes on administrative endpoints."
            },
            {
                "id": "API-TRANS-001",
                "name": "Insecure Cleartext HTTP API Transport",
                "type": "api",
                "severity": "HIGH",
                "cwe": "CWE-319",
                "standards": ["OWASP:API7:2023", "PCI-DSS:Req-4.1"],
                "description": "API definition specifies unencrypted http:// server URL.",
                "remediation": "Enforce TLS 1.3 encryption (https://)."
            },
            {
                "id": "API-MASS-001",
                "name": "Mass Assignment Vulnerability in Request Body",
                "type": "api",
                "severity": "HIGH",
                "cwe": "CWE-915",
                "standards": ["OWASP:API3:2023", "ISO-27001:A.8.28"],
                "description": "Privileged attributes exposed directly in user input schemas.",
                "remediation": "Use explicit Data Transfer Objects (DTOs) preventing auto-binding of role fields."
            },
            {
                "id": "API-DOS-001",
                "name": "Unbounded Collection Pagination Denial of Service",
                "type": "api",
                "severity": "MEDIUM",
                "cwe": "CWE-400",
                "standards": ["OWASP:API4:2023"],
                "description": "Collection GET endpoint lacks pagination query parameters.",
                "remediation": "Add limit, offset, or cursor pagination parameters to all collection routes."
            }
        ]

        total_rules = len(BUILTIN_SAST_RULES) + len(IAC_RULES) + len(api_rules) + len(platform_custom) + len(project_custom)

        return {
            "summary": {
                "total_active_rules": total_rules,
                "sast_builtin": len(BUILTIN_SAST_RULES),
                "iac_builtin": len(IAC_RULES),
                "api_builtin": len(api_rules),
                "platform_custom": len(platform_custom),
                "project_custom": len(project_custom)
            },
            "rules": {
                "sast_builtin": BUILTIN_SAST_RULES,
                "iac_builtin": IAC_RULES,
                "api_builtin": api_rules,
                "platform_custom": platform_custom,
                "project_custom": project_custom
            }
        }


rule_manager = RuleManager()
