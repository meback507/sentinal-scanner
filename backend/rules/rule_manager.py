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

    def save_rule(self, rule_data: Dict[str, Any], sync_to_yaml: bool = False, workspace_dir: str = None) -> Dict[str, Any]:
        if rule_data.get("yaml_representation"):
            try:
                parsed_yaml = yaml.safe_load(rule_data["yaml_representation"])
                if isinstance(parsed_yaml, dict):
                    for k, v in parsed_yaml.items():
                        if k != "yaml_representation" and v is not None:
                            rule_data[k] = v
            except Exception:
                pass
        saved = db.save_rule(rule_data)
        if sync_to_yaml:
            self.sync_rule_to_project_file(saved, workspace_dir)
        return saved

    def delete_rule(self, rule_id: str, workspace_dir: str = None) -> bool:
        """
        Deletes rule from both database storage and project-level YAML files (.sentinel/rules.yaml).
        Ensures deleted rules do not linger in editor or scan caches.
        """
        db_deleted = db.delete_rule(rule_id)
        yaml_deleted = self._delete_from_project_rules(rule_id, workspace_dir)
        return db_deleted or yaml_deleted

    def _delete_from_project_rules(self, rule_id: str, workspace_dir: str = None) -> bool:
        target_dir = workspace_dir or os.getcwd()
        candidates = [
            os.path.join(target_dir, ".sentinel", "rules.yaml"),
            os.path.join(target_dir, ".sentinel", "rules.yml"),
            os.path.join(target_dir, ".aegissec", "rules.yaml"),
            os.path.join(target_dir, "sentinel.rules.yaml")
        ]
        deleted_any = False
        for c in candidates:
            if os.path.exists(c):
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
                        clean_target_id = rule_id.strip().lower()
                        orig_len = len(data["rules"])
                        data["rules"] = [
                            r for r in data["rules"]
                            if r.get("id", "").strip().lower() != clean_target_id
                            and r.get("id", "").strip().lower() != f"proj-{clean_target_id}"
                        ]
                        if len(data["rules"]) < orig_len:
                            with open(c, "w", encoding="utf-8") as f:
                                yaml.dump(data, f, sort_keys=False)
                            deleted_any = True
                except Exception as e:
                    print(f"Error removing rule {rule_id} from {c}: {e}")
        return deleted_any

    def get_rules_yaml_content(self, workspace_dir: str = None) -> Dict[str, Any]:
        """
        Retrieves the raw content of .sentinel/rules.yaml. If not present, synthesizes a valid configuration.
        """
        target_dir = workspace_dir or os.getcwd()
        candidates = [
            os.path.join(target_dir, ".sentinel", "rules.yaml"),
            os.path.join(target_dir, ".sentinel", "rules.yml"),
            os.path.join(target_dir, ".aegissec", "rules.yaml"),
            os.path.join(target_dir, "sentinel.rules.yaml")
        ]
        for c in candidates:
            if os.path.exists(c):
                try:
                    with open(c, "r", encoding="utf-8") as f:
                        content = f.read()
                    return {
                        "found": True,
                        "file_path": os.path.relpath(c, target_dir),
                        "filename": os.path.basename(c),
                        "content": content
                    }
                except Exception:
                    pass

        # Synthesize from active catalog
        catalog = self.get_complete_rule_catalog(workspace_dir)
        all_custom = catalog["rules"]["platform_custom"] + catalog["rules"]["project_custom"]
        synth_yaml = yaml.dump({
            "version": "1.0",
            "project": "sentinel-scanner",
            "rules": all_custom
        }, sort_keys=False)
        return {
            "found": False,
            "file_path": ".sentinel/rules.yaml",
            "filename": "rules.yaml",
            "content": synth_yaml
        }

    def save_rules_yaml_content(self, content: str, workspace_dir: str = None) -> Dict[str, Any]:
        """
        Saves updated content directly into .sentinel/rules.yaml.
        """
        target_dir = workspace_dir or os.getcwd()
        sentinel_dir = os.path.join(target_dir, ".sentinel")
        os.makedirs(sentinel_dir, exist_ok=True)
        rules_path = os.path.join(sentinel_dir, "rules.yaml")
        with open(rules_path, "w", encoding="utf-8") as f:
            f.write(content)
        return {
            "success": True,
            "file_path": os.path.relpath(rules_path, target_dir),
            "filename": "rules.yaml"
        }

    def sync_rule_to_project_file(self, rule: Dict[str, Any], workspace_dir: str = None) -> bool:
        """
        Appends or updates a custom rule inside .sentinel/rules.yaml.
        """
        target_dir = workspace_dir or os.getcwd()
        sentinel_dir = os.path.join(target_dir, ".sentinel")
        os.makedirs(sentinel_dir, exist_ok=True)
        rules_path = os.path.join(sentinel_dir, "rules.yaml")

        data = {"version": "1.0", "project": "sentinel-scanner", "rules": []}
        if os.path.exists(rules_path):
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        data = loaded
                        if "rules" not in data or not isinstance(data["rules"], list):
                            data["rules"] = []
            except Exception:
                pass

        rule_entry = {
            "id": rule.get("id"),
            "name": rule.get("name"),
            "type": rule.get("type", "sast"),
            "severity": rule.get("severity", "HIGH"),
            "languages": rule.get("languages", ["python"]),
            "cwe": rule.get("cwe", "CWE-699"),
            "cvss": float(rule.get("cvss") or 7.5),
            "standards": rule.get("standards", ["ISO-27001:A.8.28"]),
            "regex": rule.get("regex", ""),
            "description": rule.get("description", ""),
            "remediation": rule.get("remediation", "")
        }

        # Remove existing if updating
        data["rules"] = [r for r in data["rules"] if r.get("id") != rule_entry["id"]]
        data["rules"].append(rule_entry)

        with open(rules_path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, sort_keys=False)
        return True

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

        secret_rules = []
        try:
            from ..scanners.secret_scanner import SecretScanner
            for p in SecretScanner.SECRET_PATTERNS:
                secret_rules.append({
                    "id": p["id"],
                    "name": p["type"],
                    "type": "secret",
                    "severity": p["severity"],
                    "cwe": p.get("cwe", "CWE-798"),
                    "standards": p.get("standards", ["ISO-27001 (A.8.12)"]),
                    "regex": p.get("regex", ""),
                    "description": f"Detection pattern for {p['type']}.",
                    "remediation": "Store secrets in environment variables or key vault."
                })
        except Exception:
            pass

        sonar_rules = []
        open_db_rules = []
        try:
            from .open_rule_database import open_rule_db
            sonar_rules = open_rule_db.get_sonarqube_rules(active_only=True)
            open_db_rules = open_rule_db.get_community_rules(active_only=True)
        except Exception:
            pass

        all_rule_ids = set()
        for r in (BUILTIN_SAST_RULES + IAC_RULES + api_rules + secret_rules +
                  platform_custom + project_custom + sonar_rules + open_db_rules):
            if r.get("id"):
                all_rule_ids.add(r.get("id"))
        total_rules = len(all_rule_ids)

        return {
            "summary": {
                "total_active_rules": total_rules,
                "sast_builtin": len(BUILTIN_SAST_RULES),
                "iac_builtin": len(IAC_RULES),
                "api_builtin": len(api_rules),
                "secret_builtin": len(secret_rules),
                "platform_custom": len(platform_custom),
                "project_custom": len(project_custom),
                "sonarqube_rules": len(sonar_rules),
                "open_database_rules": len(open_db_rules)
            },
            "rules": {
                "sast_builtin": BUILTIN_SAST_RULES,
                "iac_builtin": IAC_RULES,
                "api_builtin": api_rules,
                "secret_builtin": secret_rules,
                "platform_custom": platform_custom,
                "project_custom": project_custom,
                "sonarqube_rules": sonar_rules,
                "open_database_rules": open_db_rules
            }
        }


rule_manager = RuleManager()
