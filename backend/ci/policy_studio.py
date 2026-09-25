"""
Sentinel AppSec - Policy-as-Code & Visual Quality Gate Studio
Enforces customizable, threat-informed security gates for CI/CD pipelines and pull requests.
Supports interactive simulation dry-runs and automated policy rule compilation.
"""

import os
import json
from typing import Dict, List, Any, Optional


class PolicyStudio:
    """
    Manages Security Policy-as-Code definitions, gate evaluations, and interactive simulations.
    """

    POLICY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".sentinel", "policy_as_code.json")

    DEFAULT_POLICY = {
        "policy_name": "Enterprise Production Defense Gate",
        "version": "1.0",
        "description": "Standard enterprise CI/CD gate blocking weaponized vulnerabilities and leaked secrets.",
        "rules": [
            {
                "id": "RULE-ZERO-CRITICAL",
                "name": "Zero Critical Vulnerabilities",
                "field": "critical_count",
                "operator": "<=",
                "threshold": 0,
                "severity_on_breach": "BLOCK",
                "description": "Fails the build if any CRITICAL severity flaw exists in the repository."
            },
            {
                "id": "RULE-MAX-HIGH",
                "name": "Maximum High Severity Tolerance",
                "field": "high_count",
                "operator": "<=",
                "threshold": 2,
                "severity_on_breach": "BLOCK",
                "description": "Permits at most 2 HIGH severity flaws during active sprint refactoring."
            },
            {
                "id": "RULE-BLOCK-CISA-KEV",
                "name": "Block CISA KEV (Known Exploited Vulnerabilities)",
                "field": "cisa_kev_count",
                "operator": "==",
                "threshold": 0,
                "severity_on_breach": "BLOCK",
                "description": "Strictly rejects any vulnerability actively weaponized in the wild per CISA KEV catalog."
            },
            {
                "id": "RULE-ZERO-SECRETS",
                "name": "Enforce Zero High-Entropy Secrets",
                "field": "secrets_count",
                "operator": "==",
                "threshold": 0,
                "severity_on_breach": "BLOCK",
                "description": "Blocks any commit containing hardcoded API keys, JWT tokens, or private credentials."
            },
            {
                "id": "RULE-MAX-EPSS",
                "name": "EPSS Weaponization Likelihood Ceiling",
                "field": "max_epss_score",
                "operator": "<=",
                "threshold": 0.25,
                "severity_on_breach": "WARN",
                "description": "Flags pull requests introducing dependencies with EPSS exploit probability over 25%."
            }
        ]
    }

    @classmethod
    def get_policy(cls) -> Dict[str, Any]:
        if os.path.exists(cls.POLICY_FILE):
            try:
                with open(cls.POLICY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return cls.DEFAULT_POLICY

    @classmethod
    def save_policy(cls, policy_dict: Dict[str, Any]) -> bool:
        try:
            os.makedirs(os.path.dirname(cls.POLICY_FILE), exist_ok=True)
            with open(cls.POLICY_FILE, "w", encoding="utf-8") as f:
                json.dump(policy_dict, f, indent=2)
            return True
        except Exception:
            return False

    @classmethod
    def evaluate(cls, findings: List[Dict[str, Any]], policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates a set of findings against active policies and returns gate verdict.
        """
        policy = policy or cls.get_policy()
        rules = policy.get("rules", [])

        # Calculate metrics from findings
        metrics = {
            "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "cisa_kev_count": sum(1 for f in findings if f.get("cisa_kev") is True),
            "secrets_count": sum(1 for f in findings if f.get("type") == "secrets" or "Secret" in f.get("title", "")),
            "max_epss_score": max((float(f.get("epss_score", 0.0)) for f in findings), default=0.0)
        }

        return cls.simulate_metrics(metrics, policy)

    @classmethod
    def simulate_metrics(cls, metrics: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Evaluates synthetic or extracted metrics against policy rules.
        """
        policy = policy or cls.get_policy()
        rules = policy.get("rules", [])

        rule_results = []
        is_blocked = False
        warning_count = 0

        for r in rules:
            field = r["field"]
            val = metrics.get(field, 0)
            op = r["operator"]
            thresh = r["threshold"]
            breach_sev = r.get("severity_on_breach", "BLOCK")

            passed = False
            if op == "<=":
                passed = val <= thresh
            elif op == "==":
                passed = val == thresh
            elif op == "<":
                passed = val < thresh
            elif op == ">=":
                passed = val >= thresh
            else:
                passed = val <= thresh

            if not passed:
                if breach_sev == "BLOCK":
                    is_blocked = True
                else:
                    warning_count += 1

            rule_results.append({
                "rule_id": r["id"],
                "name": r["name"],
                "field": field,
                "current_value": val,
                "threshold": thresh,
                "operator": op,
                "status": "PASSED" if passed else "FAILED",
                "action": "NONE" if passed else breach_sev,
                "description": r["description"]
            })

        verdict = "BLOCKED" if is_blocked else ("WARNING" if warning_count > 0 else "PASSED")

        return {
            "policy_name": policy.get("policy_name", "Security Gate"),
            "verdict": verdict,
            "can_merge": verdict != "BLOCKED",
            "metrics_evaluated": metrics,
            "rules_evaluated_count": len(rules),
            "rules_passed_count": sum(1 for r in rule_results if r["status"] == "PASSED"),
            "rules_failed_count": sum(1 for r in rule_results if r["status"] == "FAILED"),
            "rule_details": rule_results
        }
