"""
AegisSec - Custom Rule Manager
Stores, activates, edits, and loads custom SAST and SCA rules into active scans.
"""

import json
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


rule_manager = RuleManager()
