"""
AegisSec Custom Rule Generator & Rule Manager Unit Test Suite
Validates Natural Language rule synthesis (SAST & SCA), AST/regex compilation, and YAML serialization.
"""

import pytest
import yaml
from backend.rules.nl_rule_generator import NLRuleGenerator
from backend.rules.rule_manager import rule_manager


def test_nl_rule_generator_sast_synthesis():
    prompt = "Ban dynamic eval and execution in python and javascript"
    rule = NLRuleGenerator.generate_from_text(prompt, target_ecosystem="python")
    
    assert rule is not None
    assert rule["rule_category"] == "sast"
    assert "eval" in rule["regex"] or "exec" in rule["regex"]
    assert "yaml_representation" in rule
    
    # Parse YAML representation
    parsed = yaml.safe_load(rule["yaml_representation"])
    assert parsed["id"] == rule["id"]
    assert parsed["cwe"] is not None


def test_nl_rule_generator_sca_synthesis():
    prompt = "Restrict dependency package lodash below version 4.17.21 due to prototype pollution"
    rule = NLRuleGenerator.generate_from_text(prompt, target_ecosystem="npm")

    assert rule is not None
    assert rule["rule_category"] == "sca"
    assert rule["target_package"] == "lodash"
    assert "4.17.21" in rule.get("banned_version_range", "")


def test_nl_rule_generator_alias():
    prompt = "Disallow division by zero in python"
    rule1 = NLRuleGenerator.generate_from_text(prompt)
    rule2 = NLRuleGenerator.generate_rule(prompt)
    
    assert rule1["rule_category"] == "sast"
    assert rule2["rule_category"] == "sast"
    assert rule2["cwe"] is not None


def test_rule_catalog_listing():
    catalog = rule_manager.get_complete_rule_catalog(".")
    assert "summary" in catalog
    assert catalog["summary"]["total_active_rules"] > 0
    assert "rules" in catalog
    assert "sast_builtin" in catalog["rules"]
    assert len(catalog["rules"]["sast_builtin"]) > 0

