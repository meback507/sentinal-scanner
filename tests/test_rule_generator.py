"""
Unit tests for Natural Language Rule Generator and Sandbox Test Bench.
"""

import unittest
from backend.rules.nl_rule_generator import NLRuleGenerator


class TestRuleGenerator(unittest.TestCase):
    def test_sast_rule_generation_from_text(self):
        prompt = "Disallow dynamic memory allocation malloc or free in C/C++ for MISRA compliance"
        rule = NLRuleGenerator.generate_from_text(prompt)

        self.assertEqual(rule["type"], "sast_pattern")
        self.assertIn("c", rule["languages"])
        self.assertIn("cpp", rule["languages"])
        self.assertIn("malloc", rule["regex"])
        self.assertTrue(any("MISRA" in s for s in rule["standards"]))
        self.assertTrue("yaml_representation" in rule)

    def test_sca_policy_generation_from_text(self):
        prompt = "Ban dependency package lodash below version 4.17.21 or license AGPL-3.0"
        rule = NLRuleGenerator.generate_from_text(prompt)

        self.assertEqual(rule["type"], "sca_policy")
        self.assertEqual(rule["rule_category"], "sca")
        self.assertIn("AGPL-3.0", rule["banned_license"])

    def test_rule_sandbox_execution(self):
        prompt = "Detect hardcoded API keys or JWT tokens in Python"
        rule = NLRuleGenerator.generate_from_text(prompt)

        # Test against vulnerable code
        vuln_code = "api_key = 'abcdef1234567890abcdef'\nprint(api_key)"
        res = NLRuleGenerator.test_rule_against_code(rule, vuln_code)

        self.assertTrue(res["success"])
        self.assertGreater(res["matched_count"], 0)
        self.assertEqual(res["matches"][0]["line"], 1)

        # Test against safe code
        safe_code = "api_key = os.environ.get('API_KEY')\nprint(api_key)"
        safe_res = NLRuleGenerator.test_rule_against_code(rule, safe_code)
        self.assertEqual(safe_res["matched_count"], 0)


if __name__ == "__main__":
    unittest.main()
