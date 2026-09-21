"""
Unit tests for Natural Language Rule Generator and Sandbox Test Bench.
Verifies generalized semantic intent parsing, CWE-369 divide-by-zero detection,
and live test bench execution without hardcoding.
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

    def test_division_by_zero_rule_generation_and_sandbox(self):
        """
        Verifies the user scenario: 'anything divided by zero is not possible'
        correctly synthesizes CWE-369 (Divide By Zero) and detects the violation in the test bench.
        """
        prompt = "anything divided by zero is not possible"
        rule = NLRuleGenerator.generate_from_text(prompt)

        self.assertEqual(rule["cwe"], "CWE-369")
        self.assertEqual(rule["severity"], "HIGH")
        self.assertIn("Division or Modulo by Zero", rule["name"])
        self.assertTrue(any("369" in s for s in rule["standards"]))
        self.assertIn("sample_trigger_code", rule)

        # Test 1: Sandbox execution against generated sample trigger code
        trigger_code = rule["sample_trigger_code"]
        res_sample = NLRuleGenerator.test_rule_against_code(rule, trigger_code)
        self.assertTrue(res_sample["success"])
        self.assertTrue(res_sample["violation_detected"])
        self.assertGreater(res_sample["matched_count"], 0)

        # Test 2: Multiple vulnerable code variations
        vuln_variations = [
            "result = 10 / 0",
            "val = total // 0",
            "remainder = count % 0",
            "val = x / (0)",
            "calc = metric / 0.0"
        ]
        for snippet in vuln_variations:
            res = NLRuleGenerator.test_rule_against_code(rule, snippet)
            self.assertTrue(res["success"], f"Failed on snippet: {snippet}")
            self.assertTrue(res["violation_detected"], f"Violation not detected on: {snippet}")
            self.assertGreaterEqual(res["matched_count"], 1, f"No matches found on: {snippet}")

        # Test 3: Safe code should pass cleanly with 0 violations
        safe_snippets = [
            "result = 10 / 2",
            "result = total / count",
            "if divisor != 0:\n    val = num / divisor",
            "mod = value % 10"
        ]
        for snippet in safe_snippets:
            res = NLRuleGenerator.test_rule_against_code(rule, snippet)
            self.assertTrue(res["success"], f"Failed on safe snippet: {snippet}")
            self.assertFalse(res["violation_detected"], f"False positive on: {snippet}")
            self.assertEqual(res["matched_count"], 0, f"False positive match on: {snippet}")

    def test_generalized_semantic_variations_without_hardcoding(self):
        """
        Verifies that multiple linguistic variants synthesize the correct taxonomy without hardcoding.
        """
        # Division variations
        variants = [
            "dividing by zero is forbidden",
            "prevent division by 0 in all modules",
            "check for mod 0 operations"
        ]
        for v in variants:
            r = NLRuleGenerator.generate_from_text(v)
            self.assertEqual(r["cwe"], "CWE-369", f"Failed for variant: {v}")

        # Float comparison
        float_rule = NLRuleGenerator.generate_from_text("comparing floating point numbers with ==")
        self.assertEqual(float_rule["cwe"], "CWE-1077")

        # Config debug mode
        debug_rule = NLRuleGenerator.generate_from_text("debug mode enabled")
        self.assertEqual(debug_rule["cwe"], "CWE-489")

    def test_division_by_non_zero_operand_and_sandbox(self):
        """
        Verifies the user scenario: 'flag when a division by 2 is done'
        correctly synthesizes division by 2 and triggers on '5/2' in the test bench.
        """
        prompt = "flag when a division by 2 is done"
        rule = NLRuleGenerator.generate_from_text(prompt)

        self.assertIn("Division or Modulo by 2", rule["name"])
        self.assertNotIn("Detect Occurrences of 'division'", rule["name"])
        self.assertIn("sample_trigger_code", rule)

        # Test against '5/2'
        res = NLRuleGenerator.test_rule_against_code(rule["yaml_representation"], "5/2")
        self.assertTrue(res["success"])
        self.assertTrue(res["violation_detected"])
        self.assertEqual(res["matched_count"], 1)
        self.assertEqual(res["matches"][0]["line"], 1)
        self.assertEqual(res["matches"][0]["matched_text"], "/2")

        # Test against safe code '5/3'
        safe_res = NLRuleGenerator.test_rule_against_code(rule["yaml_representation"], "5/3")
        self.assertTrue(safe_res["success"])
        self.assertFalse(safe_res["violation_detected"])
        self.assertEqual(safe_res["matched_count"], 0)

        # Ensure YAML representation has no nested duplicate yaml_representation key
        self.assertNotIn('yaml_representation: "', rule["yaml_representation"])


if __name__ == "__main__":
    unittest.main()
