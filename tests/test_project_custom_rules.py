import unittest
import os
import shutil
import tempfile
from fastapi.testclient import TestClient
from backend.main import app
from backend.db import db
from backend.rules.rule_manager import rule_manager
from backend.scanners.sast_engine import SASTEngine


class TestProjectOrientedCustomRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Login as admin
        login_resp = cls.client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
        cls.token = login_resp.json()["access_token"]
        cls.headers = {"Authorization": f"Bearer {cls.token}"}

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="sentinel_test_proj_rules_")
        
        # Create Project Alpha and Project Beta
        self.proj_alpha = db.create_project(
            name="Project Alpha",
            description="Alpha service",
            git_url=os.path.join(self.tmp_dir, "alpha"),
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        self.proj_beta = db.create_project(
            name="Project Beta",
            description="Beta service",
            git_url=os.path.join(self.tmp_dir, "beta"),
            git_branch="main",
            git_pat="",
            created_by="admin"
        )

    def tearDown(self):
        try:
            shutil.rmtree(self.tmp_dir, ignore_errors=True)
        except Exception:
            pass

    def test_01_create_project_specific_rule_via_api(self):
        """Verify saving a rule scoped to Project Alpha associates project_id and project_name."""
        rule_data = {
            "name": "Disallow Alpha Internal Token",
            "type": "sast",
            "severity": "CRITICAL",
            "languages": ["python"],
            "cwe": "CWE-798",
            "owasp": "OWASP:A07:2021",
            "regex": r"ALPHA_SECRET_TOKEN_[A-Z0-9]+",
            "description": "Detect proprietary Alpha tokens.",
            "remediation": "Do not hardcode internal Alpha tokens.",
            "project_id": self.proj_alpha["id"]
        }
        resp = self.client.post("/api/rules/custom-builder", json=rule_data, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["rule"]["project_id"], self.proj_alpha["id"])
        self.assertEqual(data["rule"]["project_name"], "Project Alpha")
        rule_id = data["rule_id"]

        # Verify DB listing
        rule_in_db = db.get_rule_by_id(rule_id)
        self.assertIsNotNone(rule_in_db)
        self.assertEqual(rule_in_db["project_id"], self.proj_alpha["id"])

        # Clean up
        db.delete_rule(rule_id)

    def test_02_project_rule_isolation(self):
        """Verify Project Alpha rules do not leak into Project Beta listings or scans."""
        # Create an Alpha-only rule
        alpha_rule = {
            "id": "RULE-ALPHA-ISOLATION-01",
            "name": "Alpha Specific Banned String",
            "type": "sast_pattern",
            "rule_category": "sast",
            "languages": ["python"],
            "severity": "HIGH",
            "cwe": "CWE-200",
            "regex": r"ALPHA_FORBIDDEN_CALL\(",
            "description": "Banned API call only in Alpha",
            "remediation": "Replace with standard API",
            "project_id": self.proj_alpha["id"],
            "project_name": "Project Alpha",
            "is_active": True
        }
        db.save_rule(alpha_rule)

        # Create a Beta-only rule
        beta_rule = {
            "id": "RULE-BETA-ISOLATION-01",
            "name": "Beta Specific Banned String",
            "type": "sast_pattern",
            "rule_category": "sast",
            "languages": ["python"],
            "severity": "HIGH",
            "cwe": "CWE-200",
            "regex": r"BETA_FORBIDDEN_CALL\(",
            "description": "Banned API call only in Beta",
            "remediation": "Replace with standard API",
            "project_id": self.proj_beta["id"],
            "project_name": "Project Beta",
            "is_active": True
        }
        db.save_rule(beta_rule)

        # Create a Global rule
        global_rule = {
            "id": "RULE-GLOBAL-ISOLATION-01",
            "name": "Global Banned Password",
            "type": "sast_pattern",
            "rule_category": "sast",
            "languages": ["python"],
            "severity": "CRITICAL",
            "cwe": "CWE-798",
            "regex": r"HARDCODED_GLOBAL_PASS",
            "description": "Global banned string across all projects",
            "remediation": "Use vault",
            "project_id": None,
            "is_active": True
        }
        db.save_rule(global_rule)

        try:
            # Query rules for Alpha with include_global=True
            alpha_rules = rule_manager.get_active_sast_rules(project_id=self.proj_alpha["id"])
            alpha_ids = [r["id"] for r in alpha_rules]
            self.assertIn("RULE-ALPHA-ISOLATION-01", alpha_ids)
            self.assertIn("RULE-GLOBAL-ISOLATION-01", alpha_ids)
            self.assertNotIn("RULE-BETA-ISOLATION-01", alpha_ids, "Project Beta rule leaked into Project Alpha!")

            # Query rules for Beta
            beta_rules = rule_manager.get_active_sast_rules(project_id=self.proj_beta["id"])
            beta_ids = [r["id"] for r in beta_rules]
            self.assertIn("RULE-BETA-ISOLATION-01", beta_ids)
            self.assertIn("RULE-GLOBAL-ISOLATION-01", beta_ids)
            self.assertNotIn("RULE-ALPHA-ISOLATION-01", beta_ids, "Project Alpha rule leaked into Project Beta!")

            # Query via API endpoint with scope=project_only
            resp_alpha_only = self.client.get(
                f"/api/rules?project_id={self.proj_alpha['id']}&scope=project_only",
                headers=self.headers
            )
            self.assertEqual(resp_alpha_only.status_code, 200)
            alpha_only_ids = [r["id"] for r in resp_alpha_only.json()]
            self.assertIn("RULE-ALPHA-ISOLATION-01", alpha_only_ids)
            self.assertNotIn("RULE-GLOBAL-ISOLATION-01", alpha_only_ids)
            self.assertNotIn("RULE-BETA-ISOLATION-01", alpha_only_ids)

        finally:
            db.delete_rule("RULE-ALPHA-ISOLATION-01")
            db.delete_rule("RULE-BETA-ISOLATION-01")
            db.delete_rule("RULE-GLOBAL-ISOLATION-01")

    def test_03_scanner_applies_only_project_scoped_rules(self):
        """Verify SAST engine when scanning files only triggers rules applicable to that project."""
        alpha_rule = {
            "id": "RULE-TEST-SCAN-ALPHA-99",
            "name": "Alpha Unique Danger",
            "type": "sast_pattern",
            "rule_category": "sast",
            "languages": ["python"],
            "severity": "CRITICAL",
            "cwe": "CWE-89",
            "regex": r"exec_alpha_unsafe\(",
            "description": "Dangerous internal Alpha execution",
            "remediation": "Do not call",
            "project_id": self.proj_alpha["id"],
            "is_active": True
        }
        db.save_rule(alpha_rule)

        code_sample = """
def handler():
    exec_alpha_unsafe()
"""
        test_file_dir = os.path.join(self.tmp_dir, "code_test")
        os.makedirs(test_file_dir, exist_ok=True)
        test_file_path = os.path.join(test_file_dir, "handler.py")
        with open(test_file_path, "w") as f:
            f.write(code_sample)

        try:
            # 1. Scan with Project Alpha rules -> Must flag violation
            alpha_custom = rule_manager.get_active_sast_rules(project_id=self.proj_alpha["id"])
            sast_alpha = SASTEngine(custom_rules=alpha_custom, include_open_db=False)
            findings_alpha = sast_alpha.scan_directory(test_file_dir)
            alpha_found_ids = [f.get("rule_id") for f in findings_alpha]
            self.assertIn("RULE-TEST-SCAN-ALPHA-99", alpha_found_ids)

            # 2. Scan with Project Beta rules -> Must NOT flag violation (rule is Alpha-only)
            beta_custom = rule_manager.get_active_sast_rules(project_id=self.proj_beta["id"])
            sast_beta = SASTEngine(custom_rules=beta_custom, include_open_db=False)
            findings_beta = sast_beta.scan_directory(test_file_dir)
            beta_found_ids = [f.get("rule_id") for f in findings_beta]
            self.assertNotIn("RULE-TEST-SCAN-ALPHA-99", beta_found_ids, "Alpha rule was triggered during Beta scan!")

        finally:
            db.delete_rule("RULE-TEST-SCAN-ALPHA-99")


if __name__ == "__main__":
    unittest.main()
