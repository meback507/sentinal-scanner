"""
Unit and Integration tests for AegisSec LLM Configuration, Natural Language Rule Generation,
and AI-Powered Vulnerability Remediation with Developer Isolation.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db
from backend.integrations.llm_service import LLMService


class TestLLMService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # Retrieve users
        cls.admin_user = db.get_user_by_username("admin") or {"id": "u-admin", "username": "admin", "role": "admin"}
        cls.marcus_user = db.get_user_by_username("marcus") or {"id": "u-marcus", "username": "marcus", "role": "developer"}
        cls.elena_user = db.get_user_by_username("elena") or {"id": "u-elena", "username": "elena", "role": "developer"}

        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])
        cls.marcus_token = create_access_token(cls.marcus_user["id"], cls.marcus_user["username"], cls.marcus_user["role"])
        cls.elena_token = create_access_token(cls.elena_user["id"], cls.elena_user["username"], cls.elena_user["role"])

        # Ensure findings exist
        projects = db.list_projects()
        demo_proj = next((p for p in projects if "automotive-cloud-demo" in p["name"].lower()), None)
        cls.created_project = False
        if not demo_proj:
            demo_proj = db.create_project("Automotive-Cloud-Demo-Suite", "Test Desc", "", "main", "", "admin")
            cls.created_project = True
        cls.project_id = demo_proj["id"]

        findings = db.list_findings(cls.project_id)
        if not findings:
            from backend.main import trigger_scan
            from backend.models import UserModel
            u = UserModel(
                id=cls.admin_user["id"],
                username=cls.admin_user["username"],
                email=cls.admin_user["email"],
                role=cls.admin_user["role"],
                created_at=cls.admin_user["created_at"]
            )
            trigger_scan(cls.project_id, "full", u)

        cls.all_findings = db.list_findings(cls.project_id)

    def test_01_llm_config_get_and_save(self):
        """Verify LLM config retrieval and persistence with secret masking."""
        # Non-admin cannot save LLM config
        resp_forbidden = self.client.post(
            "/api/integrations/llm",
            json={"enabled": True, "provider": "openai", "model": "gpt-4o", "api_key": "sk-secret12345"},
            headers={"Authorization": f"Bearer {self.marcus_token}"}
        )
        self.assertEqual(resp_forbidden.status_code, 403)

        # Admin saves LLM config
        payload = {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4o",
            "api_key": "sk-test-secret-key-9999",
            "endpoint_url": "https://api.openai.com/v1",
            "temperature": 0.15,
            "enable_rule_generation": True,
            "enable_remediation": True
        }
        resp = self.client.post(
            "/api/integrations/llm",
            json=payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["success"])

        # GET config returns masked key
        get_resp = self.client.get("/api/integrations/llm", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(get_resp.status_code, 200)
        cfg = get_resp.json()
        self.assertEqual(cfg["provider"], "openai")
        self.assertEqual(cfg["model"], "gpt-4o")
        self.assertEqual(cfg["api_key"], "••••••••••••••••")

    def test_02_llm_test_connection_endpoint(self):
        """Verify POST /api/integrations/llm/test returns connection status."""
        resp = self.client.post(
            "/api/integrations/llm/test",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        res = resp.json()
        self.assertTrue(res["success"])
        self.assertIn("Connected", res["message"])

    def test_03_llm_rule_generation_via_service(self):
        """Verify LLM rule generation synthesizes correct SAST rule structure."""
        # Prompt for automotive MISRA dynamic allocation
        prompt = "Disallow dynamic memory allocation malloc and calloc in safety-critical C code per MISRA C:2012 Rule 21.3 and ISO 26262 ASIL-D"
        res = LLMService.generate_rule(prompt, target_ecosystem="c")
        self.assertIsNotNone(res)
        self.assertTrue(res["success"])
        rule = res["rule"]
        self.assertIn("rule_category", rule)
        self.assertIn("regex", rule)
        self.assertIn("c", rule["languages"])
        self.assertIn("MISRA C:2012", str(rule["standards"]))
        self.assertIn("yaml_representation", rule)

    def test_04_llm_rule_generation_api_endpoint(self):
        """Verify POST /api/rules/generate returns synthesized rule."""
        prompt = "Block SQL injection using raw cursor.execute queries with format strings in Python"
        resp = self.client.post(
            "/api/rules/generate",
            json={"prompt": prompt},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("regex", data)
        self.assertEqual(data["cwe"], "CWE-89")
        self.assertTrue(any("A03" in s or "OWASP" in s for s in data["standards"]))
        self.assertTrue(len(data["yaml_representation"]) > 20)

    def test_05_ai_remediation_admin_global_access(self):
        """Verify Admin can request AI remediation and code diff for any finding."""
        finding = self.all_findings[0]
        resp = self.client.post(
            f"/api/findings/{finding['id']}/ai-remediation",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        rem = resp.json()
        self.assertEqual(rem["finding_id"], finding["id"])
        self.assertTrue(len(rem["root_cause_analysis"]) > 20)
        self.assertTrue(len(rem["suggested_fix_diff"]) > 20)
        self.assertTrue(len(rem["compliance_implications"]) > 10)
        self.assertTrue(len(rem["verification_steps"]) > 10)
        self.assertIn("provider", rem)
        self.assertIn("model", rem)

    def test_06_ai_remediation_developer_author_scoped_access(self):
        """Verify Developer can generate remediation on code they authored."""
        # Find a finding authored by Marcus
        marcus_findings = [f for f in self.all_findings if f.get("author_name") == "Marcus Vance"]
        self.assertTrue(len(marcus_findings) > 0, "Expected at least one finding authored by Marcus Vance")
        marcus_f = marcus_findings[0]

        # Marcus requests remediation on his own finding -> SUCCESS
        resp = self.client.post(
            f"/api/findings/{marcus_f['id']}/ai-remediation",
            headers={"Authorization": f"Bearer {self.marcus_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        rem = resp.json()
        self.assertEqual(rem["finding_id"], marcus_f["id"])
        self.assertIn("suggested_fix_diff", rem)

    def test_07_ai_remediation_cross_developer_isolation(self):
        """Verify Developer CANNOT generate remediation on code authored by another developer (403 Forbidden)."""
        # Marcus's finding
        marcus_findings = [f for f in self.all_findings if f.get("author_name") == "Marcus Vance"]
        self.assertTrue(len(marcus_findings) > 0)
        marcus_f = marcus_findings[0]

        # Elena attempts to request remediation on Marcus's finding -> 403 Forbidden
        resp = self.client.post(
            f"/api/findings/{marcus_f['id']}/ai-remediation",
            headers={"Authorization": f"Bearer {self.elena_token}"}
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn("code you authored", resp.json()["detail"])

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "created_project", False):
            db.delete_project(cls.project_id)


if __name__ == "__main__":
    unittest.main()
