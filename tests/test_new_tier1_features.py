"""
Test Suite for New AppSec Tier-1 Enterprise Features:
1. Interactive Dependency Tree & Transitive Blast Radius Visualizer
2. Conversational Security Copilot Chatbot (AI & Analytics)
3. Executive Compliance Crosswalk Matrix & Dossier Exporter (SOC 2, ISO 27001, PCI-DSS)
"""

import unittest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.db import db
from backend.models import RoleEnum
from backend.auth import create_access_token


class TestNewTier1Features(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # Create Admin
        cls.admin_user = db.create_user(
            username=f"admin_{uuid.uuid4().hex[:6]}",
            email=f"admin_{uuid.uuid4().hex[:6]}@enterprise.test",
            password="AdminPassword123!",
            role=RoleEnum.ADMIN.value
        )
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])

        # Create Developer Alice
        cls.alice_user = db.create_user(
            username=f"alice_{uuid.uuid4().hex[:6]}",
            email=f"alice_{uuid.uuid4().hex[:6]}@enterprise.test",
            password="AlicePassword123!",
            role=RoleEnum.DEVELOPER.value
        )
        cls.alice_token = create_access_token(cls.alice_user["id"], cls.alice_user["username"], cls.alice_user["role"])

        # Create Developer Bob
        cls.bob_user = db.create_user(
            username=f"bob_{uuid.uuid4().hex[:6]}",
            email=f"bob_{uuid.uuid4().hex[:6]}@enterprise.test",
            password="BobPassword123!",
            role=RoleEnum.DEVELOPER.value
        )
        cls.bob_token = create_access_token(cls.bob_user["id"], cls.bob_user["username"], cls.bob_user["role"])

        # Create Projects: Alpha (Alice only), Beta (Bob only)
        cls.proj_alpha = db.create_project(
            name=f"Project Alpha {uuid.uuid4().hex[:4]}",
            description="Alpha Enterprise App",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by=cls.admin_user["username"]
        )
        cls.proj_beta = db.create_project(
            name=f"Project Beta {uuid.uuid4().hex[:4]}",
            description="Beta Enterprise App",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by=cls.admin_user["username"]
        )

        db.assign_user_to_project(cls.proj_alpha["id"], cls.alice_user["id"], role="developer")
        db.assign_user_to_project(cls.proj_beta["id"], cls.bob_user["id"], role="developer")

        # Create sample findings in Alpha (including SQLi and SCA)
        cls.scan_id = db.create_scan(cls.proj_alpha["id"], cls.proj_alpha["name"], "full")
        cls.f_sqli = db.create_finding({
            "scan_id": cls.scan_id,
            "project_id": cls.proj_alpha["id"],
            "type": "sast",
            "title": "SQL Injection in User Profile Controller",
            "description": "Unsanitized user input formatted directly into SQL query",
            "severity": "CRITICAL",
            "file_path": "controllers/user.py",
            "line_start": 45,
            "line_end": 46,
            "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            "remediation": "Use parameterized queries cursor.execute(query, (uid,))",
            "cwe_id": "CWE-89",
            "author_name": cls.alice_user["username"]
        })

        cls.f_sca = db.create_finding({
            "scan_id": cls.scan_id,
            "project_id": cls.proj_alpha["id"],
            "type": "sca",
            "title": "urllib3: Insecure Cookie Leaking in Redirects",
            "description": "Urllib3 before 1.26.5 strips auth headers improperly",
            "severity": "HIGH",
            "package_name": "urllib3",
            "installed_version": "1.26.4",
            "fixed_version": "1.26.5",
            "cve_id": "CVE-2023-45803",
            "file_path": "requirements.txt",
            "line_start": 12,
            "remediation": "Upgrade urllib3 to >= 1.26.5"
        })

    def test_01_dependency_tree_and_blast_radius(self):
        """Verify GET /api/projects/{id}/dependencies/tree & /blast-radius with RBAC."""
        # Alice queries Alpha -> 200 OK
        resp_tree = self.client.get(
            f"/api/projects/{self.proj_alpha['id']}/dependencies/tree",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_tree.status_code, 200)
        data = resp_tree.json()
        self.assertEqual(data["project_id"], self.proj_alpha["id"])
        self.assertIn("summary", data)
        self.assertIn("tree", data)
        self.assertGreater(data["summary"]["total_dependencies"], 0)
        self.assertGreater(data["summary"]["direct_count"], 0)

        # Blast radius analysis
        resp_blast = self.client.get(
            f"/api/projects/{self.proj_alpha['id']}/dependencies/blast-radius",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_blast.status_code, 200)
        blast_data = resp_blast.json()
        self.assertIn("blast_radius_analysis", blast_data)
        items = blast_data["blast_radius_analysis"]
        self.assertTrue(any(b["package"].lower() == "urllib3" for b in items))

        # Alice queries Beta (unassigned) -> 403 Forbidden
        resp_unauth = self.client.get(
            f"/api/projects/{self.proj_beta['id']}/dependencies/tree",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_unauth.status_code, 403)

    def test_02_conversational_security_copilot_chat(self):
        """Verify POST /api/copilot/chat with project context and RBAC."""
        # Alice asks about security posture
        resp = self.client.post(
            "/api/copilot/chat",
            json={
                "project_id": self.proj_alpha["id"],
                "message": "Summarize the critical vulnerabilities and risk score."
            },
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        res_json = resp.json()
        self.assertIn("reply", res_json)
        self.assertIn("suggested_actions", res_json)
        self.assertIn("project_context", res_json)
        self.assertIn("Security Posture", res_json["reply"])

        # Alice asks how to fix SQL injection
        resp_fix = self.client.post(
            "/api/copilot/chat",
            json={
                "project_id": self.proj_alpha["id"],
                "message": "How do I fix the SQL injection vulnerability?"
            },
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_fix.status_code, 200)
        self.assertIn("Parameterized", resp_fix.json()["reply"])

        # Alice asks about supply chain / dependencies
        resp_dep = self.client.post(
            "/api/copilot/chat",
            json={
                "project_id": self.proj_alpha["id"],
                "message": "What is our dependency blast radius?"
            },
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_dep.status_code, 200)
        self.assertIn("Supply Chain", resp_dep.json()["reply"])

        # Alice queries prompts
        resp_prompts = self.client.get(
            f"/api/copilot/prompts?project_id={self.proj_alpha['id']}",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_prompts.status_code, 200)
        prompts = resp_prompts.json()
        self.assertIsInstance(prompts, list)
        self.assertGreater(len(prompts), 0)

        # Alice queries Beta (unassigned) -> Access Denied / 403
        resp_bad = self.client.post(
            "/api/copilot/chat",
            json={
                "project_id": self.proj_beta["id"],
                "message": "Give me secrets of Beta"
            },
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_bad.status_code, 200)
        self.assertIn("Access Denied", resp_bad.json()["reply"])

    def test_03_executive_compliance_crosswalk_and_html_export(self):
        """Verify GET /api/projects/{id}/compliance/matrix & /export/html with RBAC."""
        # 1. Project Compliance Matrix JSON
        resp_m = self.client.get(
            f"/api/projects/{self.proj_alpha['id']}/compliance/matrix",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_m.status_code, 200)
        matrix = resp_m.json()
        self.assertIn("meta", matrix)
        self.assertIn("frameworks", matrix)
        fws = matrix["frameworks"]
        self.assertIn("soc2", fws)
        self.assertIn("pci_dss", fws)
        self.assertIn("iso_27001", fws)
        self.assertIn("hipaa", fws)
        self.assertIn("nist_csf", fws)

        # 2. Executive HTML Dossier Export
        resp_html = self.client.get(
            f"/api/projects/{self.proj_alpha['id']}/compliance/export/html",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_html.status_code, 200)
        html_text = resp_html.text
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn("Executive Compliance Crosswalk Dossier", html_text)
        self.assertIn("SEAL:", html_text)
        self.assertIn("Regulatory Control Crosswalk & Evidence Matrix", html_text)

        # 3. Unauthorized access to Project Beta returns 403
        resp_unauth_html = self.client.get(
            f"/api/projects/{self.proj_beta['id']}/compliance/export/html",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_unauth_html.status_code, 403)


if __name__ == "__main__":
    unittest.main()
