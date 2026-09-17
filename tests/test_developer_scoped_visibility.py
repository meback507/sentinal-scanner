"""
Unit tests for Developer-Scoped Vulnerability Visibility and RBAC Isolation.
Verifies that when a developer logs in, they can ONLY view, triage, and export
vulnerabilities in code they authored (via Git blame attribution), while
admins, sec leads, and auditors retain global visibility.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db


class TestDeveloperScopedVisibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        
        # Ensure a demo scan is present
        projects = db.list_projects()
        demo_proj = next((p for p in projects if "demo" in p["name"].lower() or not p.get("git_url")), None)
        if not demo_proj:
            demo_proj = db.create_project("Automotive-Cloud-Demo-Suite", "Test Desc", "", "main", "", "admin")
        cls.project_id = demo_proj["id"]
            
        findings = db.list_findings(cls.project_id)
        if not findings:
            from backend.main import trigger_scan
            from backend.models import UserModel
            admin_user = db.get_user_by_username("admin")
            u = UserModel(
                id=admin_user["id"],
                username=admin_user["username"],
                email=admin_user["email"],
                role=admin_user["role"],
                created_at=admin_user["created_at"]
            )
            trigger_scan(cls.project_id, "full", u)

        # Retrieve user credentials and generate tokens
        cls.admin_user = db.get_user_by_username("admin")
        cls.marcus_user = db.get_user_by_username("marcus")
        cls.elena_user = db.get_user_by_username("elena")
        cls.sarah_user = db.get_user_by_username("sarah")

        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])
        cls.marcus_token = create_access_token(cls.marcus_user["id"], cls.marcus_user["username"], cls.marcus_user["role"])
        cls.elena_token = create_access_token(cls.elena_user["id"], cls.elena_user["username"], cls.elena_user["role"])
        cls.sarah_token = create_access_token(cls.sarah_user["id"], cls.sarah_user["username"], cls.sarah_user["role"])

    def test_01_admin_has_global_visibility(self):
        """Admin should see all findings across all developers and supply chain files."""
        resp = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp.status_code, 200)
        findings = resp.json()
        self.assertGreaterEqual(len(findings), 10)
        
        authors = {f.get("author_name") for f in findings}
        self.assertIn("Marcus Vance", authors)
        self.assertIn("Dr. Elena Rostova", authors)
        self.assertIn("Sarah Lin", authors)
        self.assertIn("DevOps Engineer", authors)

    def test_02_marcus_vance_scoped_findings(self):
        """Marcus Vance should only see vulnerabilities in code he authored (app.py)."""
        resp = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.marcus_token}"})
        self.assertEqual(resp.status_code, 200)
        findings = resp.json()
        self.assertGreater(len(findings), 0)

        for f in findings:
            self.assertEqual(f["author_name"], "Marcus Vance")
            self.assertEqual(f["author_email"], "marcus.vance@cloudsec.internal")
            self.assertEqual(f["file_path"], "app.py")

    def test_03_elena_rostova_scoped_findings(self):
        """Dr. Elena Rostova should only see vulnerabilities in code she authored (ecu_controller.cpp)."""
        resp = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.elena_token}"})
        self.assertEqual(resp.status_code, 200)
        findings = resp.json()
        self.assertGreater(len(findings), 0)

        for f in findings:
            self.assertEqual(f["author_name"], "Dr. Elena Rostova")
            self.assertEqual(f["author_email"], "elena.rostova@autocorp.de")
            self.assertEqual(f["file_path"], "ecu_controller.cpp")

    def test_04_sarah_lin_scoped_findings(self):
        """Sarah Lin should only see vulnerabilities in code she authored (dashboard.js)."""
        resp = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.sarah_token}"})
        self.assertEqual(resp.status_code, 200)
        findings = resp.json()
        self.assertGreater(len(findings), 0)

        for f in findings:
            self.assertEqual(f["author_name"], "Sarah Lin")
            self.assertEqual(f["author_email"], "sarah.lin@frontend.io")
            self.assertEqual(f["file_path"], "dashboard.js")

    def test_05_cross_developer_finding_access_forbidden(self):
        """A developer accessing another developer's finding directly via ID receives 403 Forbidden."""
        # Get Marcus's finding ID
        res_marcus = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.marcus_token}"})
        marcus_findings = res_marcus.json()
        self.assertTrue(len(marcus_findings) > 0)
        marcus_finding_id = marcus_findings[0]["id"]

        # Elena attempts to access Marcus's finding
        res_forbidden = self.client.get(
            f"/api/findings/{marcus_finding_id}",
            headers={"Authorization": f"Bearer {self.elena_token}"}
        )
        self.assertEqual(res_forbidden.status_code, 403)
        self.assertIn("Access denied", res_forbidden.json()["detail"])

        # Marcus accesses his own finding -> 200 OK
        res_ok = self.client.get(
            f"/api/findings/{marcus_finding_id}",
            headers={"Authorization": f"Bearer {self.marcus_token}"}
        )
        self.assertEqual(res_ok.status_code, 200)
        self.assertEqual(res_ok.json()["id"], marcus_finding_id)

    def test_06_cross_developer_status_tampering_forbidden(self):
        """A developer cannot modify status of code authored by another developer."""
        res_marcus = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.marcus_token}"})
        marcus_finding_id = res_marcus.json()[0]["id"]

        # Elena attempts to resolve Marcus's vulnerability
        res_tamper = self.client.patch(
            f"/api/findings/{marcus_finding_id}/status?status_val=resolved",
            headers={"Authorization": f"Bearer {self.elena_token}"}
        )
        self.assertEqual(res_tamper.status_code, 403)
        self.assertIn("Access denied", res_tamper.json()["detail"])

        # Marcus resolves his own finding -> 200 OK
        res_resolve = self.client.patch(
            f"/api/findings/{marcus_finding_id}/status?status_val=resolved",
            headers={"Authorization": f"Bearer {self.marcus_token}"}
        )
        self.assertEqual(res_resolve.status_code, 200)
        self.assertEqual(res_resolve.json()["status"], "resolved")

    def test_07_developer_scoped_dashboard_stats(self):
        """Dashboard statistics for a developer must be calculated strictly on their authored code."""
        # Elena stats
        res_elena_stats = self.client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {self.elena_token}"})
        self.assertEqual(res_elena_stats.status_code, 200)
        elena_data = res_elena_stats.json()
        self.assertTrue(elena_data["is_developer_scoped"])
        self.assertEqual(elena_data["scoped_developer_name"], "elena")

        # Get Elena findings count
        res_elena_findings = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.elena_token}"})
        elena_count = len(res_elena_findings.json())
        self.assertEqual(elena_data["total_findings"], elena_count)

        # Developer attribution scorecard for Elena should only show Dr. Elena Rostova
        dev_names = [d["name"] for d in elena_data["developer_attribution"]]
        self.assertEqual(dev_names, ["Dr. Elena Rostova"])

    def test_08_developer_scoped_export(self):
        """Reports exported by a developer must contain only their authored flaws."""
        res_csv = self.client.get(
            f"/api/projects/{self.project_id}/export/csv",
            headers={"Authorization": f"Bearer {self.sarah_token}"}
        )
        self.assertEqual(res_csv.status_code, 200)
        csv_text = res_csv.text
        self.assertIn("Sarah Lin", csv_text)
        self.assertNotIn("Dr. Elena Rostova", csv_text)
        self.assertNotIn("Marcus Vance", csv_text)


if __name__ == "__main__":
    unittest.main()
