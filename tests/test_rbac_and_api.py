"""
Unit tests for API endpoints, Projects CRUD, and Role-Based Access Control (RBAC).
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db


class TestRBACAndAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        admin_user = db.get_user_by_username("admin")
        dev_user = db.get_user_by_username("developer")
        self.admin_token = create_access_token(admin_user["id"], admin_user["username"], admin_user["role"])
        self.dev_token = create_access_token(dev_user["id"], dev_user["username"], dev_user["role"])

    def test_dashboard_stats_endpoint(self):
        resp = self.client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("total_projects", data)
        self.assertIn("quadrants", data)
        self.assertIn("standards_summary", data)

    def test_project_crud_lifecycle(self):
        # 1. Create project with PAT
        create_payload = {
            "name": "Safety-Critical-BMS",
            "description": "Battery Management System ISO 26262 ASIL-D",
            "git_url": "https://github.com/autocorp/bms-ecu.git",
            "git_branch": "main",
            "git_pat": "ghp_secure_personal_access_token_123"
        }
        res_create = self.client.post(
            "/api/projects",
            json=create_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_create.status_code, 200)
        proj = res_create.json()
        proj_id = proj["id"]
        self.assertTrue(proj["git_pat_configured"])

        # 2. Verify in list
        res_list = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res_list.status_code, 200)
        project_ids = [p["id"] for p in res_list.json()]
        self.assertIn(proj_id, project_ids)

        # 3. RBAC Check: Developer should NOT be allowed to delete projects
        res_del_dev = self.client.delete(
            f"/api/projects/{proj_id}",
            headers={"Authorization": f"Bearer {self.dev_token}"}
        )
        self.assertEqual(res_del_dev.status_code, 403)

        # 4. Admin deletes project
        res_del_admin = self.client.delete(
            f"/api/projects/{proj_id}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_del_admin.status_code, 200)

    def test_standards_endpoint(self):
        res = self.client.get("/api/standards", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("taxonomy", data)
        self.assertIn("ISO-27001", data["taxonomy"])
        self.assertIn("ISO-26262", data["taxonomy"])
        self.assertIn("MISRA", data["taxonomy"])


if __name__ == "__main__":
    unittest.main()
