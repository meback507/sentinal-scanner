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

    def test_login_with_admin_password(self):
        """Verify login works with username 'admin' and password 'admin'."""
        resp = self.client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["role"], "admin")

    def test_user_create_and_update_lifecycle(self):
        """Verify user creation and role/password update in RBAC."""
        import uuid
        test_username = f"user_{uuid.uuid4().hex[:6]}"
        create_payload = {
            "username": test_username,
            "email": f"{test_username}@enterprise.io",
            "password": "InitialPassword123!",
            "role": "developer"
        }

        # 1. Non-admin should be forbidden from creating users
        res_dev_create = self.client.post(
            "/api/users",
            json=create_payload,
            headers={"Authorization": f"Bearer {self.dev_token}"}
        )
        self.assertEqual(res_dev_create.status_code, 403)

        # 2. Admin creates the user
        res_create = self.client.post(
            "/api/users",
            json=create_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_create.status_code, 200)
        user_data = res_create.json()
        user_id = user_data["id"]
        self.assertEqual(user_data["role"], "developer")

        # 3. Admin updates the user's role and password
        update_payload = {
            "role": "security_engineer",
            "password": "UpdatedPassword456!",
            "email": f"updated_{test_username}@enterprise.io"
        }
        res_update = self.client.put(
            f"/api/users/{user_id}",
            json=update_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_update.status_code, 200)
        updated_data = res_update.json()
        self.assertEqual(updated_data["role"], "security_engineer")
        self.assertEqual(updated_data["email"], f"updated_{test_username}@enterprise.io")

        # 4. User logs in with newly updated password and checks role
        res_login = self.client.post(
            "/api/auth/login",
            json={"username": test_username, "password": "UpdatedPassword456!"}
        )
        self.assertEqual(res_login.status_code, 200)
        self.assertEqual(res_login.json()["user"]["role"], "security_engineer")


if __name__ == "__main__":
    unittest.main()
