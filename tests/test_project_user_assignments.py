"""
Unit tests for Project-Oriented User Assignments and Project-Level RBAC Isolation.
Verifies that:
- Non-admin users (developers, security engineers, auditors) can ONLY view and access
  details, findings, scans, quality gates, and reports for projects they are assigned to.
- Cross-project access by non-admins returns 403 Forbidden.
- Administrators retain global visibility across all projects.
- Project membership management endpoints (list, assign, remove) function securely.
"""

import unittest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db


class TestProjectUserAssignments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_user = db.get_user_by_username("admin") or {"id": "u-admin", "username": "admin", "role": "admin"}
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], "admin")

        # Create two distinct test projects
        cls.proj_a = db.create_project(
            name=f"Project-Alpha-{uuid.uuid4().hex[:6]}",
            description="Alpha Telematics Suite",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        cls.proj_b = db.create_project(
            name=f"Project-Beta-{uuid.uuid4().hex[:6]}",
            description="Beta Powertrain ECU",
            git_url="",
            git_branch="develop",
            git_pat="",
            created_by="admin"
        )

        # Create finding in Project A and finding in Project B
        cls.scan_a_id = db.create_scan(cls.proj_a["id"], cls.proj_a["name"], "full")
        f_a = db.create_finding({
            "scan_id": cls.scan_a_id,
            "project_id": cls.proj_a["id"],
            "type": "sast",
            "title": "SQL Injection in Alpha Auth",
            "description": "Unsanitized query in login handler",
            "severity": "HIGH",
            "file_path": "src/auth.py",
            "line_start": 10,
            "line_end": 15,
            "code_snippet": "query = f'SELECT * FROM users WHERE name={user}'",
            "remediation": "Use parameterized queries",
            "cwe_id": "CWE-89",
            "author_name": "Alice Developer",
            "author_email": "alice@corp.internal"
        })
        cls.finding_a_id = f_a["id"]

        cls.scan_b_id = db.create_scan(cls.proj_b["id"], cls.proj_b["name"], "full")
        f_b = db.create_finding({
            "scan_id": cls.scan_b_id,
            "project_id": cls.proj_b["id"],
            "type": "sast",
            "title": "Buffer Overflow in Beta CanBus",
            "description": "Unchecked memcpy in packet receiver",
            "severity": "CRITICAL",
            "file_path": "src/canbus.c",
            "line_start": 50,
            "line_end": 55,
            "code_snippet": "memcpy(buf, packet, packet_len);",
            "remediation": "Bound check packet_len against buffer size",
            "cwe_id": "CWE-120",
            "author_name": "Bob Engineer",
            "author_email": "bob@corp.internal"
        })
        cls.finding_b_id = f_b["id"]

        # Create Developer Alice, assigned ONLY to Project A
        cls.alice_username = f"alice_{uuid.uuid4().hex[:6]}"
        cls.alice_user = db.create_user(
            username=cls.alice_username,
            email=f"{cls.alice_username}@corp.internal",
            password="SecurePassword123!",
            role="developer",
            assigned_projects=[cls.proj_a["id"]]
        )
        cls.alice_token = create_access_token(cls.alice_user["id"], cls.alice_user["username"], "developer")

        # Create Security Engineer Dave, assigned ONLY to Project B
        cls.dave_username = f"dave_{uuid.uuid4().hex[:6]}"
        cls.dave_user = db.create_user(
            username=cls.dave_username,
            email=f"{cls.dave_username}@corp.internal",
            password="SecurePassword123!",
            role="security_engineer",
            assigned_projects=[cls.proj_b["id"]]
        )
        cls.dave_token = create_access_token(cls.dave_user["id"], cls.dave_user["username"], "security_engineer")

    def test_01_user_model_includes_assigned_projects(self):
        """Verify UserModel and /api/users include assigned_projects."""
        resp = self.client.get("/api/users", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp.status_code, 200)
        users = resp.json()
        alice_entry = next((u for u in users if u["id"] == self.alice_user["id"]), None)
        self.assertIsNotNone(alice_entry)
        self.assertIn(self.proj_a["id"], alice_entry["assigned_projects"])
        self.assertNotIn(self.proj_b["id"], alice_entry["assigned_projects"])

    def test_02_project_list_scoped_to_assigned_projects(self):
        """Non-admin user only sees projects they are assigned to in GET /api/projects."""
        # Alice only sees Project A
        resp_alice = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_alice.status_code, 200)
        alice_proj_ids = [p["id"] for p in resp_alice.json()]
        self.assertIn(self.proj_a["id"], alice_proj_ids)
        self.assertNotIn(self.proj_b["id"], alice_proj_ids)

        # Dave only sees Project B
        resp_dave = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_dave.status_code, 200)
        dave_proj_ids = [p["id"] for p in resp_dave.json()]
        self.assertIn(self.proj_b["id"], dave_proj_ids)
        self.assertNotIn(self.proj_a["id"], dave_proj_ids)

        # Admin sees both
        resp_admin = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp_admin.status_code, 200)
        admin_proj_ids = [p["id"] for p in resp_admin.json()]
        self.assertIn(self.proj_a["id"], admin_proj_ids)
        self.assertIn(self.proj_b["id"], admin_proj_ids)

    def test_03_cross_project_direct_access_forbidden(self):
        """Non-admin attempting to fetch another project by ID gets 403 Forbidden."""
        # Alice tries to inspect Project B -> 403
        resp = self.client.get(f"/api/projects/{self.proj_b['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Access denied", resp.json()["detail"])

        # Alice inspects Project A -> 200
        resp_ok = self.client.get(f"/api/projects/{self.proj_a['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(resp_ok.json()["name"], self.proj_a["name"])

    def test_04_cross_project_findings_access_forbidden(self):
        """Non-admin attempting to list or view findings of an unassigned project gets 403."""
        # Alice queries findings with ?project_id=Project-B -> 403
        resp = self.client.get(f"/api/findings?project_id={self.proj_b['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp.status_code, 403)

        # Alice queries finding B directly by ID -> 403
        resp_finding = self.client.get(f"/api/findings/{self.finding_b_id}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_finding.status_code, 403)

    def test_05_cross_project_scan_trigger_forbidden(self):
        """Security Engineer Dave cannot trigger scan on Project A (not assigned to it)."""
        resp = self.client.post(f"/api/projects/{self.proj_a['id']}/scan", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp.status_code, 403)

        # Dave CAN trigger scan on Project B
        resp_b = self.client.post(f"/api/projects/{self.proj_b['id']}/scan", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_b.status_code, 200)

    def test_06_cross_project_reports_and_exporters_forbidden(self):
        """Exporting HTML, SARIF, or CSV for unassigned project returns 403."""
        resp_html = self.client.get(f"/api/projects/{self.proj_b['id']}/export/html", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_html.status_code, 403)

        resp_sarif = self.client.get(f"/api/projects/{self.proj_b['id']}/export/sarif", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_sarif.status_code, 403)

        resp_csv = self.client.get(f"/api/projects/{self.proj_b['id']}/export/csv", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_csv.status_code, 403)

    def test_07_project_membership_management_endpoints(self):
        """Verify listing members, assigning new members, and removing members from a project."""
        # 1. Admin lists members of Project A
        resp_list = self.client.get(f"/api/projects/{self.proj_a['id']}/members", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp_list.status_code, 200)
        members = resp_list.json()
        member_ids = [m["user_id"] for m in members]
        self.assertIn(self.alice_user["id"], member_ids)

        # 2. Admin assigns Dave to Project A as well
        resp_assign = self.client.post(
            f"/api/projects/{self.proj_a['id']}/members",
            json={"user_ids": [self.dave_user["id"]], "role": "security_engineer"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_assign.status_code, 200)
        updated_member_ids = [m["user_id"] for m in resp_assign.json()]
        self.assertIn(self.dave_user["id"], updated_member_ids)

        # 3. Now Dave has access to Project A
        resp_dave_access = self.client.get(f"/api/projects/{self.proj_a['id']}", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_dave_access.status_code, 200)

        # 4. Admin removes Dave from Project A
        resp_del = self.client.delete(
            f"/api/projects/{self.proj_a['id']}/members/{self.dave_user['id']}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_del.status_code, 200)

        # 5. Dave once again gets 403 on Project A
        resp_dave_lost = self.client.get(f"/api/projects/{self.proj_a['id']}", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_dave_lost.status_code, 403)

    def test_08_update_user_assigned_projects_via_api(self):
        """Updating user via PUT /api/users/{id} updates project assignments."""
        update_payload = {
            "assigned_projects": [self.proj_a["id"], self.proj_b["id"]]
        }
        resp = self.client.put(
            f"/api/users/{self.alice_user['id']}",
            json=update_payload,
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn(self.proj_a["id"], data["assigned_projects"])
        self.assertIn(self.proj_b["id"], data["assigned_projects"])

        # Alice can now view Project B
        resp_b = self.client.get(f"/api/projects/{self.proj_b['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_b.status_code, 200)

    @classmethod
    def tearDownClass(cls):
        db.delete_project(cls.proj_a["id"])
        db.delete_project(cls.proj_b["id"])
        db.delete_user(cls.alice_user["id"])
        db.delete_user(cls.dave_user["id"])


if __name__ == "__main__":
    unittest.main()
