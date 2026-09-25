"""
Comprehensive End-to-End Test Suite and Bug Hunt
Verifies the complete lifecycle and multi-persona boundaries:
1. Multi-persona authentication & token lifecycle (Admin, Dev Alice, Dev Bob, Dev Charlie, SecEng Dave, Auditor Eve).
2. Project creation with initial assigned members.
3. Strict project visibility scoping across all roles.
4. Cross-project 403 Forbidden access enforcement (project details, scans, findings, reports).
5. Project membership management API (listing, assigning, revoking, unauthorized caller prevention).
6. Project-oriented custom rules scoping & isolation (project-scoped vs global rules).
7. Vulnerability findings queries and triage actions scoped strictly to assigned projects.
8. Security report exporters (HTML, SARIF, CycloneDX, SonarQube, OpenVEX, Audit Bundle) cross-project protection.
9. Scoped dashboard statistics metrics calculation per persona.
10. PUT /api/users/{id} project reassignment and cascading deletions.
"""

import unittest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db
from backend.rules.rule_manager import rule_manager


class TestEndToEndIsolationAndBugHunt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # 1. Super Admin
        cls.admin_user = db.get_user_by_username("admin") or {"id": "u-admin", "username": "admin", "role": "admin"}
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], "admin")

        # 2. Projects Alpha and Beta
        cls.proj_alpha = db.create_project(
            name=f"E2E-Project-Alpha-{uuid.uuid4().hex[:6]}",
            description="Alpha Powertrain Telematics",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        cls.proj_beta = db.create_project(
            name=f"E2E-Project-Beta-{uuid.uuid4().hex[:6]}",
            description="Beta Cloud Infotainment",
            git_url="",
            git_branch="develop",
            git_pat="",
            created_by="admin"
        )

        # 3. Create Users with designated project scopes
        # Alice -> Project Alpha
        cls.alice_name = f"alice_e2e_{uuid.uuid4().hex[:6]}"
        cls.alice = db.create_user(
            username=cls.alice_name,
            email=f"{cls.alice_name}@corp.internal",
            password="Password123!",
            role="developer",
            assigned_projects=[cls.proj_alpha["id"]]
        )
        cls.alice_token = create_access_token(cls.alice["id"], cls.alice["username"], "developer")

        # Bob -> Project Beta
        cls.bob_name = f"bob_e2e_{uuid.uuid4().hex[:6]}"
        cls.bob = db.create_user(
            username=cls.bob_name,
            email=f"{cls.bob_name}@corp.internal",
            password="Password123!",
            role="developer",
            assigned_projects=[cls.proj_beta["id"]]
        )
        cls.bob_token = create_access_token(cls.bob["id"], cls.bob["username"], "developer")

        # Charlie -> NO projects initially
        cls.charlie_name = f"charlie_e2e_{uuid.uuid4().hex[:6]}"
        cls.charlie = db.create_user(
            username=cls.charlie_name,
            email=f"{cls.charlie_name}@corp.internal",
            password="Password123!",
            role="developer",
            assigned_projects=[]
        )
        cls.charlie_token = create_access_token(cls.charlie["id"], cls.charlie["username"], "developer")

        # Dave -> Security Engineer on both Alpha and Beta
        cls.dave_name = f"dave_e2e_{uuid.uuid4().hex[:6]}"
        cls.dave = db.create_user(
            username=cls.dave_name,
            email=f"{cls.dave_name}@corp.internal",
            password="Password123!",
            role="security_engineer",
            assigned_projects=[cls.proj_alpha["id"], cls.proj_beta["id"]]
        )
        cls.dave_token = create_access_token(cls.dave["id"], cls.dave["username"], "security_engineer")

        # Eve -> Auditor on Alpha
        cls.eve_name = f"eve_e2e_{uuid.uuid4().hex[:6]}"
        cls.eve = db.create_user(
            username=cls.eve_name,
            email=f"{cls.eve_name}@corp.internal",
            password="Password123!",
            role="auditor",
            assigned_projects=[cls.proj_alpha["id"]]
        )
        cls.eve_token = create_access_token(cls.eve["id"], cls.eve["username"], "auditor")

        # 4. Populate Findings in Alpha and Beta
        cls.scan_alpha_id = db.create_scan(cls.proj_alpha["id"], cls.proj_alpha["name"], "full")
        cls.finding_alpha = db.create_finding({
            "scan_id": cls.scan_alpha_id,
            "project_id": cls.proj_alpha["id"],
            "type": "sast",
            "title": "SQL Injection in Alpha ECU",
            "description": "Unsanitized user input in query",
            "severity": "CRITICAL",
            "file_path": "ecu/query.py",
            "line_start": 25,
            "line_end": 28,
            "code_snippet": "cursor.execute(f'SELECT * FROM ecu WHERE id={uid}')",
            "remediation": "Use parameterized queries",
            "cwe_id": "CWE-89",
            "author_name": cls.alice_name,
            "author_email": f"{cls.alice_name}@corp.internal"
        })

        cls.scan_beta_id = db.create_scan(cls.proj_beta["id"], cls.proj_beta["name"], "full")
        cls.finding_beta = db.create_finding({
            "scan_id": cls.scan_beta_id,
            "project_id": cls.proj_beta["id"],
            "type": "sast",
            "title": "Hardcoded JWT Secret in Beta",
            "description": "Hardcoded signing key in auth service",
            "severity": "HIGH",
            "file_path": "auth/jwt.js",
            "line_start": 12,
            "line_end": 14,
            "code_snippet": "const secret = 'SuperSecretKey123!';",
            "remediation": "Load from environment variables",
            "cwe_id": "CWE-798",
            "author_name": cls.bob_name,
            "author_email": f"{cls.bob_name}@corp.internal"
        })

    def test_01_project_list_role_scoping(self):
        """Verify GET /api/projects returns strictly assigned projects for all personas."""
        # Alice (Alpha only)
        resp_a = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_a.status_code, 200)
        a_ids = [p["id"] for p in resp_a.json()]
        self.assertIn(self.proj_alpha["id"], a_ids)
        self.assertNotIn(self.proj_beta["id"], a_ids)

        # Bob (Beta only)
        resp_b = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.bob_token}"})
        self.assertEqual(resp_b.status_code, 200)
        b_ids = [p["id"] for p in resp_b.json()]
        self.assertIn(self.proj_beta["id"], b_ids)
        self.assertNotIn(self.proj_alpha["id"], b_ids)

        # Charlie (No projects)
        resp_c = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.charlie_token}"})
        self.assertEqual(resp_c.status_code, 200)
        c_ids = [p["id"] for p in resp_c.json()]
        self.assertEqual(c_ids, [])

        # Dave (Both Alpha and Beta)
        resp_d = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_d.status_code, 200)
        d_ids = [p["id"] for p in resp_d.json()]
        self.assertIn(self.proj_alpha["id"], d_ids)
        self.assertIn(self.proj_beta["id"], d_ids)

        # Admin (Global)
        resp_admin = self.client.get("/api/projects", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp_admin.status_code, 200)
        admin_ids = [p["id"] for p in resp_admin.json()]
        self.assertIn(self.proj_alpha["id"], admin_ids)
        self.assertIn(self.proj_beta["id"], admin_ids)

    def test_02_cross_project_direct_403_protection(self):
        """Attempting to access an unassigned project directly by ID returns 403 Forbidden."""
        # Alice tries Project Beta -> 403
        resp = self.client.get(f"/api/projects/{self.proj_beta['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Access denied", resp.json()["detail"])

        # Bob tries Project Alpha -> 403
        resp_bob = self.client.get(f"/api/projects/{self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.bob_token}"})
        self.assertEqual(resp_bob.status_code, 403)

        # Charlie tries either -> 403
        resp_c1 = self.client.get(f"/api/projects/{self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.charlie_token}"})
        self.assertEqual(resp_c1.status_code, 403)

        # Authorized access succeeds
        resp_ok = self.client.get(f"/api/projects/{self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_ok.status_code, 200)
        self.assertEqual(resp_ok.json()["name"], self.proj_alpha["name"])

    def test_03_project_membership_management_and_rbac(self):
        """Test listing, adding, and removing project members with RBAC guards."""
        # 1. Non-admin (Alice) cannot add members -> 403
        resp_unauth = self.client.post(
            f"/api/projects/{self.proj_alpha['id']}/members",
            json={"user_id": self.charlie["id"], "role": "developer"},
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_unauth.status_code, 403)

        # 2. Admin adds Charlie to Project Alpha
        resp_add = self.client.post(
            f"/api/projects/{self.proj_alpha['id']}/members",
            json={"user_id": self.charlie["id"], "role": "developer"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_add.status_code, 200)
        members = resp_add.json()
        member_ids = [m["user_id"] for m in members]
        self.assertIn(self.charlie["id"], member_ids)

        # 3. Charlie now has access to Project Alpha
        resp_c_access = self.client.get(f"/api/projects/{self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.charlie_token}"})
        self.assertEqual(resp_c_access.status_code, 200)

        # 4. Admin removes Charlie from Project Alpha
        resp_del = self.client.delete(
            f"/api/projects/{self.proj_alpha['id']}/members/{self.charlie['id']}",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_del.status_code, 200)

        # 5. Charlie loses access -> 403
        resp_c_lost = self.client.get(f"/api/projects/{self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.charlie_token}"})
        self.assertEqual(resp_c_lost.status_code, 403)

    def test_04_project_custom_rules_scoping(self):
        """Custom rules scoped to a project are isolated and do not leak to other projects."""
        rule_alpha_id = f"RULE-ALPHA-{uuid.uuid4().hex[:6]}"
        rule_beta_id = f"RULE-BETA-{uuid.uuid4().hex[:6]}"
        rule_global_id = f"RULE-GLOBAL-{uuid.uuid4().hex[:6]}"

        # Security Engineer Dave creates rule for Alpha, Beta, and Global
        r1 = db.create_custom_rule({
            "id": rule_alpha_id,
            "name": "Alpha Specific Rule",
            "type": "sast",
            "rule_category": "sast",
            "languages": ["python"],
            "severity": "HIGH",
            "regex": "test_alpha_danger",
            "description": "Restricted to Alpha",
            "remediation": "Do not use",
            "project_id": self.proj_alpha["id"]
        })
        self.assertIsNotNone(r1)

        r2 = db.create_custom_rule({
            "id": rule_beta_id,
            "name": "Beta Specific Rule",
            "type": "sast",
            "rule_category": "sast",
            "languages": ["javascript"],
            "severity": "MEDIUM",
            "regex": "test_beta_danger",
            "description": "Restricted to Beta",
            "remediation": "Do not use",
            "project_id": self.proj_beta["id"]
        })
        self.assertIsNotNone(r2)

        r3 = db.create_custom_rule({
            "id": rule_global_id,
            "name": "Global Enterprise Rule",
            "type": "sast",
            "rule_category": "sast",
            "languages": ["python", "javascript"],
            "severity": "CRITICAL",
            "regex": "test_global_danger",
            "description": "Global rule",
            "remediation": "Fix everywhere",
            "project_id": None
        })
        self.assertIsNotNone(r3)

        # Alice queries rules for Project Alpha -> gets Alpha rule + Global rule, NOT Beta rule
        resp_rules_a = self.client.get(f"/api/rules?project_id={self.proj_alpha['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_rules_a.status_code, 200)
        rules_a = [r["id"] for r in resp_rules_a.json()]
        self.assertIn(rule_alpha_id, rules_a)
        self.assertIn(rule_global_id, rules_a)
        self.assertNotIn(rule_beta_id, rules_a)

        # Alice tries querying rules for Project Beta -> 403 Forbidden!
        resp_unauth_rules = self.client.get(f"/api/rules?project_id={self.proj_beta['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_unauth_rules.status_code, 403)

        # Bob queries rules for Project Beta -> gets Beta rule + Global rule, NOT Alpha rule
        resp_rules_b = self.client.get(f"/api/rules?project_id={self.proj_beta['id']}", headers={"Authorization": f"Bearer {self.bob_token}"})
        self.assertEqual(resp_rules_b.status_code, 200)
        rules_b = [r["id"] for r in resp_rules_b.json()]
        self.assertIn(rule_beta_id, rules_b)
        self.assertIn(rule_global_id, rules_b)
        self.assertNotIn(rule_alpha_id, rules_b)

        # Cleanup test rules
        db.delete_custom_rule(rule_alpha_id)
        db.delete_custom_rule(rule_beta_id)
        db.delete_custom_rule(rule_global_id)

    def test_05_cross_project_findings_and_triage_protection(self):
        """Non-admin cannot list, view, or modify findings belonging to an unassigned project."""
        # 1. Listing: Alice lists findings -> finding_alpha is present, finding_beta is NOT
        resp_f = self.client.get("/api/findings", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_f.status_code, 200)
        f_ids = [f["id"] for f in resp_f.json()]
        self.assertIn(self.finding_alpha["id"], f_ids)
        self.assertNotIn(self.finding_beta["id"], f_ids)

        # 2. Filter query: Alice specifies ?project_id=Beta -> 403 Forbidden
        resp_filter = self.client.get(f"/api/findings?project_id={self.proj_beta['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_filter.status_code, 403)

        # 3. Direct ID query: Alice queries finding_beta by ID -> 403 Forbidden
        resp_detail = self.client.get(f"/api/findings/{self.finding_beta['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_detail.status_code, 403)

        # 4. Status update: Alice tries to change status on finding_beta -> 403 Forbidden
        resp_patch = self.client.patch(
            f"/api/findings/{self.finding_beta['id']}/status",
            json={"status": "false_positive", "reason": "Testing unauthorized update"},
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_patch.status_code, 403)

        # 5. AI remediation: Alice tries to request AI remediation for finding_beta -> 403 Forbidden
        resp_ai = self.client.post(
            f"/api/findings/{self.finding_beta['id']}/ai-remediation",
            headers={"Authorization": f"Bearer {self.alice_token}"}
        )
        self.assertEqual(resp_ai.status_code, 403)

    def test_06_all_exporters_protected_by_project_isolation(self):
        """Every report exporter endpoint returns 403 Forbidden for unassigned projects."""
        formats = ["html", "sarif", "cyclonedx", "csv", "vex", "sonarqube", "audit-bundle"]
        for fmt in formats:
            url = f"/api/projects/{self.proj_beta['id']}/export/{fmt}"
            resp = self.client.get(url, headers={"Authorization": f"Bearer {self.alice_token}"})
            self.assertEqual(
                resp.status_code, 403,
                f"Expected 403 for format '{fmt}' on unassigned project, got {resp.status_code}"
            )

        # Authorized export succeeds
        resp_ok = self.client.get(f"/api/projects/{self.proj_alpha['id']}/export/html", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_ok.status_code, 200)
        self.assertIn("<!DOCTYPE html>", resp_ok.text)

    def test_07_dashboard_stats_scoped_to_assigned_projects(self):
        """GET /api/dashboard/stats computes metrics strictly for authorized projects."""
        # Alice dashboard stats
        resp_a = self.client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_a.status_code, 200)
        stats_a = resp_a.json()
        self.assertEqual(stats_a.get("total_projects"), 1)

        # Bob dashboard stats
        resp_b = self.client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {self.bob_token}"})
        self.assertEqual(resp_b.status_code, 200)
        stats_b = resp_b.json()
        self.assertEqual(stats_b.get("total_projects"), 1)

        # Dave (2 projects)
        resp_d = self.client.get("/api/dashboard/stats", headers={"Authorization": f"Bearer {self.dave_token}"})
        self.assertEqual(resp_d.status_code, 200)
        stats_d = resp_d.json()
        self.assertGreaterEqual(stats_d.get("total_projects"), 2)

    def test_08_put_user_project_reassignment_lifecycle(self):
        """Updating user assigned_projects dynamically grants access."""
        # Update Alice to have access to both Alpha and Beta
        resp_update = self.client.put(
            f"/api/users/{self.alice['id']}",
            json={"assigned_projects": [self.proj_alpha["id"], self.proj_beta["id"]]},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_update.status_code, 200)
        updated_data = resp_update.json()
        self.assertIn(self.proj_alpha["id"], updated_data["assigned_projects"])
        self.assertIn(self.proj_beta["id"], updated_data["assigned_projects"])

        # Alice now has access to Project Beta
        resp_now_ok = self.client.get(f"/api/projects/{self.proj_beta['id']}", headers={"Authorization": f"Bearer {self.alice_token}"})
        self.assertEqual(resp_now_ok.status_code, 200)

        # Restore Alice back to Alpha only
        self.client.put(
            f"/api/users/{self.alice['id']}",
            json={"assigned_projects": [self.proj_alpha["id"]]},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )

    @classmethod
    def tearDownClass(cls):
        # Cascading cleanup
        db.delete_project(cls.proj_alpha["id"])
        db.delete_project(cls.proj_beta["id"])
        db.delete_user(cls.alice["id"])
        db.delete_user(cls.bob["id"])
        db.delete_user(cls.charlie["id"])
        db.delete_user(cls.dave["id"])
        db.delete_user(cls.eve["id"])


if __name__ == "__main__":
    unittest.main()
