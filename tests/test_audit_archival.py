"""
Unit tests for Archiving Solved Vulnerabilities to the Compliance Audit Trail.
Verifies:
- Solved/resolved vulnerabilities are excluded from active findings (GET /api/findings)
- GET /api/findings?include_resolved=true retains resolved vulnerabilities for auditing
- POST /api/findings/archive-resolved migrates solved vulnerabilities into immutable audit logs with SHA-256 seals
- Solved findings are permanently purged from active findings after archival
"""

import unittest
import uuid
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db
from backend.models import UserModel, RoleEnum


class TestAuditArchival(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # Create isolated test project
        cls.project = db.create_project(
            name=f"Audit-Archival-Test-{uuid.uuid4().hex[:6]}",
            description="Testing solved vulnerabilities audit retention",
            git_url="https://github.com/mock/audit-test.git",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        cls.project_id = cls.project["id"]

        # Admin user and token
        cls.admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(
            cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"]
        )
        cls.headers = {"Authorization": f"Bearer {cls.admin_token}"}

    @classmethod
    def tearDownClass(cls):
        db.delete_project(cls.project_id)

    def test_01_resolved_findings_excluded_from_active_list(self):
        """Active findings endpoint (/api/findings) must exclude resolved vulnerabilities by default."""
        scan_id = db.create_scan(self.project_id, self.project["name"], "full")
        flaws = [
            {
                "type": "sast",
                "title": "SQL Injection in User Search",
                "file_path": "backend/search.py",
                "line_start": 45,
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.5,
                "status": "open"
            },
            {
                "type": "sast",
                "title": "Resolved Insecure Deserialization",
                "file_path": "backend/parser.py",
                "line_start": 80,
                "severity": "HIGH",
                "cvss_score": 8.5,
                "epss_score": 0.4,
                "status": "resolved"
            }
        ]
        db.update_scan_results(scan_id, self.project_id, flaws)

        # 1. Default request: resolved must be excluded
        resp_default = self.client.get(f"/api/findings?project_id={self.project_id}", headers=self.headers)
        self.assertEqual(resp_default.status_code, 200)
        items_default = resp_default.json()
        titles_default = [f["title"] for f in items_default]
        self.assertIn("SQL Injection in User Search", titles_default)
        self.assertNotIn("Resolved Insecure Deserialization", titles_default)

        # 2. Audit request with include_resolved=True: must include resolved
        resp_audit = self.client.get(f"/api/findings?project_id={self.project_id}&include_resolved=true", headers=self.headers)
        self.assertEqual(resp_audit.status_code, 200)
        items_audit = resp_audit.json()
        titles_audit = [f["title"] for f in items_audit]
        self.assertIn("SQL Injection in User Search", titles_audit)
        self.assertIn("Resolved Insecure Deserialization", titles_audit)

    def test_02_archive_resolved_findings_endpoint(self):
        """POST /api/findings/archive-resolved transfers resolved items to audit_logs and deletes from findings."""
        # Ensure a resolved finding exists
        findings = db.list_findings(self.project_id)
        resolved_finding = next((f for f in findings if f["status"] == "resolved"), None)
        self.assertIsNotNone(resolved_finding, "Expected at least one resolved finding")

        # Call archive endpoint
        resp = self.client.post(f"/api/findings/archive-resolved?project_id={self.project_id}", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertGreaterEqual(data["archived_count"], 1)

        # Verify finding was deleted from active findings
        post_findings = db.list_findings(self.project_id)
        post_resolved = [f for f in post_findings if f["status"] == "resolved"]
        self.assertEqual(len(post_resolved), 0, "Resolved findings must be purged from findings table")

        # Verify audit record was created in audit_logs
        audit_resp = self.client.get(f"/api/audit/logs?project_id={self.project_id}", headers=self.headers)
        self.assertEqual(audit_resp.status_code, 200)
        logs = audit_resp.json()
        matching_log = next((l for l in logs if l.get("finding_id") == resolved_finding["id"]), None)
        self.assertIsNotNone(matching_log, "Audit record must exist in immutable audit log")
        self.assertEqual(matching_log["event_type"], "VULNERABILITY_RESOLVED")
        self.assertTrue(len(matching_log["cryptographic_seal"]) >= 16)
        self.assertEqual(len(matching_log["event_hash"]), 64)
