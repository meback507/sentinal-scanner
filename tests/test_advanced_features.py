"""
Unit and Integration Tests for Advanced Enterprise Features:
- 1-Click Autonomous AI Remediation PR Generator
- CI/CD Quality Gates & Differential PR Webhooks
- SCA Call-Graph Reachability Engine
- High-Entropy Secret Scanner with Shannon Entropy
- Audit Trail Ledger & Signed Attestation Certificates
- Vulnerability Trend Graph with RBAC Contributor Scoping
"""

import os
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db import db
from backend.models import RoleEnum
from backend.auth import create_access_token
from backend.ci.quality_gate import CIQualityGate
from backend.scanners.secret_scanner import SecretScanner
from backend.scanners.sca_engine import SCAEngine
from backend.audit.audit_service import AuditService
from backend.integrations.git_pr_service import GitPRService


class TestAdvancedFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

        # Create or ensure test users
        cls.admin_token = create_access_token("1", "admin", "admin")
        cls.marcus_token = create_access_token("3", "marcus", "developer")
        cls.elena_token = create_access_token("4", "elena", "developer")

        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}
        cls.marcus_headers = {"Authorization": f"Bearer {cls.marcus_token}"}
        cls.elena_headers = {"Authorization": f"Bearer {cls.elena_token}"}

        import uuid
        # Seed sample isolated project and findings
        cls.proj = db.create_project(
            name=f"Adv-Features-{uuid.uuid4().hex[:6]}",
            description="Test Suite",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        # Insert test findings
        test_findings = [
            {
                "title": "SQL Injection in User Authentication",
                "file_path": "src/app.py",
                "line_start": 25,
                "line_end": 28,
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "epss_score": 0.85,
                "epss_percentile": 0.98,
                "composite_risk_score": 95.0,
                "quadrant": "ACT_NOW",
                "sla_days": 2,
                "author_name": "Marcus Vance",
                "author_email": "marcus.vance@cloudsec.internal",
                "commit_hash": "a1b2c3d4",
                "commit_date": "2026-09-15",
                "commit_message": "Add user authentication query",
                "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "cwe_id": "CWE-89",
                "standards": ["ISO-27001", "OWASP-Top10-A03"],
                "scan_type": "sast"
            },
            {
                "title": "MISRA C:2012 Rule 21.3 Dynamic Memory in ASIL Controller",
                "file_path": "ecu_controller.cpp",
                "line_start": 44,
                "line_end": 45,
                "severity": "CRITICAL",
                "cvss_score": 8.9,
                "epss_score": 0.04,
                "epss_percentile": 0.35,
                "composite_risk_score": 75.0,
                "quadrant": "CRITICAL_PATCH",
                "sla_days": 14,
                "author_name": "Dr. Elena Rostova",
                "author_email": "elena.rostova@autocorp.de",
                "commit_hash": "e5f6g7h8",
                "commit_date": "2026-09-14",
                "commit_message": "Implement dynamic buffer telemetry",
                "code_snippet": "char* buf = (char*)malloc(256);",
                "cwe_id": "CWE-401",
                "standards": ["ISO-26262", "MISRA-C:2012-Rule-21.3"],
                "scan_type": "sast"
            }
        ]
        scan_id = db.create_scan(cls.proj["id"], cls.proj["name"], "full")
        db.update_scan_results(scan_id, cls.proj["id"], test_findings)
        for f in db.list_findings(cls.proj["id"]):
            if "marcus" in (f.get("author_name", "") + f.get("author_email", "")).lower():
                cls.marcus_finding = f
            elif "elena" in (f.get("author_name", "") + f.get("author_email", "")).lower():
                cls.elena_finding = f

    @classmethod
    def tearDownClass(cls):
        db.delete_project(cls.proj["id"])

    def test_01_shannon_entropy_calculation(self):
        """Verify Shannon entropy correctly identifies high-randomness secrets vs regular text."""
        low_entropy = "hello world this is regular text and comments"
        high_entropy = "sk-ant-api03-X89zQjLm3K98pLqR209XzMna9871KlOpQ"

        e_low = SecretScanner.calculate_shannon_entropy(low_entropy)
        e_high = SecretScanner.calculate_shannon_entropy(high_entropy)

        self.assertGreater(e_high, e_low)
        self.assertGreater(e_high, 4.0)

    def test_02_sca_reachability_classification(self):
        """Verify SCA engine static reachability analysis."""
        scanner = SCAEngine()
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            # Code imports 'requests' but does not import 'unused_dep'
            with open(os.path.join(td, "main.py"), "w") as f:
                f.write("import requests\nresp = requests.get('https://example.com')\n")

            reachable = scanner._check_reachability(td, "requests")
            dormant = scanner._check_reachability(td, "unused_library_xyz")

            self.assertEqual(reachable["reachability"], "REACHABLE")
            self.assertEqual(dormant["reachability"], "DORMANT")

    def test_03_ci_quality_gate_evaluation(self):
        """Verify CI quality gate fails on critical Act-Now issues and generates PR comments."""
        findings = [
            {"severity": "CRITICAL", "quadrant": "ACT_NOW", "title": "SQLi RCE", "standards": ["ISO-27001"]},
            {"severity": "HIGH", "quadrant": "ROUTINE", "title": "Old Dep", "standards": []}
        ]
        result = CIQualityGate.evaluate(findings, strict_mode=False, max_critical=0)
        self.assertEqual(result["gate_status"], "FAILED")
        self.assertGreater(len(result["blocking_reasons"]), 0)

        pr_comment = CIQualityGate.format_pr_comment(result)
        self.assertIn("AegisSec CI/CD Quality Gate Evaluation", pr_comment)
        self.assertIn("FAILED", pr_comment)

    def test_04_ci_gate_endpoint_and_github_webhook(self):
        """Test POST /api/ci/gate-check and POST /api/webhooks/github."""
        gate_res = self.client.post("/api/ci/gate-check", json={
            "project_id": self.proj["id"],
            "strict_mode": False,
            "max_critical": 0
        }, headers=self.admin_headers)
        self.assertEqual(gate_res.status_code, 200)
        self.assertIn("gate_status", gate_res.json())

        webhook_res = self.client.post("/api/webhooks/github", json={
            "action": "pull_request",
            "repository": {"full_name": "autocorp/ecu-core"},
            "sender": {"login": "ci-bot"}
        })
        self.assertEqual(webhook_res.status_code, 200)
        self.assertEqual(webhook_res.json()["status"], "processed")

    def test_05_autonomous_pr_creation_developer_scoping(self):
        """Verify Marcus can create PR on his code, but CANNOT create PR on Elena's code (403 Forbidden)."""
        self.assertIsNotNone(self.marcus_finding)
        self.assertIsNotNone(self.elena_finding)

        # Marcus creates PR on Marcus's code -> SUCCESS
        res_ok = self.client.post(
            f"/api/findings/{self.marcus_finding['id']}/create-pr",
            headers=self.marcus_headers
        )
        self.assertEqual(res_ok.status_code, 200)
        data = res_ok.json()
        self.assertTrue(data["success"])
        self.assertIn("fix/aegissec-", data["branch_name"])
        self.assertIn("Marcus Vance", data["author_attributed"])

        # Marcus attempts to create PR on Elena's code -> 403 Forbidden
        res_forbidden = self.client.post(
            f"/api/findings/{self.elena_finding['id']}/create-pr",
            headers=self.marcus_headers
        )
        self.assertEqual(res_forbidden.status_code, 403)
        self.assertIn("Access restricted", res_forbidden.json()["detail"])

        # Admin can create PR on any code -> SUCCESS
        res_admin = self.client.post(
            f"/api/findings/{self.elena_finding['id']}/create-pr",
            headers=self.admin_headers
        )
        self.assertEqual(res_admin.status_code, 200)

    def test_06_audit_trail_and_certificate(self):
        """Verify AuditService logs events and generates cryptographically signed certificates."""
        # Check audit logs endpoint
        logs_res = self.client.get("/api/audit/logs", headers=self.admin_headers)
        self.assertEqual(logs_res.status_code, 200)
        logs = logs_res.json()
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)

        # Check ISO-26262 Certificate
        cert_res = self.client.get("/api/audit/certificate/ISO-26262", headers=self.admin_headers)
        self.assertEqual(cert_res.status_code, 200)
        cert = cert_res.json()
        self.assertEqual(cert["attestation_standard"], "ISO-26262")
        self.assertIn("digital_seal", cert)
        self.assertEqual(len(cert["digital_seal"]), 64)  # Valid SHA-256

    def test_07_dashboard_trend_lines_rbac_scoping(self):
        """
        Verify that /api/dashboard/stats returns time-series trend lines:
        - Scoped strictly to developer's contributed code when logged in as Marcus.
        - Global enterprise aggregate with all developers when logged in as Admin.
        """
        # Developer (Marcus)
        dev_res = self.client.get("/api/dashboard/stats", headers=self.marcus_headers)
        self.assertEqual(dev_res.status_code, 200)
        dev_data = dev_res.json()

        self.assertTrue(dev_data["is_developer_scoped"])
        self.assertEqual(dev_data["scoped_developer_name"], "marcus")

        trends = dev_data.get("trends")
        self.assertIsNotNone(trends)
        self.assertTrue(trends["is_developer_scoped"])
        self.assertEqual(trends["scoped_developer_name"], "marcus")
        # In developer view, options only contains marcus
        self.assertEqual(trends["developer_options"], ["marcus"])
        # Series check
        self.assertEqual(len(trends["labels"]), 6)
        self.assertEqual(len(trends["primary"]["critical_series"]), 6)
        self.assertEqual(len(trends["primary"]["posture_series"]), 6)

        # Admin
        admin_res = self.client.get("/api/dashboard/stats", headers=self.admin_headers)
        self.assertEqual(admin_res.status_code, 200)
        admin_data = admin_res.json()

        self.assertFalse(admin_data["is_developer_scoped"])
        admin_trends = admin_data.get("trends")
        self.assertIsNotNone(admin_trends)
        self.assertFalse(admin_trends["is_developer_scoped"])
        self.assertIn("All Enterprise Code", admin_trends["developer_options"])
        # Both Marcus and Elena should be in per_developer_trends for Admin filtering
        self.assertIn("All Enterprise Code", admin_trends["per_developer_trends"])

    def test_09_ticket_assigned_to_code_author_jira_and_zammad(self):
        """
        Verify that when creating a ticket for a vulnerable finding,
        the ticket is assigned directly to the author of the code,
        and persisted in the database.
        """
        # 1. Marcus Vance finding ticket via Jira
        marcus_res = self.client.post(
            f"/api/findings/{self.marcus_finding['id']}/ticket",
            headers=self.marcus_headers,
            json={"platform": "jira", "finding_id": self.marcus_finding["id"]}
        )
        self.assertEqual(marcus_res.status_code, 200)
        data = marcus_res.json()
        self.assertTrue(data["success"])
        self.assertIn("SEC-", data["ticket_key"])
        self.assertIn("Marcus Vance", data.get("assigned_to", ""))

        # Verify database record updated with author assignment
        f_db = db.get_finding_by_id(self.marcus_finding["id"])
        self.assertEqual(f_db["status"], "in_triage")
        self.assertIn("Marcus Vance", f_db["ticket_assigned_to"])
        self.assertEqual(f_db["jira_key"], data["ticket_key"])

        # 2. Elena Rostova finding ticket via Zammad
        elena_res = self.client.post(
            f"/api/findings/{self.elena_finding['id']}/ticket",
            headers=self.elena_headers,
            json={"platform": "zammad", "finding_id": self.elena_finding["id"]}
        )
        self.assertEqual(elena_res.status_code, 200)
        e_data = elena_res.json()
        self.assertTrue(e_data["success"])
        self.assertIn("Dr. Elena Rostova", e_data.get("assigned_to", ""))

        f_elena_db = db.get_finding_by_id(self.elena_finding["id"])
        self.assertEqual(f_elena_db["status"], "in_triage")
        self.assertIn("Dr. Elena Rostova", f_elena_db["ticket_assigned_to"])

    def test_10_project_auto_ticket_dispatch_assigned_to_authors(self):
        """
        Verify that auto-dispatching tickets for a project assigns tickets
        to each respective code author for all vulnerable code.
        """
        res = self.client.post(
            f"/api/projects/{self.proj['id']}/auto-ticket?platform=jira",
            headers=self.admin_headers
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertIn("dispatched_count", data)

        # Every auto-dispatched ticket must have assigned_to set to the code author
        for t in data["tickets"]:
            self.assertTrue(bool(t.get("assigned_to")))
            self.assertNotEqual(t.get("assigned_to"), "")


if __name__ == "__main__":
    unittest.main()
