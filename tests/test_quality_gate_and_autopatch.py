"""
Tests for Quality Gate Evaluation, Live SVG Security Badges, 
Auditor Evidence ZIP Bundles, and 1-Click Code Patching.
"""

import unittest
import zipfile
import io
import json
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db


class TestQualityGateAndAutoPatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_user = db.get_user_by_username("admin") or {"id": "u-admin", "username": "admin", "role": "admin"}
        cls.dev_user = db.get_user_by_username("developer") or {"id": "u-dev", "username": "developer", "role": "developer"}
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])
        cls.dev_token = create_access_token(cls.dev_user["id"], cls.dev_user["username"], cls.dev_user["role"])

        # Retrieve a valid project
        projects = db.list_projects()
        if not projects:
            cls.project = db.create_project(
                name="Test-Quality-Gate-Suite",
                description="Testing quality gates and evidence bundles",
                git_url="https://github.com/test/repo.git",
                git_branch="main",
                git_pat="",
                created_by="admin"
            )
        else:
            cls.project = projects[0]
        cls.project_id = cls.project["id"]

    def test_01_quality_gate_endpoint(self):
        """Verify GET /api/projects/{id}/quality-gate returns structured Quality Gate results."""
        resp = self.client.get(
            f"/api/projects/{self.project_id}/quality-gate",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("status", data)
        self.assertIn("passed", data)
        self.assertIn("criteria", data)
        self.assertIn("metrics", data)
        self.assertEqual(data["project_id"], self.project_id)
        self.assertIn(data["status"], ["PASSED", "FAILED"])

        # Test strict mode
        resp_strict = self.client.get(
            f"/api/projects/{self.project_id}/quality-gate?strict=true",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp_strict.status_code, 200)
        data_strict = resp_strict.json()
        self.assertEqual(data_strict["criteria"]["max_high_allowed"], 0)

    def test_02_project_security_badge_svg(self):
        """Verify GET /api/projects/{id}/badge.svg returns a valid public SVG badge."""
        resp = self.client.get(f"/api/projects/{self.project_id}/badge.svg")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("image/svg+xml", resp.headers.get("content-type", ""))
        self.assertIn("<svg", resp.text)
        self.assertIn("security", resp.text)
        self.assertIn("</svg>", resp.text)

        # Test with custom label
        resp_custom = self.client.get(f"/api/projects/{self.project_id}/badge.svg?label=sentinel-gate")
        self.assertEqual(resp_custom.status_code, 200)
        self.assertIn("sentinel-gate", resp_custom.text)

    def test_03_auditor_evidence_bundle_zip(self):
        """Verify GET /api/projects/{id}/export/audit-bundle generates an integrity-signed ZIP package."""
        resp = self.client.get(
            f"/api/projects/{self.project_id}/export/audit-bundle",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("content-type"), "application/zip")
        self.assertIn(".zip", resp.headers.get("content-disposition", ""))

        # Verify ZIP archive layout & manifest
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        names = zf.namelist()
        self.assertIn("reports/executive-audit-report.html", names)
        self.assertIn("security/sarif-v2.1.0.json", names)
        self.assertIn("supply-chain/cyclonedx-sbom.json", names)
        self.assertIn("supply-chain/vex-exploitability.json", names)
        self.assertIn("sonarqube/sonar-issues.json", names)
        self.assertIn("attestations/ISO-26262-Safety-Attestation.json", names)
        self.assertIn("attestations/ISO-27001-Secure-Coding-Attestation.json", names)
        self.assertIn("audit-trail/immutable_logs.csv", names)
        self.assertIn("MANIFEST-CHECKSUMS.sha256", names)

        # Verify checksums manifest content
        manifest_data = zf.read("MANIFEST-CHECKSUMS.sha256").decode("utf-8")
        self.assertIn("Manifest", manifest_data)
        self.assertIn("sarif-v2.1.0.json", manifest_data)

    def test_04_apply_finding_patch_and_resolution(self):
        """Verify POST /api/findings/{id}/apply-patch updates finding status and records audit event."""
        findings = db.list_findings(self.project_id)
        if not findings:
            self.skipTest("No findings available to test patch application")

        target_finding = findings[0]
        finding_id = target_finding["id"]

        resp = self.client.post(
            f"/api/findings/{finding_id}/apply-patch",
            json={"patch_code": "# Safe Parameterized Implementation"},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "resolved")

        # Verify in DB
        updated = db.get_finding_by_id(finding_id)
        self.assertEqual(updated["status"], "resolved")

        # Verify audit log entry
        with db._get_conn() as conn:
            audit_logs = conn.execute(
                "SELECT * FROM audit_logs WHERE finding_id = ? AND event_type = 'CODE_PATCH_APPLIED'",
                (finding_id,)
            ).fetchall()
            self.assertGreaterEqual(len(audit_logs), 1)


if __name__ == "__main__":
    unittest.main()
