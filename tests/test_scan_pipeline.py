"""
Unit and integration tests for DevSecOps Status Pipeline upon full scan completion.
Validates 8-stage pipeline telemetry, quality gate evaluation, audit seal, and REST endpoints.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app, _build_pipeline_from_scan
from backend.auth import create_access_token
from backend.db import db


class TestScanPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(admin_user["id"], admin_user["username"], admin_user["role"])
        cls.headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Create or fetch a test project for pipeline tests
        projects = db.list_projects()
        if projects:
            cls.project_id = projects[0]["id"]
        else:
            cls.project_id = db.create_project(
                name="Pipeline Test Repository",
                repo_url="https://github.com/acme/pipeline-test",
                branch="main"
            )

    def test_01_trigger_scan_returns_status_pipeline(self):
        """Verify that triggering a scan returns the complete 8-stage DevSecOps pipeline."""
        resp = self.client.post(
            f"/api/projects/{self.project_id}/scan?scan_type=full",
            headers=self.headers
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertIn("pipeline", data)

        pipe = data["pipeline"]
        self.assertTrue(pipe["pipeline_id"].startswith("PIPE-"))
        self.assertEqual(pipe["project_id"], self.project_id)
        self.assertIn(pipe["status"], ["PASSED", "WARNING", "FAILED"])
        self.assertIn(pipe["verdict"], ["PASSED", "BLOCKED"])
        self.assertIn("audit_seal", pipe)
        self.assertTrue(len(pipe["audit_seal"]) >= 32)
        self.assertIn("duration_display", pipe)
        self.assertIn("quality_gate", pipe)
        self.assertIn("metrics", pipe)

        # Verify 8 stages
        stages = pipe["stages"]
        self.assertEqual(len(stages), 8)
        stage_ids = [s["id"] for s in stages]
        expected_ids = ["ingestion", "sast", "sca", "secrets", "iac", "api", "ai_triage", "quality_gate"]
        self.assertEqual(stage_ids, expected_ids)

        for s in stages:
            self.assertIn("step", s)
            self.assertIn("name", s)
            self.assertIn("status", s)
            self.assertIn("duration_ms", s)
            self.assertIn("findings_count", s)
            self.assertIn("description", s)

    def test_02_get_scan_pipeline_endpoint(self):
        """Verify GET /api/scans/{scan_id}/pipeline retrieves the persisted pipeline."""
        # Find latest scan for this project
        scans = db.list_scans(self.project_id)
        self.assertGreater(len(scans), 0)
        latest_scan = scans[0]
        scan_id = latest_scan["id"]

        resp = self.client.get(f"/api/scans/{scan_id}/pipeline", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertIn("pipeline", data)
        self.assertEqual(data["pipeline"]["scan_id"], scan_id)
        self.assertEqual(len(data["pipeline"]["stages"]), 8)

    def test_03_get_project_latest_pipeline_endpoint(self):
        """Verify GET /api/projects/{project_id}/pipeline-latest returns the active project's most recent pipeline."""
        resp = self.client.get(f"/api/projects/{self.project_id}/pipeline-latest", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success"))
        self.assertIn("pipeline", data)
        self.assertEqual(data["pipeline"]["project_id"], self.project_id)
        self.assertEqual(len(data["pipeline"]["stages"]), 8)

    def test_04_fallback_pipeline_generator(self):
        """Verify fallback generator creates valid 8-stage pipeline for legacy scan rows."""
        mock_scan = {
            "id": "scan-mock-legacy-1234",
            "project_id": "proj-legacy",
            "project_name": "Legacy Repo",
            "critical_count": 0,
            "high_count": 2,
            "medium_count": 1,
            "low_count": 0,
            "total_findings": 3
        }
        pipe = _build_pipeline_from_scan(mock_scan)
        self.assertEqual(pipe["scan_id"], "scan-mock-legacy-1234")
        self.assertEqual(pipe["status"], "WARNING")
        self.assertEqual(len(pipe["stages"]), 8)
        self.assertTrue(len(pipe["audit_seal"]) >= 32)

    def test_05_nonexistent_scan_pipeline_returns_404(self):
        """Verify 404 is returned for non-existent scan ID."""
        resp = self.client.get("/api/scans/non-existent-scan-id-9999/pipeline", headers=self.headers)
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
