"""
Unit and integration tests for AegisSec Benchmark and Tool Comparison Engine.
Verifies comparative metrics against Dependency-Check, SonarQube, and Semgrep.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db
from backend.benchmark.comparator import BenchmarkComparator


class TestBenchmarkEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(admin_user["id"], admin_user["username"], admin_user["role"])

    def test_01_comparator_data_structure(self):
        """Verify BenchmarkComparator returns structured comparison dataset."""
        report = BenchmarkComparator.get_benchmark_report()
        self.assertIn("tools", report)
        self.assertIn("comparison_matrix", report)
        self.assertIn("benchmarks", report)

        # Check all 4 target tools are present
        tools = report["tools"]
        self.assertIn("aegissec", tools)
        self.assertIn("semgrep", tools)
        self.assertIn("sonarqube", tools)
        self.assertIn("depcheck", tools)

        self.assertGreater(tools["aegissec"]["overall_score"], tools["semgrep"]["overall_score"])
        self.assertGreater(tools["semgrep"]["overall_score"], tools["sonarqube"]["overall_score"])
        self.assertGreater(tools["sonarqube"]["overall_score"], tools["depcheck"]["overall_score"])

    def test_02_comparison_matrix_categories(self):
        """Verify comparison matrix covers key evaluation dimensions."""
        report = BenchmarkComparator.get_benchmark_report()
        categories = [c["category"] for c in report["comparison_matrix"]]

        self.assertIn("Vulnerability Prioritization & Threat Intel", categories)
        self.assertIn("Multi-Industry Regulatory & Safety Standards", categories)
        self.assertIn("Custom Rule Studio & Extensibility", categories)
        self.assertIn("Developer Isolation & Git Blame Attribution", categories)
        self.assertIn("Contextual AI Remediation & Code Diffs", categories)
        self.assertIn("Unified SAST & SCA Architecture", categories)

    def test_03_benchmark_api_endpoint(self):
        """Verify GET /api/benchmark endpoint returns 200 with complete benchmark report."""
        resp = self.client.get("/api/benchmark", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["tools"]["aegissec"]["name"], "AegisSec")
        self.assertIn("alert_fatigue_reduction", data["benchmarks"])
        self.assertIn("rule_synthesis_latency", data["benchmarks"])


if __name__ == "__main__":
    unittest.main()
