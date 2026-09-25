"""
Test Suite v3 for Enterprise Additions:
1. AI Threat Modeling & Attack Surface Engine (STRIDE & DFD)
2. Automated Secret Rotation & Cloud Vault Integration
3. Container Image & Base OS Vulnerability Scanner
4. Policy-as-Code & Quality Gate Studio
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.db import db
from backend.scanners.threat_model_engine import ThreatModelEngine
from backend.integrations.vault_manager import VaultManager
from backend.scanners.container_os_scanner import ContainerOSScanner
from backend.ci.policy_studio import PolicyStudio


class TestEnterpriseSuiteV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        user = db.get_user_by_username("admin")
        if not user:
            user = db.create_user("admin", "admin@sentinel.io", "admin123", "admin")
        cls.admin_token = create_access_token(user["id"], user["username"], user["role"])
        cls.headers = {"Authorization": f"Bearer {cls.admin_token}"}

    def test_01_threat_model_engine_direct(self):
        """Test ThreatModelEngine STRIDE analysis and Data-Flow Diagram generation."""
        res = ThreatModelEngine.analyze_repository(".", findings=[])
        self.assertIn("stride_summary", res)
        self.assertIn("threats", res)
        self.assertIn("data_flow_diagram", res)
        self.assertGreater(len(res["threats"]), 0)
        # Verify STRIDE categories are present
        stride_codes = {t["stride_code"] for t in res["threats"]}
        self.assertTrue({"S", "T", "R", "I", "D", "E"}.issubset(stride_codes))
        # Verify DFD structure
        dfd = res["data_flow_diagram"]
        self.assertIn("nodes", dfd)
        self.assertIn("edges", dfd)

    def test_02_threat_model_endpoints(self):
        """Test GET /api/threat-model and POST /api/threat-model/generate."""
        r1 = self.client.get("/api/threat-model", headers=self.headers)
        self.assertEqual(r1.status_code, 200)
        data1 = r1.json()
        self.assertIn("stride_summary", data1)

        r2 = self.client.post("/api/threat-model/generate", json={}, headers=self.headers)
        self.assertEqual(r2.status_code, 200)
        data2 = r2.json()
        self.assertIn("threats", data2)

    def test_03_vault_manager_direct(self):
        """Test VaultManager secret rotation workflow and code diff synthesis."""
        status = VaultManager.get_status()
        self.assertIn("active_provider", status)
        self.assertIn("providers", status)

        fake_finding = {
            "id": "find-secret-999",
            "title": "AWS Secret Access Key Leaked",
            "file_path": "config/settings.py",
            "code_snippet": 'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"'
        }
        rot_res = VaultManager.rotate_secret(fake_finding, provider="hashicorp_vault")
        self.assertTrue(rot_res["success"])
        self.assertIn("vault_uri", rot_res["rotation"])
        self.assertIn("secure_code_diff", rot_res)
        self.assertIn("os.getenv", rot_res["retrieval_code"])

    def test_04_vault_endpoints(self):
        """Test GET /api/vault/status and POST /api/vault/rotate."""
        r1 = self.client.get("/api/vault/status", headers=self.headers)
        self.assertEqual(r1.status_code, 200)
        self.assertIn("providers", r1.json())

        # Test rotation endpoint
        projects = db.list_projects()
        proj_id = projects[0]["id"] if projects else "demo"
        findings = db.list_findings(proj_id)
        if not findings:
            # Insert a temporary finding to test rotation
            findings = [{
                "id": "test-finding-for-vault",
                "project_id": proj_id,
                "title": "Stripe Secret Key Leaked",
                "file_path": "billing.py",
                "code_snippet": 'STRIPE_SECRET = "sk_live_1234567890"',
                "severity": "CRITICAL",
                "type": "secrets"
            }]
            db.create_finding(findings[0])

        r2 = self.client.post("/api/vault/rotate", json={
            "finding_id": findings[0]["id"],
            "provider": "hashicorp_vault"
        }, headers=self.headers)
        self.assertEqual(r2.status_code, 200)
        rot_data = r2.json()
        self.assertTrue(rot_data["success"])

    def test_05_container_os_scanner_direct(self):
        """Test ContainerOSScanner Dockerfile and base OS CVE analysis."""
        dockerfile = (
            "FROM alpine:3.14\n"
            "RUN apk add --no-cache curl openssl zlib\n"
            "USER root\n"
            "CMD [\"curl\", \"--help\"]\n"
        )
        res = ContainerOSScanner.scan_dockerfile_content(dockerfile)
        self.assertIn("layer_findings", res)
        self.assertIn("os_package_cves", res)
        self.assertGreater(res["total_vulnerabilities"], 0)
        self.assertFalse(res["non_root_enforced"])

    def test_06_container_os_scanner_endpoints(self):
        """Test GET /api/container-scan/cves and POST /api/container-scan/analyze."""
        r1 = self.client.get("/api/container-scan/cves", headers=self.headers)
        self.assertEqual(r1.status_code, 200)
        cves = r1.json()
        self.assertIsInstance(cves, list)
        self.assertGreater(len(cves), 0)

        r2 = self.client.post("/api/container-scan/analyze", json={
            "dockerfile_content": "FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y curl\nUSER 10001\n"
        }, headers=self.headers)
        self.assertEqual(r2.status_code, 200)
        data = r2.json()
        self.assertTrue(data["non_root_enforced"])
        self.assertIn("layer_findings", data)

    def test_07_policy_studio_direct(self):
        """Test PolicyStudio evaluation and simulation dry-run."""
        policy = PolicyStudio.get_policy()
        self.assertIn("rules", policy)

        # Test passing metrics
        clean_metrics = {
            "critical_count": 0,
            "high_count": 1,
            "cisa_kev_count": 0,
            "secrets_count": 0,
            "max_epss_score": 0.05
        }
        res_clean = PolicyStudio.simulate_metrics(clean_metrics, policy)
        self.assertEqual(res_clean["verdict"], "PASSED")
        self.assertTrue(res_clean["can_merge"])

        # Test failing metrics
        failing_metrics = {
            "critical_count": 3,
            "high_count": 5,
            "cisa_kev_count": 1,
            "secrets_count": 2,
            "max_epss_score": 0.85
        }
        res_fail = PolicyStudio.simulate_metrics(failing_metrics, policy)
        self.assertEqual(res_fail["verdict"], "BLOCKED")
        self.assertFalse(res_fail["can_merge"])

    def test_08_policy_studio_endpoints(self):
        """Test GET /api/policy-studio/rules and POST /api/policy-studio/dry-run."""
        r1 = self.client.get("/api/policy-studio/rules", headers=self.headers)
        self.assertEqual(r1.status_code, 200)
        self.assertIn("rules", r1.json())

        r2 = self.client.post("/api/policy-studio/dry-run", json={
            "metrics": {
                "critical_count": 0,
                "high_count": 0,
                "cisa_kev_count": 0,
                "secrets_count": 0,
                "max_epss_score": 0.01
            }
        }, headers=self.headers)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.json()["verdict"], "PASSED")


if __name__ == "__main__":
    unittest.main()
