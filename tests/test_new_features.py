"""
Unit and Integration Tests for Next-Gen AppSec Feature Suite:
1. CISA KEV Threat Intelligence
2. AI-Assisted Confidence & False Positive Evaluation
3. Infrastructure as Code (IaC) & Container Hardening Scanner
4. OpenAPI & Swagger Security Engine (OWASP API Top 10)
5. OpenVEX v0.2.0 Governance Exporter
6. Sentinel CLI & Pre-Commit Shield
"""

import unittest
import os
import json
import tempfile
import shutil
from fastapi.testclient import TestClient

from backend.main import app
from backend.db import db
from backend.auth import create_access_token
from backend.prioritization.cisa_service import cisa_service
from backend.scanners.iac_engine import IaCEngine
from backend.scanners.api_sec_engine import APISecEngine
from backend.scanners.sca_engine import SCAEngine
from backend.integrations.llm_service import LLMService
from backend.exporters.report_generator import ReportGenerator
from scripts.sentinel_cli import run_scan


class TestNewAppSecFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])

        # Create dedicated isolated test project
        cls.test_proj = db.create_project(
            name="Test-New-Features-Sandbox",
            description="Sandbox project for feature suite testing",
            git_url="",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        cls.project_id = cls.test_proj["id"]

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "project_id"):
            db.delete_project(cls.project_id)

    # --- 1. CISA KEV Catalog Tests ---
    def test_01_cisa_kev_known_vulnerability_lookup(self):
        """Verify CISA KEV catalog identifies weaponized CVEs and returns due dates."""
        is_kev, due_date, name = cisa_service.check_cisa_kev("CVE-2022-22965")
        self.assertTrue(is_kev)
        self.assertIsNotNone(due_date)
        self.assertIn("Spring", name)

        is_kev_log4j, due_date_log4j, name_log4j = cisa_service.check_cisa_kev("CVE-2021-44228")
        self.assertTrue(is_kev_log4j)
        self.assertIn("Log4j", name_log4j)

        is_kev_fake, _, _ = cisa_service.check_cisa_kev("CVE-2099-99999")
        self.assertFalse(is_kev_fake)

    def test_02_cisa_kev_finding_enrichment(self):
        """Verify findings matching CISA KEV are escalated to ACT_NOW with tight SLAs."""
        mock_finding = {
            "cve_id": "CVE-2022-22965",
            "title": "Spring4Shell RCE",
            "quadrant": "ROUTINE",
            "urgency": "LOW",
            "sla_days": 90,
            "standards": ["OWASP:A06:2021"]
        }
        enriched = cisa_service.enrich_finding_with_cisa_kev(mock_finding)
        self.assertTrue(enriched["cisa_kev"])
        self.assertEqual(enriched["quadrant"], "ACT_NOW")
        self.assertEqual(enriched["urgency"], "IMMEDIATE")
        self.assertEqual(enriched["sla_days"], 2)
        self.assertIn("CISA:KEV", enriched["standards"])

    # --- 2. IaC & Container Security Scanner Tests ---
    def test_03_iac_dockerfile_scanning(self):
        """Verify IaC scanner identifies root process and unpinned images in Dockerfiles."""
        temp_dir = tempfile.mkdtemp()
        try:
            dockerfile_content = """FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
RUN curl -s http://example.com/install.sh | bash
EXPOSE 22
CMD ["app"]
"""
            with open(os.path.join(temp_dir, "Dockerfile"), "w") as f:
                f.write(dockerfile_content)

            iac = IaCEngine()
            findings = iac.scan_directory(temp_dir)
            rule_ids = [f["title"] for f in findings]

            # Should catch running as root (IAC-DOCKER-001)
            self.assertTrue(any("IAC-DOCKER-001" in t for t in rule_ids))
            # Should catch curl | bash (IAC-DOCKER-002)
            self.assertTrue(any("IAC-DOCKER-002" in t for t in rule_ids))
            # Should catch unpinned :latest tag (IAC-DOCKER-003)
            self.assertTrue(any("IAC-DOCKER-003" in t for t in rule_ids))
            # Should catch exposed SSH port 22 (IAC-DOCKER-004)
            self.assertTrue(any("IAC-DOCKER-004" in t for t in rule_ids))
        finally:
            shutil.rmtree(temp_dir)

    def test_04_iac_terraform_and_k8s_scanning(self):
        """Verify IaC scanner detects public S3 bucket and privileged K8s pods."""
        temp_dir = tempfile.mkdtemp()
        try:
            tf_content = """resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"
  acl    = "public-read"
}
resource "aws_db_instance" "default" {
  allocated_storage = 10
  storage_encrypted = false
}
"""
            with open(os.path.join(temp_dir, "main.tf"), "w") as f:
                f.write(tf_content)

            k8s_content = """apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: sec-ctx-demo
    image: gcr.io/google-samples/node-hello:1.0
    securityContext:
      privileged: true
"""
            with open(os.path.join(temp_dir, "k8s-pod.yaml"), "w") as f:
                f.write(k8s_content)

            iac = IaCEngine()
            findings = iac.scan_directory(temp_dir)
            rule_ids = [f["title"] for f in findings]

            self.assertTrue(any("IAC-TF-001" in t for t in rule_ids))
            self.assertTrue(any("IAC-TF-003" in t for t in rule_ids))
            self.assertTrue(any("IAC-K8S-001" in t for t in rule_ids))
        finally:
            shutil.rmtree(temp_dir)

    # --- 3. OpenAPI / Swagger API Security Scanner Tests ---
    def test_05_api_security_scanner(self):
        """Verify OpenAPI scanner flags BOLA, broken auth on admin routes, and missing pagination."""
        temp_dir = tempfile.mkdtemp()
        try:
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Test API", "version": "1.0.0"},
                "servers": [{"url": "http://api.insecure.internal"}],
                "paths": {
                    "/users/{id}": {
                        "get": {
                            "summary": "Get user by ID",
                            "parameters": [{"name": "id", "in": "path", "required": True}],
                            "responses": {"200": {"description": "OK"}}
                            # Missing security -> BOLA
                        }
                    },
                    "/admin/system-reset": {
                        "post": {
                            "summary": "Admin reset",
                            "security": [],  # Explicitly unauthenticated admin endpoint
                            "responses": {"200": {"description": "OK"}}
                        }
                    },
                    "/orders": {
                        "get": {
                            "summary": "List all orders",
                            "parameters": [],  # Missing pagination
                            "responses": {"200": {"description": "OK"}}
                        },
                        "post": {
                            "summary": "Create order",
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "item": {"type": "string"},
                                                "is_admin": {"type": "boolean"},  # Mass assignment
                                                "role": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            },
                            "responses": {"201": {"description": "Created"}}
                        }
                    }
                }
            }
            with open(os.path.join(temp_dir, "openapi.json"), "w") as f:
                json.dump(spec, f)

            scanner = APISecEngine()
            findings = scanner.scan_directory(temp_dir)
            rule_ids = [f["title"] for f in findings]

            self.assertTrue(any("API-TRANS-001" in t for t in rule_ids))
            self.assertTrue(any("API-BOLA-001" in t for t in rule_ids))
            self.assertTrue(any("API-AUTH-001" in t for t in rule_ids))
            self.assertTrue(any("API-MASS-001" in t for t in rule_ids))
            self.assertTrue(any("API-DOS-001" in t for t in rule_ids))
        finally:
            shutil.rmtree(temp_dir)

    # --- 4. OpenVEX Exporter Tests ---
    def test_06_openvex_export(self):
        """Verify OpenVEX document adheres to OpenVEX v0.2.0 specification."""
        mock_findings = [
            {
                "id": "vuln-1",
                "cve_id": "CVE-2022-22965",
                "package_name": "spring-boot",
                "installed_version": "2.5.6",
                "fixed_version": "2.6.6",
                "title": "Spring4Shell RCE",
                "status": "in_triage",
                "reachability_status": "REACHABLE",
                "cisa_kev": True
            },
            {
                "id": "vuln-2",
                "cve_id": "CVE-2021-23337",
                "package_name": "lodash",
                "installed_version": "4.17.15",
                "fixed_version": "4.17.21",
                "title": "Lodash Prototype Pollution",
                "status": "false_positive",
                "reachability_status": "DORMANT"
            }
        ]

        vex_str = ReportGenerator.generate_openvex({"id": self.project_id, "name": "DemoApp"}, mock_findings)
        vex_doc = json.loads(vex_str)

        self.assertEqual(vex_doc["@context"], "https://openvex.dev/ns/v0.2.0")
        self.assertIn("statements", vex_doc)
        self.assertEqual(len(vex_doc["statements"]), 2)

        # Reachable / CISA finding -> affected
        st1 = vex_doc["statements"][0]
        self.assertEqual(st1["status"], "affected")
        self.assertIn("CVE-2022-22965", st1["vulnerability"]["name"])

        # Dormant finding -> not_affected with justification
        st2 = vex_doc["statements"][1]
        self.assertEqual(st2["status"], "not_affected")
        self.assertEqual(st2["justification"], "vulnerable_code_not_in_execute_path")

    # --- 5. AI-Assisted Confidence & False Positive Evaluation Tests ---
    def test_07_ai_confidence_scoring(self):
        """Verify AI confidence engine accurately detects true positives vs benign test fixtures."""
        kev_finding = {
            "title": "Spring4Shell RCE",
            "cve_id": "CVE-2022-22965",
            "cisa_kev": True,
            "file_path": "pom.xml"
        }
        res_kev = LLMService.evaluate_finding_confidence(kev_finding)
        self.assertGreaterEqual(res_kev["confidence_score"], 0.95)
        self.assertFalse(res_kev["is_false_positive_candidate"])

        test_finding = {
            "title": "Hardcoded API Key",
            "cwe_id": "CWE-798",
            "file_path": "tests/fixtures/mock_credentials.py",
            "code_snippet": "api_key = 'test-token-1234567890'"
        }
        res_test = LLMService.evaluate_finding_confidence(test_finding)
        self.assertLess(res_test["confidence_score"], 0.50)
        self.assertTrue(res_test["is_false_positive_candidate"])

    # --- 6. API Endpoints Tests ---
    def test_08_api_openvex_and_confidence_endpoints(self):
        """Verify /api/projects/{id}/export/vex and /api/findings/{id}/evaluate-confidence endpoints."""
        # 1. Test OpenVEX export endpoint
        res_vex = self.client.get(
            f"/api/projects/{self.project_id}/export/vex",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_vex.status_code, 200)
        self.assertEqual(res_vex.headers["content-type"], "application/vnd.openvex+json")
        vex_json = res_vex.json()
        self.assertEqual(vex_json["@context"], "https://openvex.dev/ns/v0.2.0")

        # 2. Test Evaluate Confidence on an existing finding
        findings = db.list_findings()
        if findings:
            target_f = findings[0]
            res_conf = self.client.post(
                f"/api/findings/{target_f['id']}/evaluate-confidence",
                headers={"Authorization": f"Bearer {self.admin_token}"}
            )
            self.assertEqual(res_conf.status_code, 200)
            data = res_conf.json()
            self.assertIn("confidence_score", data)
            self.assertIn("confidence_label", data)
            self.assertIn("rationale", data)

    # --- 7. Sentinel CLI Tests ---
    def test_09_sentinel_cli_runner(self):
        """Verify Sentinel CLI executes local security scans cleanly without errors."""
        temp_dir = tempfile.mkdtemp()
        try:
            with open(os.path.join(temp_dir, "clean_module.py"), "w") as f:
                f.write("def safe_hello():\n    return 'Hello Secure World!'\n")

            exit_code = run_scan(temp_dir, fail_on="HIGH")
            self.assertEqual(exit_code, 0)
        finally:
            shutil.rmtree(temp_dir)


if __name__ == "__main__":
    unittest.main()
