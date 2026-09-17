"""
Unit and Integration Tests for:
1. IDE Extension Manifest & Rule Engine
2. Project Custom Rules (.sentinel/rules.yaml) Discovery & Ingestion
3. Backend Rule Catalog (/api/rules/catalog) & Export Endpoints
4. CLI list-rules & JSON Diagnostic Output
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
from backend.rules.rule_manager import rule_manager
from backend.scanners.sast_engine import SASTEngine
from backend.scanners.iac_engine import IaCEngine
from scripts.sentinel_cli import list_rules, run_scan


class TestIDEAndCustomRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"])

    def test_01_ide_extension_manifest_validity(self):
        """Verify ide-extension/package.json contains all required VS Code extension declarations."""
        pkg_path = os.path.join(os.path.dirname(__file__), "..", "ide-extension", "package.json")
        self.assertTrue(os.path.exists(pkg_path), "ide-extension/package.json must exist")

        with open(pkg_path, "r") as f:
            manifest = json.load(f)

        self.assertEqual(manifest["name"], "sentinel-appsec-ide")
        self.assertIn("contributes", manifest)
        self.assertIn("commands", manifest["contributes"])
        self.assertIn("views", manifest["contributes"])

        cmd_ids = [c["command"] for c in manifest["contributes"]["commands"]]
        self.assertIn("sentinel.scanCurrentFile", cmd_ids)
        self.assertIn("sentinel.refreshRules", cmd_ids)
        self.assertIn("sentinel.inspectRule", cmd_ids)

    def test_02_project_custom_rules_yaml_parsing(self):
        """Verify project .sentinel/rules.yaml is discovered and parsed by RuleManager."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        project_rules = rule_manager.load_project_rules(repo_root)

        self.assertGreaterEqual(len(project_rules), 4)
        rule_ids = [r["id"] for r in project_rules]
        self.assertIn("PROJ-SAST-001", rule_ids)
        self.assertIn("PROJ-SAST-002", rule_ids)
        self.assertIn("PROJ-IAC-001", rule_ids)
        self.assertIn("PROJ-SEC-001", rule_ids)

        for r in project_rules:
            self.assertTrue(r.get("is_project_custom"))

    def test_03_backend_rule_catalog_endpoint(self):
        """Verify GET /api/rules/catalog returns all rule tiers including project custom rules."""
        res = self.client.get(
            "/api/rules/catalog",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("summary", data)
        self.assertIn("rules", data)
        self.assertGreater(data["summary"]["total_active_rules"], 20)
        self.assertGreaterEqual(data["summary"]["project_custom"], 4)

        # Check rule categories in payload
        rules = data["rules"]
        self.assertIn("sast_builtin", rules)
        self.assertIn("iac_builtin", rules)
        self.assertIn("api_builtin", rules)
        self.assertIn("project_custom", rules)

    def test_04_backend_rule_export_endpoint(self):
        """Verify GET /api/rules/export downloads YAML and JSON bundles."""
        res_yaml = self.client.get(
            "/api/rules/export?format=yaml",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_yaml.status_code, 200)
        self.assertIn("version:", res_yaml.text)
        self.assertIn("PROJ-SAST-001", res_yaml.text)

        res_json = self.client.get(
            "/api/rules/export?format=json",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_json.status_code, 200)
        data = res_json.json()
        self.assertIn("rules", data)

    def test_05_sast_engine_executes_project_custom_rules(self):
        """Verify SASTEngine dynamically flags violations defined in .sentinel/rules.yaml."""
        temp_dir = tempfile.mkdtemp()
        try:
            # Create synthetic .sentinel/rules.yaml inside temp directory
            sentinel_dir = os.path.join(temp_dir, ".sentinel")
            os.makedirs(sentinel_dir, exist_ok=True)
            with open(os.path.join(sentinel_dir, "rules.yaml"), "w") as f:
                f.write("""version: "1.0"
rules:
  - id: "PROJ-LOCAL-001"
    name: "Unsafe YAML Load Violation"
    type: "sast"
    severity: "CRITICAL"
    languages: ["python"]
    regex: "(?i)yaml\\\\.load\\\\("
    description: "Insecure yaml.load"
    remediation: "Use safe_load"
""")

            # Create vulnerable python file
            with open(os.path.join(temp_dir, "vulnerable.py"), "w") as f:
                f.write("import yaml\ndata = yaml.load(user_stream)\n")

            sast = SASTEngine()
            findings = sast.scan_directory(temp_dir)
            rule_titles = [f["title"] for f in findings]

            self.assertTrue(any("PROJ-LOCAL-001" in t or "Unsafe YAML Load" in t for t in rule_titles))
        finally:
            shutil.rmtree(temp_dir)

    def test_06_iac_engine_executes_project_custom_rules(self):
        """Verify IaCEngine dynamically flags violations defined in .sentinel/rules.yaml."""
        temp_dir = tempfile.mkdtemp()
        try:
            sentinel_dir = os.path.join(temp_dir, ".sentinel")
            os.makedirs(sentinel_dir, exist_ok=True)
            with open(os.path.join(sentinel_dir, "rules.yaml"), "w") as f:
                f.write("""version: "1.0"
rules:
  - id: "PROJ-DOCKER-ROOT"
    name: "Explicit Root User Ban"
    type: "iac"
    severity: "CRITICAL"
    languages: ["dockerfile"]
    regex: "(?i)^USER\\\\s+root"
    description: "Root user forbidden"
    remediation: "Switch to appuser"
""")

            with open(os.path.join(temp_dir, "Dockerfile"), "w") as f:
                f.write("FROM alpine:3.19\nUSER root\nCMD [\"sh\"]\n")

            iac = IaCEngine()
            findings = iac.scan_directory(temp_dir)
            rule_titles = [f["title"] for f in findings]

            self.assertTrue(any("PROJ-DOCKER-ROOT" in t or "Explicit Root User Ban" in t for t in rule_titles))
        finally:
            shutil.rmtree(temp_dir)

    def test_07_cli_list_rules_runner(self):
        """Verify CLI list_rules functions correctly in both text and JSON modes."""
        exit_code_text = list_rules(".", output_json=False)
        self.assertEqual(exit_code_text, 0)

        exit_code_json = list_rules(".", output_json=True)
        self.assertEqual(exit_code_json, 0)


if __name__ == "__main__":
    unittest.main()
