"""
Unit and Integration Tests for SonarQube SAST RSPEC Rules & Open Rule Database:
1. SonarQube RSPEC rule structure & multi-language detection (Python, JS, Java, C/C++)
2. SAST Engine detection of SonarQube vulnerabilities (S2077, S5144, S4790, S5131, S5814)
3. SonarQube Quality Profile XML Import
4. SonarQube JSON Rules Import
5. Semgrep Community YAML Rules Import
6. Open Rule Database Toggling and Sync
7. FastAPI REST API endpoints (/api/rules/sonarqube & /api/rules/database)
8. Rule Manager Catalog & CLI list-rules integration
"""

import os
import shutil
import tempfile
import unittest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db import db
from backend.auth import create_access_token
from backend.scanners.sast_engine import SASTEngine
from backend.rules.sonar_rules_db import SONARQUBE_SAST_RULES
from backend.rules.open_rule_database import OpenRuleDatabaseManager, open_rule_db
from backend.rules.rule_manager import rule_manager
from scripts.sentinel_cli import list_rules


class TestSonarQubeAndOpenRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.admin_user = db.get_user_by_username("admin")
        cls.admin_token = create_access_token(
            cls.admin_user["id"], cls.admin_user["username"], cls.admin_user["role"]
        )

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_sonar_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_sonarqube_rules_structure(self):
        """Verify SonarQube RSPEC rules contain required metadata and valid regex."""
        self.assertGreaterEqual(len(SONARQUBE_SAST_RULES), 38)
        sonar_keys = [r.get("sonar_key") for r in SONARQUBE_SAST_RULES]

        # Verify key SonarQube RSPEC rules exist
        self.assertIn("S2077", sonar_keys)  # SQL Injection
        self.assertIn("S2068", sonar_keys)  # Hardcoded Credentials
        self.assertIn("S5144", sonar_keys)  # SSRF
        self.assertIn("S5883", sonar_keys)  # OS Command Injection
        self.assertIn("S5131", sonar_keys)  # XSS
        self.assertIn("S4790", sonar_keys)  # Weak Hash
        self.assertIn("S5542", sonar_keys)  # Insecure Encryption
        self.assertIn("S5135", sonar_keys)  # Deserialization
        self.assertIn("S2083", sonar_keys)  # Path Traversal
        self.assertIn("S2755", sonar_keys)  # XXE
        self.assertIn("S5146", sonar_keys)  # Open Redirect
        self.assertIn("S5122", sonar_keys)  # CORS
        self.assertIn("S4423", sonar_keys)  # Weak TLS
        self.assertIn("S5814", sonar_keys)  # C/C++ Buffer Overflow
        self.assertIn("S5042", sonar_keys)  # Zip Slip
        self.assertIn("S5332", sonar_keys)  # Cleartext Protocols
        self.assertIn("S2612", sonar_keys)  # Loose File Permissions (chmod 777)
        self.assertIn("S5443", sonar_keys)  # Insecure /tmp Files
        self.assertIn("S5808", sonar_keys)  # Timing Attacks
        self.assertIn("S2091", sonar_keys)  # XPath Injection
        self.assertIn("S5838", sonar_keys)  # Sensitive Logging
        self.assertIn("S2095", sonar_keys)  # Resource Leaks
        self.assertIn("S3330", sonar_keys)  # Insecure Cookie SameSite
        self.assertIn("S5167", sonar_keys)  # Mass Assignment
        self.assertIn("S6287", sonar_keys)  # Rate Limiting
        self.assertIn("S2115", sonar_keys)  # Hardcoded DB URI
        self.assertIn("S5706", sonar_keys)  # Reflection
        self.assertIn("S2277", sonar_keys)  # RSA OAEP

        for r in SONARQUBE_SAST_RULES:
            self.assertTrue(r["id"].startswith("SONAR-"))
            self.assertIn("cwe", r)
            self.assertIn("owasp", r)
            self.assertIn("regex", r)
            self.assertIn("description", r)
            self.assertIn("remediation", r)
            self.assertGreater(len(r["languages"]), 0)

    def test_02_sast_engine_detects_sonarqube_vulnerabilities(self):
        """Verify SAST engine flags SonarQube-specific flaws and enriches findings."""
        # Create a Python file triggering SonarQube S2077 (SQLi) & S5144 (SSRF)
        py_code = """
import requests
import sqlite3

def handle_request(req):
    target_url = req.query.get("target")
    # SonarQube S5144: SSRF
    resp = requests.get(req.query.url)

    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SonarQube S2077: SQL Injection
    cursor.execute(f"SELECT * FROM accounts WHERE id = '{req.query.id}'")
"""
        with open(os.path.join(self.test_dir, "service.py"), "w") as f:
            f.write(py_code)

        # Create a JavaScript file triggering SonarQube S5131 (XSS)
        js_code = """
app.get('/search', (req, res) => {
    // SonarQube S5131: Reflected XSS
    res.send(req.query.keyword);
});
"""
        with open(os.path.join(self.test_dir, "server.js"), "w") as f:
            f.write(js_code)

        sast = SASTEngine(include_open_db=True)
        findings = sast.scan_directory(self.test_dir)
        rule_ids = [f["rule_id"] for f in findings]

        # Verify SonarQube rules fired
        self.assertTrue(any("S2077" in rid for rid in rule_ids))
        self.assertTrue(any("S5144" in rid for rid in rule_ids))
        self.assertTrue(any("S5131" in rid for rid in rule_ids))

        # Verify enriched SonarQube finding metadata
        sqli_sonar = next(f for f in findings if "S2077" in f["rule_id"])
        self.assertEqual(sqli_sonar.get("sonar_key"), "S2077")
        self.assertEqual(sqli_sonar.get("sonar_type"), "VULNERABILITY")
        self.assertEqual(sqli_sonar.get("rule_source"), "sonarqube_rspec")

    def test_03_sonarqube_xml_quality_profile_import(self):
        """Verify importing a SonarQube XML Quality Profile parses and registers rules."""
        xml_profile = """<?xml version="1.0" encoding="UTF-8"?>
<profile>
  <name>Custom Secure Profile</name>
  <language>py</language>
  <rules>
    <rule>
      <repositoryKey>python</repositoryKey>
      <key>S2077</key>
      <priority>BLOCKER</priority>
      <name>Formatting SQL queries is security-sensitive</name>
      <description>SQL queries formatted with variables allows SQL injection.</description>
    </rule>
    <rule>
      <repositoryKey>python</repositoryKey>
      <key>S5144</key>
      <priority>CRITICAL</priority>
      <name>Server-side requests should not be vulnerable to SSRF</name>
      <description>Unchecked URLs in requests cause SSRF.</description>
    </rule>
  </rules>
</profile>
"""
        imported = open_rule_db.import_sonarqube_profile_xml(xml_profile)
        self.assertEqual(len(imported), 2)
        self.assertEqual(imported[0]["sonar_key"], "S2077")
        self.assertEqual(imported[0]["sonar_severity"], "BLOCKER")
        self.assertEqual(imported[0]["severity"], "CRITICAL")
        self.assertEqual(imported[0]["languages"], ["python"])

    def test_04_sonarqube_json_rules_import(self):
        """Verify importing SonarQube JSON rules register into the open database."""
        json_payload = {
            "rules": [
                {
                    "key": "python:S4790",
                    "repo": "python",
                    "name": "Using weak hashing algorithms is security-sensitive",
                    "severity": "MAJOR",
                    "type": "SECURITY_HOTSPOT",
                    "description": "MD5 and SHA-1 have known collision issues."
                }
            ]
        }
        imported = open_rule_db.import_sonarqube_json(json_payload)
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0]["sonar_key"], "S4790")
        self.assertEqual(imported[0]["rule_source"], "sonarqube_imported")

    def test_05_semgrep_yaml_rules_import(self):
        """Verify importing Semgrep YAML rules converts them to Sentinel regex SAST rules."""
        yaml_content = """
rules:
  - id: python-hardcoded-bearer
    message: Hardcoded Bearer token found in code
    severity: ERROR
    languages: [python, javascript]
    pattern-regex: 'Bearer\\s+[a-zA-Z0-9_\\-\\.]{32,}'
    metadata:
      cwe: CWE-798
      owasp: A07:2021
"""
        imported = open_rule_db.import_semgrep_yaml(yaml_content)
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0]["id"], "SEMGREP-python-hardcoded-bearer")
        self.assertEqual(imported[0]["cwe"], "CWE-798")
        self.assertEqual(imported[0]["severity"], "HIGH")
        self.assertIn("Bearer", imported[0]["regex"])

    def test_06_open_rule_database_toggle_and_sync(self):
        """Verify enabling/disabling rules and synchronizing the database."""
        # Toggle rule S2077 to inactive
        success = open_rule_db.toggle_rule("SONAR-S2077", False)
        self.assertTrue(success)
        rule = open_rule_db.get_rule_by_id("SONAR-S2077")
        self.assertFalse(rule["is_active"])

        # Re-enable rule S2077
        success = open_rule_db.toggle_rule("SONAR-S2077", True)
        self.assertTrue(success)
        rule = open_rule_db.get_rule_by_id("SONAR-S2077")
        self.assertTrue(rule["is_active"])

        # Sync database
        sync_res = open_rule_db.sync_remote_database()
        self.assertEqual(sync_res["status"], "success")
        self.assertGreater(sync_res["total_active_rules"], 20)

    def test_07_api_endpoints_sonarqube_and_database(self):
        """Verify GET /api/rules/sonarqube and /api/rules/database REST endpoints."""
        # GET /api/rules/sonarqube
        res = self.client.get(
            "/api/rules/sonarqube",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total", data)
        self.assertIn("rules", data)
        self.assertIn("stats", data)
        self.assertGreaterEqual(data["total"], 20)

        # Filter by language
        res_py = self.client.get(
            "/api/rules/sonarqube?language=python",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_py.status_code, 200)
        py_data = res_py.json()
        for r in py_data["rules"]:
            self.assertIn("python", r["languages"])

        # GET /api/rules/database
        res_db = self.client.get(
            "/api/rules/database",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_db.status_code, 200)
        db_data = res_db.json()
        self.assertIn("stats", db_data)
        self.assertIn("rules", db_data)
        self.assertGreater(db_data["stats"]["total_open_rules"], 20)

        # POST /api/rules/database/sync
        res_sync = self.client.post(
            "/api/rules/database/sync",
            json={},
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_sync.status_code, 200)
        self.assertEqual(res_sync.json()["status"], "success")

    def test_08_rule_manager_catalog_integration(self):
        """Verify RuleManager returns SonarQube & Open Database rules in the catalog."""
        catalog = rule_manager.get_complete_rule_catalog()
        summary = catalog["summary"]
        rules = catalog["rules"]

        self.assertIn("sonarqube_rules", summary)
        self.assertIn("open_database_rules", summary)
        self.assertGreaterEqual(summary["sonarqube_rules"], 20)
        self.assertIn("sonarqube_rules", rules)
        self.assertIn("open_database_rules", rules)

        # Verify CLI list_rules executes without error
        status = list_rules(output_json=True)
        self.assertEqual(status, 0)

    def test_09_new_sonarqube_rules_detection(self):
        """Verify SAST engine detects newly added SonarQube rules (S5042, S5332, S2612, S5808, S2115)."""
        py_vuln = """
import os
import tarfile

def process_archive(tar_path):
    # SonarQube S5042: Zip Slip
    with tarfile.open(tar_path) as tar:
        tar.extractall("/tmp/extracted")

    # SonarQube S2612: Overly permissive chmod
    os.chmod("/tmp/extracted/run.sh", 0o777)

    # SonarQube S5332: Cleartext protocol
    api_url = "http://production-vault.company.internal/keys"

    # SonarQube S5808: Timing attack in secret comparison
    if auth_token == user_token:
        pass

    # SonarQube S2115: Hardcoded database URI
    db_uri = "postgres://admin:SuperSecretPassword123!@db.internal:5432/production"
"""
        vuln_file = os.path.join(self.test_dir, "vuln_service.py")
        with open(vuln_file, "w") as f:
            f.write(py_vuln)

        sast = SASTEngine(include_open_db=True)
        findings = sast.scan_file(vuln_file, "vuln_service.py", "python")
        sonar_keys = [f.get("sonar_key") for f in findings if f.get("sonar_key")]

        self.assertIn("S5042", sonar_keys)
        self.assertIn("S2612", sonar_keys)
        self.assertIn("S5332", sonar_keys)
        self.assertIn("S5808", sonar_keys)
        self.assertIn("S2115", sonar_keys)

    def test_09b_additional_sonarqube_rules_detection(self):
        """Verify SAST engine detects S6035 (JS Prototype Pollution), S3329 (Predictable IV), S6362 (JWT Secret), S5165 (Upload)."""
        # Test JavaScript file with Prototype Pollution S6035
        js_vuln = """
function mergeUserData(target, req) {
    Object.assign(target, req.body);
    target["__proto__"] = req.body.admin;
}
"""
        js_file = os.path.join(self.test_dir, "vuln_proto.js")
        with open(js_file, "w") as f:
            f.write(js_vuln)

        # Test Python file with predictable IV (S3329), hardcoded JWT secret (S6362), and file upload (S5165)
        py_vuln = """
import os
import jwt
from Crypto.Cipher import AES

# S3329: Predictable IV
iv = bytes(16)
cipher = AES.new(key, AES.MODE_CBC, iv)

# S6362: Hardcoded JWT secret
token = jwt.encode({"sub": "user"}, "MyHardcodedJwtSecretKey123!")

# S5165: Unrestricted file upload
file.save(os.path.join("/var/uploads", file.filename))
"""
        py_file = os.path.join(self.test_dir, "vuln_crypto_upload.py")
        with open(py_file, "w") as f:
            f.write(py_vuln)

        sast = SASTEngine(include_open_db=True)
        js_findings = sast.scan_file(js_file, "vuln_proto.js", "javascript")
        py_findings = sast.scan_file(py_file, "vuln_crypto_upload.py", "python")

        js_keys = [f.get("sonar_key") for f in js_findings if f.get("sonar_key")]
        py_keys = [f.get("sonar_key") for f in py_findings if f.get("sonar_key")]

        self.assertIn("S6035", js_keys)
        self.assertIn("S3329", py_keys)
        self.assertIn("S6362", py_keys)
        self.assertIn("S5165", py_keys)

    def test_10_sonarqube_generic_issues_export(self):
        """Verify GET /api/projects/{id}/export/sonarqube returns valid SonarQube Generic Issue JSON."""
        projects = db.list_projects()
        if not projects:
            p = db.create_project("Sonar Test Project", "/tmp", "main")
            proj_id = p["id"]
        else:
            proj_id = projects[0]["id"]

        res = self.client.get(
            f"/api/projects/{proj_id}/export/sonarqube",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("issues", data)
        self.assertIsInstance(data["issues"], list)
        if data["issues"]:
            first_issue = data["issues"][0]
            self.assertEqual(first_issue["engineId"], "sentinel-sast")
            self.assertIn("ruleId", first_issue)
            self.assertIn("severity", first_issue)
            self.assertIn(first_issue["severity"], ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"])
            self.assertIn("type", first_issue)
            self.assertIn("primaryLocation", first_issue)
            self.assertIn("message", first_issue["primaryLocation"])
            self.assertIn("filePath", first_issue["primaryLocation"])
            self.assertIn("textRange", first_issue["primaryLocation"])

    def test_11_sonar_properties_and_workflow_exports(self):
        """Verify GET /api/projects/{id}/export/sonar-properties and github-sonar-workflow."""
        projects = db.list_projects()
        proj_id = projects[0]["id"] if projects else db.create_project("Sonar Properties Test", "/tmp", "main")["id"]

        # 1. sonar-project.properties
        res_props = self.client.get(
            f"/api/projects/{proj_id}/export/sonar-properties",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_props.status_code, 200)
        props_text = res_props.text
        self.assertIn("sonar.projectKey=", props_text)
        self.assertIn("sonar.externalIssuesReportPaths=sonar-issues.json", props_text)
        self.assertIn("sonar.sarifReportPaths=aegissec-sarif.json", props_text)

        # 2. github-sonar-workflow
        res_wf = self.client.get(
            f"/api/projects/{proj_id}/export/github-sonar-workflow",
            headers={"Authorization": f"Bearer {self.admin_token}"}
        )
        self.assertEqual(res_wf.status_code, 200)
        wf_text = res_wf.text
        self.assertIn("Sentinel SAST", wf_text)
        self.assertIn("SonarSource/sonarqube-scan-action", wf_text)
        self.assertIn("-Dsonar.externalIssuesReportPaths=sonar-issues.json", wf_text)

    def test_12_project_sonarqube_integration_endpoint(self):
        """Verify POST /api/projects/{id}/integrate/sonarqube generates integration files in workspace."""
        temp_repo = tempfile.mkdtemp(prefix="test_repo_sonar_")
        try:
            projects = db.list_projects()
            proj_id = projects[0]["id"] if projects else db.create_project(
                "Integration Test Repo", "Test desc", "https://github.com/org/repo.git", "main", "", "admin"
            )["id"]

            res = self.client.post(
                f"/api/projects/{proj_id}/integrate/sonarqube",
                json={"target_dir": temp_repo},
                headers={"Authorization": f"Bearer {self.admin_token}"}
            )
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertEqual(data["status"], "success")
            self.assertIn("sonar-project.properties", [os.path.basename(f) for f in data["files_created"]])
            self.assertIn("sonar-sast.yml", [os.path.basename(f) for f in data["files_created"]])
            self.assertIn("sonar-issues.json", [os.path.basename(f) for f in data["files_created"]])

            # Verify files actually exist on disk
            self.assertTrue(os.path.exists(os.path.join(temp_repo, "sonar-project.properties")))
            self.assertTrue(os.path.exists(os.path.join(temp_repo, ".github", "workflows", "sonar-sast.yml")))
            self.assertTrue(os.path.exists(os.path.join(temp_repo, "sonar-issues.json")))
        finally:
            shutil.rmtree(temp_repo, ignore_errors=True)

    def test_13_cli_init_sonar_and_sonar_export(self):
        """Verify CLI init-sonar and scan with --sonar-export generates valid generic issue report."""
        from scripts.sentinel_cli import init_sonar, run_scan
        import json

        cli_repo = tempfile.mkdtemp(prefix="test_cli_sonar_")
        try:
            # 1. init_sonar
            exit_code = init_sonar(cli_repo, "cli-test-project")
            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(os.path.join(cli_repo, "sonar-project.properties")))
            self.assertTrue(os.path.exists(os.path.join(cli_repo, ".github", "workflows", "sonar-sast.yml")))

            # 2. Add vulnerable file and scan with --sonar-export
            with open(os.path.join(cli_repo, "app.py"), "w") as f:
                f.write('password = "SecretHardcodedPassword123!"\n')

            out_sonar = os.path.join(cli_repo, "sonar-issues.json")
            run_scan(cli_repo, fail_on="LOW", output_json=True, sonar_export=out_sonar)
            self.assertTrue(os.path.exists(out_sonar))

            with open(out_sonar, "r") as f:
                sonar_data = json.load(f)
                self.assertIn("issues", sonar_data)
                self.assertGreaterEqual(len(sonar_data["issues"]), 1)
                self.assertEqual(sonar_data["issues"][0]["engineId"], "sentinel-sast")
        finally:
            shutil.rmtree(cli_repo, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

