import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token
from backend.exporters.sbom_generator import sbom_generator
from backend.scanners.rasp_engine import rasp_engine
from backend.integrations.issue_trackers import issue_tracker


class TestEnterpriseSuiteV2(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.admin_token = create_access_token(user_id="admin-id", username="admin", role="admin")
        self.headers = {"Authorization": f"Bearer {self.admin_token}"}

    def test_sbom_cyclonedx_generation(self):
        resp = self.client.get("/api/sbom/cyclonedx", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["bomFormat"], "CycloneDX")
        self.assertEqual(data["specVersion"], "1.5")
        self.assertIn("components", data)
        self.assertGreater(len(data["components"]), 0)
        # Check PURL format
        first_comp = data["components"][0]
        self.assertTrue(first_comp["purl"].startswith("pkg:"))

    def test_sbom_spdx_generation(self):
        resp = self.client.get("/api/sbom/spdx", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["spdxVersion"], "SPDX-2.3")
        self.assertEqual(data["dataLicense"], "CC0-1.0")
        self.assertIn("packages", data)
        self.assertIn("relationships", data)

    def test_sbom_openvex_attestation(self):
        resp = self.client.get("/api/sbom/vex", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("@context", data)
        self.assertIn("statements", data)
        self.assertGreater(len(data["statements"]), 0)
        self.assertIn("status", data["statements"][0])

    def test_rule_sandbox_evaluate(self):
        payload = {
            "regex": r"(?i)eval\s*\(",
            "test_snippet": "x = 10\neval('2 + 2')\nprint(x)",
            "language": "python"
        }
        resp = self.client.post("/api/rules/test-sandbox", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["match_count"], 1)
        self.assertEqual(data["matches"][0]["line"], 2)

    def test_rule_sandbox_syntax_error(self):
        payload = {
            "regex": r"(?i)[unclosed bracket",
            "test_snippet": "eval('2 + 2')",
            "language": "python"
        }
        resp = self.client.post("/api/rules/test-sandbox", json=payload, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["valid"])
        self.assertIn("Regex Syntax Error", data["error"])

    def test_custom_rule_builder_creation(self):
        rule_data = {
            "name": "Disallow Insecure Deserialization Pickle",
            "type": "sast",
            "severity": "CRITICAL",
            "languages": ["python"],
            "cwe": "CWE-502",
            "owasp": "OWASP:A08:2021",
            "regex": r"(?i)pickle\.(?:loads|load)\s*\(",
            "description": "Unpickling untrusted data allows arbitrary remote code execution.",
            "remediation": "Use safe JSON serialization or HMAC signature verification."
        }
        resp = self.client.post("/api/rules/custom-builder", json=rule_data, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["rule_id"].startswith("CUSTOM-"))

    def test_issue_trackers_status(self):
        resp = self.client.get("/api/trackers/status", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("jira", data)
        self.assertIn("linear", data)
        self.assertTrue(data["jira"]["connected"])

    def test_create_tracker_ticket_jira_and_linear(self):
        # Jira ticket
        resp = self.client.post("/api/trackers/create-ticket", json={
            "finding_id": "FINDING-TEST-001",
            "provider": "jira",
            "project_key": "SEC"
        }, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["ticket"]["ticket_id"].startswith("SEC-"))

        # Linear ticket
        resp2 = self.client.post("/api/trackers/create-ticket", json={
            "finding_id": "FINDING-TEST-002",
            "provider": "linear",
            "project_key": "ENG"
        }, headers=self.headers)
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.json()
        self.assertEqual(data2["status"], "success")
        self.assertTrue(data2["ticket"]["ticket_id"].startswith("ENG-"))

    def test_tracker_sync(self):
        resp = self.client.post("/api/trackers/sync", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("synced_count", data)

    def test_rasp_telemetry(self):
        resp = self.client.get("/api/rasp/telemetry", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("mode", data)
        self.assertIn("recent_incidents", data)
        self.assertGreater(data["total_incidents"], 0)

    def test_rasp_simulate_attack(self):
        resp = self.client.post("/api/rasp/simulate", json={
            "vector": "SQL_INJECTION",
            "payload": "' UNION SELECT 1, @@version, user() --"
        }, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        sim = data["simulation"]
        self.assertTrue(sim["intercepted"])
        self.assertTrue(sim["blocked"])
        self.assertEqual(sim["incident"]["vector"], "SQL_INJECTION")

    def test_rasp_mode_switch(self):
        resp = self.client.post("/api/rasp/mode", json={"mode": "MONITOR"}, headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["mode"], "MONITOR")

        # Test simulation in MONITOR mode (should not block)
        resp2 = self.client.post("/api/rasp/simulate", json={
            "vector": "COMMAND_INJECTION",
            "payload": "; cat /etc/passwd"
        }, headers=self.headers)
        sim2 = resp2.json()["simulation"]
        self.assertTrue(sim2["intercepted"])
        self.assertFalse(sim2["blocked"])

        # Reset back to BLOCK
        self.client.post("/api/rasp/mode", json={"mode": "BLOCK"}, headers=self.headers)


if __name__ == "__main__":
    unittest.main()
