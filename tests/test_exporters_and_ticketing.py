"""
Unit tests for SARIF 2.1, CycloneDX SBOM, Executive HTML Exporters, and Ticketing Connectors.
"""

import json
import unittest
from backend.exporters.report_generator import ReportGenerator
from backend.integrations.jira_connector import JiraConnector
from backend.integrations.zammad_connector import ZammadConnector


class TestExportersAndTicketing(unittest.TestCase):
    def setUp(self):
        self.mock_project = {"id": "proj-101", "name": "Telemetry-App", "git_branch": "main"}
        self.mock_scan = {"id": "scan-202", "composite_risk_score": 75.0}
        self.mock_findings = [
            {
                "id": "f-1",
                "type": "sast",
                "title": "Hardcoded API Key",
                "description": "Found hardcoded AWS token",
                "remediation": "Use AWS Secrets Manager",
                "severity": "CRITICAL",
                "cwe_id": "CWE-798",
                "file_path": "auth.py",
                "line_start": 12,
                "line_end": 12,
                "code_snippet": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
                "cvss_score": 9.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "epss_score": 0.88,
                "epss_percentile": 0.98,
                "composite_risk_score": 92.0,
                "quadrant": "ACT_NOW",
                "sla_days": 2,
                "standards": ["ISO-27001:A.8.12", "CIS:CIS-1.1"],
                "status": "open"
            }
        ]

    def test_sarif_v210_generation(self):
        sarif_str = ReportGenerator.generate_sarif(self.mock_project, self.mock_scan, self.mock_findings)
        doc = json.loads(sarif_str)

        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 1)
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "AegisSec SAST & SCA Engine")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["ruleId"], "CWE-798")
        self.assertEqual(run["results"][0]["level"], "error")

    def test_cyclonedx_sbom_generation(self):
        mock_deps = [{"name": "requests", "version": "2.28.0", "license": "Apache-2.0", "ecosystem": "pypi"}]
        sbom_str = ReportGenerator.generate_cyclonedx_sbom(self.mock_project, mock_deps, self.mock_findings)
        doc = json.loads(sbom_str)

        self.assertEqual(doc["bomFormat"], "CycloneDX")
        self.assertEqual(doc["specVersion"], "1.5")
        self.assertEqual(len(doc["components"]), 1)
        self.assertEqual(doc["components"][0]["name"], "requests")

    def test_executive_html_generation(self):
        html = ReportGenerator.generate_html_report(self.mock_project, self.mock_scan, self.mock_findings)
        self.assertIn("AegisSec Executive Report", html)
        self.assertIn("Telemetry-App", html)
        self.assertIn("Hardcoded API Key", html)
        self.assertIn("ISO-27001", html)

    def test_ticketing_payload_creation(self):
        # Jira Mock Ticket
        jira_res = JiraConnector.create_ticket(self.mock_findings[0])
        self.assertTrue(jira_res["success"])
        self.assertIn("ticket_key", jira_res)

        # Zammad Mock Ticket
        zammad_res = ZammadConnector.create_ticket(self.mock_findings[0])
        self.assertTrue(zammad_res["success"])
        self.assertIn("ticket_key", zammad_res)


if __name__ == "__main__":
    unittest.main()
