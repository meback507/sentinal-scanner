"""
Unit & Integration Tests for Sentinel AppSec Advanced Capabilities:
- Multi-Channel Webhook Alerts (Slack, Teams, Discord, Generic HMAC)
- Live DAST & HTTP Security Header Auditor
- Interactive Batch Multi-File Auto-Patching & PR Studio
- Background Task Scheduler & Threat Intel Auto-Sync
- Interactive SCA Dependency Graph / DAG Builder
"""

import unittest
import os
import json
from fastapi.testclient import TestClient
from backend.main import app
from backend.db import db
from backend.integrations.webhook_notifier import WebhookNotifier
from backend.scanners.dast_engine import DASTEngine
from backend.scheduler import scheduler
from backend.scanners.dependency_graph import DependencyGraphBuilder


class TestNewUpgrades(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        from backend.auth import create_access_token
        # Admin Token
        admin_user = db.get_user_by_username("admin") or {"id": "1", "username": "admin", "role": "admin"}
        cls.admin_token = create_access_token(str(admin_user["id"]), admin_user["username"], admin_user["role"])
        cls.admin_headers = {"Authorization": f"Bearer {cls.admin_token}"}

        # Marcus Token (Developer)
        marcus_user = db.get_user_by_username("marcus") or {"id": "3", "username": "marcus", "role": "developer"}
        cls.marcus_token = create_access_token(str(marcus_user["id"]), marcus_user["username"], marcus_user["role"])
        cls.marcus_headers = {"Authorization": f"Bearer {cls.marcus_token}"}

    def test_01_webhook_notifier_payloads_and_test(self):
        """Verify WebhookNotifier builds valid payloads for Slack, Teams, Discord, and Generic."""
        fields = [{"title": "CVSS", "value": "9.8", "short": True}]
        slack = WebhookNotifier._build_slack_payload("Alert", "Critical flaw", fields, "CRITICAL", "http://localhost:8000")
        self.assertIn("attachments", slack)
        self.assertEqual(slack["attachments"][0]["color"], "#E63946")

        teams = WebhookNotifier._build_teams_payload("Alert", "Critical flaw", fields, "HIGH", "http://localhost:8000")
        self.assertEqual(teams["@type"], "MessageCard")
        self.assertIn("sections", teams)

        discord = WebhookNotifier._build_discord_payload("Alert", "Critical flaw", fields, "MEDIUM", "http://localhost:8000")
        self.assertIn("embeds", discord)

        generic = WebhookNotifier._build_generic_payload("test", "Alert", "Critical flaw", fields, "LOW", None)
        self.assertEqual(generic["event"], "test")

        # Test simulated webhook dispatch with invalid/mock URL
        test_res = WebhookNotifier.test_webhook("slack", "https://hooks.slack.com/services/MOCK/TEST/TOKEN")
        self.assertIn("success", test_res)

    def test_02_webhook_api_endpoints(self):
        """Verify GET and POST /api/integrations/webhooks and /test."""
        # 1. Get config
        get_res = self.client.get("/api/integrations/webhooks", headers=self.admin_headers)
        self.assertEqual(get_res.status_code, 200)

        # 2. Update config
        new_cfg = {
            "enabled": True,
            "slack_webhook_url": "https://hooks.slack.com/services/TEST/AAA/BBB",
            "teams_webhook_url": "https://outlook.office.com/webhook/test",
            "discord_webhook_url": "",
            "generic_webhook_url": "https://api.internal/webhook",
            "generic_secret": "my-secret-key-123",
            "notify_on_scan_completed": True,
            "notify_on_critical_finding": True,
            "notify_on_cisa_kev": True,
            "min_severity": "HIGH"
        }
        post_res = self.client.post("/api/integrations/webhooks", json=new_cfg, headers=self.admin_headers)
        self.assertEqual(post_res.status_code, 200)
        self.assertTrue(post_res.json()["success"])

        # 3. Test endpoint
        test_payload = {
            "webhook_type": "generic",
            "webhook_url": "https://httpbin.org/post",
            "secret": "test-sec"
        }
        test_res = self.client.post("/api/integrations/webhooks/test", json=test_payload, headers=self.admin_headers)
        self.assertEqual(test_res.status_code, 200)

    def test_03_dast_engine_and_endpoint(self):
        """Verify DASTEngine audits web headers, cookies, CSP, HSTS, and generates letter grades."""
        # Test on local server URL
        audit_res = self.client.post(
            "/api/dast/audit",
            json={"target_url": "http://127.0.0.1:8000/api/health", "timeout": 4},
            headers=self.admin_headers
        )
        self.assertEqual(audit_res.status_code, 200)
        data = audit_res.json()
        self.assertIn("score", data)
        self.assertIn("grade", data)
        self.assertIn("findings", data)
        self.assertIn("summary", data)
        # Should flag missing CSP or missing HSTS on local cleartext HTTP
        self.assertGreaterEqual(len(data["findings"]), 1)

    def test_04_batch_patching_and_pr_studio(self):
        """Verify /api/findings/batch-patch with dry_run and developer row-level access."""
        # Get findings authored by marcus
        all_findings = db.list_findings()
        marcus_findings = [f for f in all_findings if "marcus" in f.get("author_name", "").lower() or "marcus" in f.get("author_email", "").lower()]

        if marcus_findings:
            fids = [f["id"] for f in marcus_findings[:2]]

            # Dry Run
            dry_res = self.client.post(
                "/api/findings/batch-patch",
                json={"finding_ids": fids, "dry_run": True},
                headers=self.marcus_headers
            )
            self.assertEqual(dry_res.status_code, 200)
            data = dry_res.json()
            self.assertTrue(data["success"])
            self.assertTrue(data["dry_run"])
            self.assertEqual(data["applied_count"], len(fids))
            self.assertIn("--- a/", data["unified_diff"])

            # Test Batch PR creation
            pr_res = self.client.post(
                "/api/findings/batch-pr",
                json={"finding_ids": fids, "pr_title": "fix: batch remediation test"},
                headers=self.marcus_headers
            )
            self.assertEqual(pr_res.status_code, 200)
            pr_data = pr_res.json()
            self.assertTrue(pr_data["success"])
            self.assertIn("pr_url", pr_data)

    def test_05_developer_isolation_on_batch_patching(self):
        """Verify developers cannot batch-patch vulnerabilities in code authored by someone else."""
        all_findings = db.list_findings()
        # Find a finding authored by Elena (ecu_controller.cpp)
        foreign_finding = next((f for f in all_findings if "elena" in f.get("author_name", "").lower()), None)
        if foreign_finding:
            # Marcus attempts to batch patch Elena's code flaw
            blocked_res = self.client.post(
                "/api/findings/batch-patch",
                json={"finding_ids": [foreign_finding["id"]], "dry_run": True},
                headers=self.marcus_headers
            )
            self.assertEqual(blocked_res.status_code, 403)

    def test_06_scheduler_and_threat_intel_sync(self):
        """Verify TaskScheduler get/save/delete schedules and on-demand threat intel sync."""
        # 1. Get schedules
        sched_res = self.client.get("/api/schedules", headers=self.admin_headers)
        self.assertEqual(sched_res.status_code, 200)
        schedules = sched_res.json()
        self.assertGreaterEqual(len(schedules), 1)

        # 2. Add custom schedule
        new_sched = {
            "name": "Hourly Critical Scan",
            "type": "project_scan",
            "interval_hours": 1,
            "enabled": True
        }
        create_res = self.client.post("/api/schedules", json=new_sched, headers=self.admin_headers)
        self.assertEqual(create_res.status_code, 200)

        # 3. Trigger Threat Intel Sync
        sync_res = self.client.post("/api/threat-intel/sync", headers=self.admin_headers)
        self.assertEqual(sync_res.status_code, 200)
        sync_data = sync_res.json()
        self.assertEqual(sync_data["status"], "success")
        self.assertGreater(sync_data["cisa_kev_count"], 1000)

        # 4. Get Status
        status_res = self.client.get("/api/threat-intel/status", headers=self.admin_headers)
        self.assertEqual(status_res.status_code, 200)
        self.assertEqual(status_res.json()["status"], "success")

    def test_07_sca_dependency_graph(self):
        """Verify /api/projects/{id}/dependencies/graph returns valid DAG nodes and edges."""
        projects = self.client.get("/api/projects", headers=self.admin_headers).json()
        self.assertGreaterEqual(len(projects), 1)
        proj_id = projects[0]["id"]

        graph_res = self.client.get(f"/api/projects/{proj_id}/dependencies/graph", headers=self.admin_headers)
        self.assertEqual(graph_res.status_code, 200)
        data = graph_res.json()

        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertIn("summary", data)
        self.assertGreaterEqual(len(data["nodes"]), 5)
        self.assertGreaterEqual(len(data["edges"]), 4)

        # Verify summary counts
        summary = data["summary"]
        self.assertIn("direct_count", summary)
        self.assertIn("transitive_count", summary)
        self.assertIn("vulnerable_count", summary)
        self.assertIn("reachable_count", summary)


if __name__ == "__main__":
    unittest.main()
