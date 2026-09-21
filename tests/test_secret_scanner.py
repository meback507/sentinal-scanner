"""
Unit tests for Comprehensive Secret Scanning Engine, Shannon Entropy,
Credential Masking, and False-Positive Suppression.
"""

import os
import shutil
import tempfile
import unittest
from backend.scanners.secret_scanner import SecretScanner, calculate_shannon_entropy, mask_credential
from backend.db import db
from fastapi.testclient import TestClient
from backend.main import app
from backend.auth import create_access_token


class TestSecretScanner(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_secrets_")
        self.scanner = SecretScanner()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_shannon_entropy_calculation(self):
        # Repetitive single character has zero entropy
        self.assertEqual(calculate_shannon_entropy("aaaaaaaa"), 0.0)
        # Low entropy string
        low = calculate_shannon_entropy("abcde")
        # High entropy random cryptographic hash / token
        high = calculate_shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertGreater(high, low)
        self.assertGreater(high, 4.0)

    def test_mask_credential(self):
        token = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_credential(token)
        self.assertTrue(masked.startswith("AKIA"))
        self.assertTrue(masked.endswith("MPLE"))
        self.assertIn("****", masked)
        # Ensure middle is concealed
        self.assertNotIn("FODNN7EXA", masked)

        short_token = "abc"
        self.assertEqual(mask_credential(short_token), "********")

    def test_cloud_tokens_detection(self):
        code = """
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_798410293847291039485720192837465019"
GITLAB_PAT = "glpat-a1b2c3d4e5f6g7h8i9j0"
SLACK_BOT = "xoxb-123456789012-1234567890123-abcde12345FGHIJ67890"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T12345678/B12345678/aBcDeFgHiJkLmNoPqRsTuVwX"
OPENAI_KEY = "sk-proj-a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
ANTHROPIC_KEY = "sk-ant-api03-abcdef1234567890abcdef1234567890-aBcDeFgH"
HUGGINGFACE = "hf_abCDefGhIJklMNopQRstUVwxYZ01234567"
GOOGLE_API = "AIzaSyD9876543210zyxwvutsrqponmlkjihgfe"
STRIPE_LIVE = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
TWILIO_SID = "AC0123456789abcdef0123456789abcdef"
SENDGRID_KEY = "SG.abcdefghijklmnopqrstuv.1234567890abcdefghijklmnopqrstuvwxyz12345678901"
DB_CONN = "postgres://admin:Sup3rS3cr3tPassword123!@db.internal.net:5432/production"
"""
        findings = self.scanner.scan_content(code, "config.py")
        detected_rule_ids = {f["rule_id"] for f in findings}

        self.assertIn("SEC-AWS-001", detected_rule_ids)
        self.assertIn("SEC-AWS-002", detected_rule_ids)
        self.assertIn("SEC-GH-001", detected_rule_ids)
        self.assertIn("SEC-GL-001", detected_rule_ids)
        self.assertIn("SEC-SLACK-001", detected_rule_ids)
        self.assertIn("SEC-SLACK-002", detected_rule_ids)
        self.assertIn("SEC-OPENAI-001", detected_rule_ids)
        self.assertIn("SEC-ANTH-001", detected_rule_ids)
        self.assertIn("SEC-HF-001", detected_rule_ids)
        self.assertIn("SEC-GCP-001", detected_rule_ids)
        self.assertIn("SEC-STRIPE-001", detected_rule_ids)
        self.assertIn("SEC-TWILIO-001", detected_rule_ids)
        self.assertIn("SEC-SG-001", detected_rule_ids)
        self.assertIn("SEC-DB-001", detected_rule_ids)

        for f in findings:
            self.assertEqual(f["type"], "secret")
            self.assertIsNotNone(f.get("entropy"))
            self.assertIsNotNone(f.get("masked_value"))
            self.assertIn("****", f["masked_value"])

    def test_private_key_block_detection(self):
        key_block = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1+r...
-----END RSA PRIVATE KEY-----
"""
        findings = self.scanner.scan_content(key_block, "id_rsa")
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("SEC-KEY-001", rule_ids)

    def test_dummy_and_placeholder_exclusion(self):
        dummy_code = """
aws_secret_access_key = "placeholder_key_not_real_secret_token"
GITHUB_TOKEN = "ghp_example_key_replace_me_with_your_token_now"
api_key = "your_secret_key_here_dummy_insert_here"
test_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"""
        findings = self.scanner.scan_content(dummy_code, "test_config.py")
        self.assertEqual(len(findings), 0, "Dummy placeholders should be filtered out")

    def test_inline_comment_suppression(self):
        suppressed_code = """
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # sentinel-ignore secret
OPENAI_KEY = "sk-proj-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"  # pragma: allowlist secret
"""
        findings = self.scanner.scan_content(suppressed_code, "settings.py")
        self.assertEqual(len(findings), 0, "Suppressed secrets should not be reported")

    def test_db_persistence_entropy_and_masked_value(self):
        # Verify db.py preserves entropy and masked_value
        test_proj = db.create_project(
            name="Secret Test Proj",
            description="Testing secret fields in DB",
            git_url="demo",
            git_branch="main",
            git_pat="",
            created_by="admin"
        )
        scan_id = db.create_scan(test_proj["id"], "Secret Test Proj", "secrets")

        sample_finding = {
            "type": "secret",
            "title": "Hardcoded Stripe Key",
            "description": "Exposed Stripe secret key",
            "remediation": "Move to KMS",
            "severity": "CRITICAL",
            "cwe_id": "CWE-798",
            "file_path": "billing.py",
            "line_start": 10,
            "line_end": 10,
            "code_snippet": "stripe_key = 'sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "epss_score": 0.85,
            "epss_percentile": 0.95,
            "composite_risk_score": 92.5,
            "quadrant": "URGENT",
            "urgency": "IMMEDIATE",
            "sla_days": 1,
            "standards": ["ISO-27001:A.8.12"],
            "entropy": 4.62,
            "masked_value": "sk_l****...****6789"
        }

        db.update_scan_results(scan_id, test_proj["id"], [sample_finding])

        findings = db.list_findings(project_id=test_proj["id"])
        self.assertEqual(len(findings), 1)
        saved = findings[0]
        self.assertAlmostEqual(saved["entropy"], 4.62, places=2)
        self.assertEqual(saved["masked_value"], "sk_l****...****6789")

    def test_api_scan_secrets_endpoint(self):
        client = TestClient(app)
        token = create_access_token("admin-id", "admin", "admin")
        headers = {"Authorization": f"Bearer {token}"}

        payload = {
            "content": "ANTHROPIC_KEY = 'sk-ant-api03-abcdef1234567890abcdef1234567890-aBcDeFgH'",
            "filename": "server.py"
        }

        response = client.post("/api/scan/secrets", json=payload, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertGreaterEqual(data["total_secrets"], 1)
        finding = data["findings"][0]
        self.assertEqual(finding["rule_id"], "SEC-ANTH-001")
        self.assertIn("masked_value", finding)
        self.assertIn("entropy", finding)


if __name__ == "__main__":
    unittest.main()
