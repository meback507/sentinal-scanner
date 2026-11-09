"""
AegisSec CI Quality Gate Unit Test Suite
Validates policy enforcement, ASIL-D / MISRA compliance checks, ThreatGate cryptographic seal verification, and PR markdown comment generation.
"""

import os
import tempfile
import pytest
from backend.ci.quality_gate import CIQualityGate
from src.threatgate.core.crypto import generate_keypair, sign_payload, embed_seal_into_markdown


def test_quality_gate_passes_clean_findings():
    findings = [
        {
            "id": "SEC-001",
            "title": "Low Severity Deprecation Warning",
            "file_path": "src/utils.py",
            "severity": "LOW",
            "quadrant": "ROUTINE",
            "cvss_score": 2.5,
            "epss_score": 0.01,
            "standards": ["CWE-398"]
        }
    ]
    result = CIQualityGate.evaluate(findings, strict_mode=False)
    assert result["passed"] is True
    assert result["status"] == "PASSED"
    assert result["exit_code"] == 0
    assert len(result["blockers"]) == 0
    assert "✅" in result["pr_comment_markdown"]


def test_quality_gate_blocks_act_now_exploit():
    findings = [
        {
            "id": "INJ-001",
            "title": "SQL Injection in User Login",
            "file_path": "src/auth/login.py",
            "severity": "CRITICAL",
            "quadrant": "ACT_NOW",
            "cvss_score": 9.8,
            "epss_score": 0.65,
            "standards": ["OWASP:A03:2021", "CWE-89"]
        }
    ]
    result = CIQualityGate.evaluate(findings)
    assert result["passed"] is False
    assert result["status"] == "FAILED"
    assert result["exit_code"] == 1
    assert len(result["blockers"]) >= 1
    assert result["blockers"][0]["reason"] == "ACT_NOW_EXPLOIT"
    assert "⚠️ Merge Blocked by Security Policy" in result["pr_comment_markdown"]


def test_quality_gate_blocks_asil_d_violation():
    findings = [
        {
            "id": "MISRA-001",
            "title": "Dynamic Memory Allocation in Steering Loop",
            "file_path": "src/ecu/steering.c",
            "severity": "CRITICAL",
            "quadrant": "CRITICAL_PATCH",
            "cvss_score": 8.0,
            "epss_score": 0.02,
            "standards": ["ISO-26262:ASIL-D", "MISRA-C:2012:Rule-21.3"]
        }
    ]
    result = CIQualityGate.evaluate(findings)
    assert result["passed"] is False
    assert any(b["reason"] == "SAFETY_STANDARDS_VIOLATION" for b in result["blockers"])


def test_quality_gate_threatgate_seal_verification():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create .threatmodel with keys
        tm_dir = os.path.join(tmpdir, ".threatmodel")
        os.makedirs(tm_dir, exist_ok=True)
        priv_pem, pub_pem = generate_keypair()
        with open(os.path.join(tm_dir, "public_key.pem"), "wb") as f:
            f.write(pub_pem)
        with open(os.path.join(tm_dir, "private_key.pem"), "wb") as f:
            f.write(priv_pem)

        # Create code file and threat model
        code_file = os.path.join(tmpdir, "wallet.py")
        code_content = "def transfer(amount):\n    print('transferring', amount)\n"
        with open(code_file, "w") as f:
            f.write(code_content)

        threat_file = os.path.join(tmpdir, "wallet.threat.md")
        base_threat_md = "# Threat Model for wallet.py\n\nNo threats."
        seal = sign_payload(code_content, base_threat_md, priv_pem)
        sealed_md = embed_seal_into_markdown(base_threat_md, seal)
        with open(threat_file, "w") as f:
            f.write(sealed_md)

        # Valid seal check
        valid_res = CIQualityGate.evaluate([], repo_path=tmpdir)
        assert valid_res["passed"] is True

        # Now tamper with code
        with open(code_file, "w") as f:
            f.write("def transfer(amount):\n    # TAMPERED UNREVIEWED CODE\n    transfer_all_funds()\n")

        tampered_res = CIQualityGate.evaluate([], repo_path=tmpdir)
        assert tampered_res["passed"] is False
        assert any(b["reason"] == "THREATGATE_SEAL_INVALID" for b in tampered_res["blockers"])

