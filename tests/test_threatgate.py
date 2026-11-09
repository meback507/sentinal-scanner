"""
ThreatGate End-to-End Cryptographic & Verification Test Suite
Tests Ed25519 signing, code digest binding, tamper resistance, and delta calculations.
"""

import os
import shutil
import tempfile
from pathlib import Path
import pytest

from src.threatgate.core.crypto import (
    generate_keypair,
    sign_payload,
    verify_payload,
    extract_seal_from_markdown,
    embed_seal_into_markdown
)
from src.threatgate.core.engine import ThreatEngine
from src.threatgate.core.delta import compute_delta, parse_threats_from_markdown
from src.threatgate.core.test_gen import generate_security_regression_test


def test_ed25519_keypair_generation():
    priv, pub = generate_keypair()
    assert b"BEGIN PRIVATE KEY" in priv
    assert b"BEGIN PUBLIC KEY" in pub


def test_signature_and_tamper_detection():
    priv, pub = generate_keypair()
    code = "def get_profile(user_id):\n    return db.query(user_id)\n"
    report = "# Threat Model: profile.py\nStatus: APPROVED\n"

    # 1. Valid Signature
    sig = sign_payload(code, report, priv)
    assert verify_payload(code, report, sig, pub) is True

    # 2. Tampered Source Code (1 single character change)
    tampered_code = "def get_profile(user_id):\n    return db.query(user_id) # extra\n"
    assert verify_payload(tampered_code, report, sig, pub) is False

    # 3. Tampered Report
    tampered_report = "# Threat Model: profile.py\nStatus: FORGED\n"
    assert verify_payload(code, tampered_report, sig, pub) is False

    # 4. Wrong Public Key
    _, wrong_pub = generate_keypair()
    assert verify_payload(code, report, sig, wrong_pub) is False


def test_threat_engine_dfd_graph_generation():
    engine = ThreatEngine()
    code = """
from fastapi import FastAPI, Depends
app = FastAPI()

@app.post("/refund")
def process_refund(transaction_id: str, amount: float):
    # Missing caller ownership check
    return {"status": "ok", "txn": transaction_id}
"""
    report = engine.evaluate_code("refund.py", code)
    assert report.is_approved is False  # BOLA on transaction_id detected
    assert len(report.threats) > 0
    assert report.dfd_mermaid is not None
    assert "flowchart LR" in report.dfd_mermaid
    assert "Untrusted External Zone" in report.dfd_mermaid
    assert report.graph_nodes is not None
    assert len(report.graph_nodes) >= 3


def test_mitigated_code_approval_and_sealing():
    engine = ThreatEngine()
    priv, pub = generate_keypair()

    mitigated_code = """
from fastapi import FastAPI, Depends, HTTPException
app = FastAPI()

@app.post("/refund")
def process_refund(transaction_id: str, amount: float, user: UserModel = Depends(get_current_user)):
    txn = db.query(Transaction).filter_by(id=transaction_id, user_id=user.id).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Not found")
    return {"status": "refunded", "txn": transaction_id}
"""
    report = engine.evaluate_code("refund.py", mitigated_code)
    assert report.is_approved is True

    # Format and sign
    markdown_doc = engine.format_threat_model_markdown("refund.py", report, mitigated_code)
    sig = sign_payload(mitigated_code, markdown_doc, priv)
    sealed_md = embed_seal_into_markdown(markdown_doc, sig)

    # Extract and verify
    body, extracted_sig = extract_seal_from_markdown(sealed_md)
    assert extracted_sig == sig
    assert verify_payload(mitigated_code, body, extracted_sig, pub) is True


def test_threat_delta_computation():
    baseline_md = """
| Threat ID | STRIDE Category | Severity | Element | Status |
| :--- | :--- | :--- | :--- | :--- |
| TH-01 | Elevation of Privilege | HIGH | transaction_id | ❌ Open (HIGH) |
"""
    current_md = """
| Threat ID | STRIDE Category | Severity | Element | Status |
| :--- | :--- | :--- | :--- | :--- |
| TH-01 | Elevation of Privilege | HIGH | transaction_id | ✅ Mitigated |
"""
    delta = compute_delta(baseline_md, current_md)
    assert delta.is_pr_acceptable is True
    assert len(delta.neutralized_threats) == 1
    assert "TH-01" in delta.neutralized_threats[0]
    assert len(delta.new_unmitigated_threats) == 0


def test_security_regression_test_generation():
    engine = ThreatEngine()
    code = "def check_auth(user): return user.is_authenticated"
    report = engine.evaluate_code("auth.py", code)
    threat = report.threats[0]

    with tempfile.TemporaryDirectory() as tmp_dir:
        test_path = generate_security_regression_test(threat, output_dir=tmp_dir)
        assert test_path.exists()
        content = test_path.read_text(encoding="utf-8")
        assert "def test_" in content
        assert "pytest" in content

