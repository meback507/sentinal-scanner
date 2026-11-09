"""
Sentinel AppSec & ThreatGate CLI Integration Tests
Validates command-line invocations, argument handling, and structured JSON output.
"""

import subprocess
import sys
import json
import pytest


def test_cli_list_rules_json():
    cmd = [sys.executable, "scripts/sentinel_cli.py", "list-rules", "--json"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    catalog = json.loads(proc.stdout)
    assert "summary" in catalog
    assert catalog["summary"]["total_active_rules"] > 0


def test_cli_threatgate_verify_pr():
    cmd = [sys.executable, "scripts/sentinel_cli.py", "verify-pr"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "ThreatGate Fast-Path CI Verification" in proc.stdout
    assert "APPROVED" in proc.stdout


def test_cli_threat_graph():
    cmd = [sys.executable, "scripts/sentinel_cli.py", "threat-graph", "src/payments/refund.py"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert "flowchart LR" in proc.stdout
    assert "refund_py" in proc.stdout


def test_threatgate_module_cli_help():
    cmd = [sys.executable, "-m", "src.threatgate.cli", "--help"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert "ThreatGate" in proc.stdout
    assert "verify-pr" in proc.stdout
    assert "graph" in proc.stdout

