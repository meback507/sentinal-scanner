"""
Unit tests for SAST and SCA Scanning Engines.
"""

import os
import shutil
import tempfile
import unittest
from backend.scanners.sast_engine import SASTEngine
from backend.scanners.sca_engine import SCAEngine


class TestScanners(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_scanner_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_sast_python_vulnerabilities(self):
        py_code = """
import sqlite3
import pickle

API_KEY = "sk_live_9999888877776666"

def login(user):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
    eval("print('debug')")
    pickle.loads(b"cos\\nsystem\\n(S'id'\\ntR.")
"""
        file_path = os.path.join(self.test_dir, "vuln.py")
        with open(file_path, "w") as f:
            f.write(py_code)

        sast = SASTEngine()
        findings = sast.scan_directory(self.test_dir)
        rule_ids = [f["rule_id"] for f in findings]

        # Verify detection
        self.assertIn("SEC-001", rule_ids)  # Hardcoded secret
        self.assertIn("INJ-001", rule_ids)  # SQL injection
        self.assertIn("PY-AST-001", rule_ids)  # eval() AST check
        self.assertIn("DES-001", rule_ids)  # pickle deserialization

        # Verify standards mapping
        sqli_finding = next(f for f in findings if f["rule_id"] == "INJ-001")
        self.assertTrue(any("OWASP:A03" in s for s in sqli_finding["standards"]))

    def test_sast_automotive_misra_c(self):
        c_code = """
#include <stdlib.h>
#include <string.h>

void run_ecu(const char* input) {
    char* mem = (char*)malloc(100);
    strcpy(mem, input);
    free(mem);
}
"""
        file_path = os.path.join(self.test_dir, "ecu.c")
        with open(file_path, "w") as f:
            f.write(c_code)

        sast = SASTEngine()
        findings = sast.scan_directory(self.test_dir)
        rule_ids = [f["rule_id"] for f in findings]

        # Verify MISRA and buffer violations
        self.assertIn("MISRA-001", rule_ids)
        self.assertIn("MISRA-002", rule_ids)

        misra_finding = next(f for f in findings if f["rule_id"] == "MISRA-001")
        self.assertTrue(any("ISO-26262" in s for s in misra_finding["standards"]))
        self.assertTrue(any("MISRA" in s for s in misra_finding["standards"]))

    def test_sca_dependencies_and_licenses(self):
        pkg_json = """{
  "dependencies": {
    "lodash": "4.17.15",
    "gpl-sample": "1.0.0"
  }
}"""
        with open(os.path.join(self.test_dir, "package.json"), "w") as f:
            f.write(pkg_json)

        sca = SCAEngine()
        res = sca.scan_directory(self.test_dir)
        findings = res["findings"]

        # Check CVE-2021-23337 detection on lodash
        cves = [f.get("cve_id") for f in findings if f.get("cve_id")]
        self.assertIn("CVE-2021-23337", cves)

        # Check ISO-5230 OpenChain restricted license detection
        lic_findings = [f for f in findings if f.get("rule_id") == "SCA-LIC-RESTRICTED"]
        self.assertGreater(len(lic_findings), 0)


if __name__ == "__main__":
    unittest.main()
