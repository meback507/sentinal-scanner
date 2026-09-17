"""
Unit tests for Developer Attribution and Git Blame tracking.
"""

import os
import shutil
import tempfile
import subprocess
import unittest
from backend.git_service import GitService
from backend.scanners.sast_engine import SASTEngine


class TestDeveloperAttribution(unittest.TestCase):
    def setUp(self):
        self.repo_dir = tempfile.mkdtemp(prefix="test_blame_repo_")
        # Initialize Git repository
        subprocess.run(["git", "init"], cwd=self.repo_dir, check=True, capture_output=True)

        # Developer 1: Alice Chen
        subprocess.run(["git", "config", "user.name", "Alice Chen"], cwd=self.repo_dir, check=True)
        subprocess.run(["git", "config", "user.email", "alice.chen@enterprise.com"], cwd=self.repo_dir, check=True)
        with open(os.path.join(self.repo_dir, "vuln_service.py"), "w") as f:
            f.write("API_KEY = 'sk_live_123456789012345678'\n")
        subprocess.run(["git", "add", "vuln_service.py"], cwd=self.repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "feat: hardcoded credentials"], cwd=self.repo_dir, check=True)

        # Developer 2: Bob Smith
        subprocess.run(["git", "config", "user.name", "Bob Smith"], cwd=self.repo_dir, check=True)
        subprocess.run(["git", "config", "user.email", "bob.smith@enterprise.com"], cwd=self.repo_dir, check=True)
        with open(os.path.join(self.repo_dir, "vuln_service.py"), "a") as f:
            f.write("def run_cmd(c):\n    eval(c)\n")
        subprocess.run(["git", "add", "vuln_service.py"], cwd=self.repo_dir, check=True)
        subprocess.run(["git", "commit", "-m", "feat: dynamic eval logic"], cwd=self.repo_dir, check=True)

    def tearDown(self):
        shutil.rmtree(self.repo_dir, ignore_errors=True)

    def test_git_blame_line_attribution(self):
        # Line 1 was written by Alice Chen
        blame_line_1 = GitService.get_line_blame(self.repo_dir, "vuln_service.py", 1)
        self.assertEqual(blame_line_1["author_name"], "Alice Chen")
        self.assertEqual(blame_line_1["author_email"], "alice.chen@enterprise.com")
        self.assertIn("hardcoded", blame_line_1["commit_message"])

        # Line 3 was written by Bob Smith
        blame_line_3 = GitService.get_line_blame(self.repo_dir, "vuln_service.py", 3)
        self.assertEqual(blame_line_3["author_name"], "Bob Smith")
        self.assertEqual(blame_line_3["author_email"], "bob.smith@enterprise.com")
        self.assertIn("eval", blame_line_3["commit_message"])

    def test_sast_findings_with_blame_enrichment(self):
        sast = SASTEngine()
        findings = sast.scan_directory(self.repo_dir)
        self.assertGreaterEqual(len(findings), 2)

        for f in findings:
            blame = GitService.get_line_blame(self.repo_dir, f["file_path"], f["line_start"])
            f["author_name"] = blame["author_name"]
            f["author_email"] = blame["author_email"]
            f["commit_hash"] = blame["commit_hash"]

        authors = [f["author_name"] for f in findings]
        self.assertIn("Alice Chen", authors)
        self.assertIn("Bob Smith", authors)


if __name__ == "__main__":
    unittest.main()
