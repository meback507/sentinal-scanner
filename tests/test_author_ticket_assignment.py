"""
Sentinel AppSec - Author Blame & Ticket Direct Assignment Unit Test Suite
Validates that:
1. Git blame extracts the actual code committer from git, avoiding AppSec platform administrators or bot handles.
2. If a registered user has the same email address as the git committer, tickets and findings are directly assigned to that person.
"""

import os
import uuid
import pytest
from backend.git_service import GitService
from backend.db import db
from backend.integrations.jira_connector import JiraConnector
from backend.integrations.zammad_connector import ZammadConnector
from backend.integrations.issue_trackers import IssueTrackerManager


def test_git_blame_fetches_code_committer_not_appsec():
    # Test blame on a file authored by a developer in this repository
    blame = GitService.get_line_blame(".", "src/payments/refund.py", line_no=15)
    assert blame is not None
    assert blame["author_name"] != "DevOps Engineer"
    assert blame["author_email"] != "devops@internal.net"
    assert blame["author_name"] != "AegisSec Admin"
    assert blame["author_email"] != "admin@aegissec.internal"
    assert "ARAVIND ANIL" in blame["author_name"]
    assert ("mewithbackup@gmail.com" in blame["author_email"] or "aravindnil" in blame["author_email"])


def test_git_blame_clamps_out_of_bounds_line():
    # Line 9999 exceeds file length, should clamp to file length without throwing 128 error
    blame = GitService.get_line_blame(".", "src/payments/refund.py", line_no=9999)
    assert blame is not None
    assert blame["author_name"] != "DevOps Engineer"
    assert "ARAVIND ANIL" in blame["author_name"]


def test_db_get_user_by_email():
    # Create a test developer user with a specific email
    unique_email = f"developer_{uuid.uuid4().hex[:6]}@company.com"
    username = f"dev_{uuid.uuid4().hex[:6]}"
    created = db.create_user(username, unique_email, "SecurePassword123!", "developer")
    assert created["email"] == unique_email

    # Lookup user by email (case-insensitive)
    found = db.get_user_by_email(unique_email.upper())
    assert found is not None
    assert found["username"] == username
    assert found["email"] == unique_email

    # Non-existent email returns None
    assert db.get_user_by_email("nonexistent_user_xyz@company.com") is None


def test_jira_ticket_directly_assigned_to_person_with_matching_email():
    dev_email = f"committer_{uuid.uuid4().hex[:6]}@engineering.org"
    dev_username = f"committer_{uuid.uuid4().hex[:6]}"
    db.create_user(dev_username, dev_email, "Password123!", "developer")

    finding = {
        "id": "FINDING-001",
        "title": "SQL Injection in User Login",
        "severity": "CRITICAL",
        "file_path": "src/auth.py",
        "line_start": 25,
        "author_name": "Original Committer Name",
        "author_email": dev_email,
        "commit_hash": "a1b2c3d4",
        "standards": ["OWASP:A03:2021"]
    }

    # Create ticket via JiraConnector
    res = JiraConnector.create_ticket(finding)
    assert res["success"] is True
    # The ticket must be assigned directly to the registered person with that email
    assert res["assigned_to"] == dev_username
    assert res["assigned_email"] == dev_email
    assert res["assignee"] == dev_username


def test_zammad_ticket_directly_assigned_to_person_with_matching_email():
    dev_email = f"dev_{uuid.uuid4().hex[:6]}@company.net"
    dev_username = f"dev_{uuid.uuid4().hex[:6]}"
    db.create_user(dev_username, dev_email, "Password123!", "developer")

    finding = {
        "id": "FINDING-002",
        "title": "Hardcoded AWS Secret Key",
        "severity": "HIGH",
        "file_path": "config/aws.py",
        "line_start": 10,
        "author_name": "Unknown Git Author",
        "author_email": dev_email,
        "commit_hash": "c5d6e7f8"
    }

    res = ZammadConnector.create_ticket(finding)
    assert res["success"] is True
    assert res["assigned_to"] == dev_username
    assert res["assigned_email"] == dev_email


def test_issue_tracker_directly_assigned_to_person_with_matching_email():
    dev_email = f"tracker_dev_{uuid.uuid4().hex[:6]}@company.net"
    dev_username = f"tracker_dev_{uuid.uuid4().hex[:6]}"
    db.create_user(dev_username, dev_email, "Password123!", "developer")

    finding = {
        "id": "FINDING-003",
        "title": "Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "file_path": "frontend/render.js",
        "line_start": 5,
        "author_name": "Frontend Committer",
        "author_email": dev_email
    }

    manager = IssueTrackerManager()
    res = manager.create_ticket(finding, provider="jira")
    assert res["assigned_to"] == dev_username
    assert res["assigned_email"] == dev_email


def test_dast_finding_attributes_to_git_committer_not_devops():
    # Dynamic endpoint findings have URL file paths (e.g. http://127.0.0.1:8000:1)
    # They should resolve directly to the repository Git committer, never 'DevOps Engineer'
    blame = GitService.get_line_blame(".", "http://127.0.0.1:8000:1", line_no=1)
    assert blame is not None
    assert blame["author_name"] != "DevOps Engineer"
    assert blame["author_email"] != "devops@internal.net"
    assert blame["author_name"] != "AegisSec Admin"
    assert "ARAVIND ANIL" in blame["author_name"]
    assert ("mewithbackup@gmail.com" in blame["author_email"] or "aravindnil" in blame["author_email"])


def test_reconcile_finding_authors_fixes_placeholder_records():
    # Insert a finding with stale 'DevOps Engineer' / 'devops@internal.net' author
    proj_name = f"Test_Reconcile_{uuid.uuid4().hex[:6]}"
    created_proj = db.create_project(proj_name, "Desc", ".", "main", "", "admin")
    p_id = created_proj["id"]

    stale_fid = f"FINDING-STALE-{uuid.uuid4().hex[:6]}"
    db.create_finding({
        "id": stale_fid,
        "project_id": p_id,
        "type": "dast",
        "title": "Missing Referrer-Policy Header",
        "file_path": "http://127.0.0.1:8000:1",
        "author_name": "DevOps Engineer",
        "author_email": "devops@internal.net",
        "commit_hash": "HEAD"
    })

    # Run author reconciliation
    db.reconcile_finding_authors()

    # Verify that the finding was retroactively updated to the true Git committer
    f_updated = db.get_finding_by_id(stale_fid)
    assert f_updated is not None
    assert f_updated["author_name"] != "DevOps Engineer"
    assert f_updated["author_email"] != "devops@internal.net"
    assert "ARAVIND ANIL" in f_updated["author_name"]
    assert ("mewithbackup@gmail.com" in f_updated["author_email"] or "aravindnil" in f_updated["author_email"])

