"""
AegisSec - Zammad Helpdesk & Ticketing Integration Connector
Dispatches security findings to Zammad instances via REST API.
"""

import requests
from typing import Dict, Any, Optional
from ..db import db


class ZammadConnector:
    @classmethod
    def get_config(cls) -> Optional[Dict[str, Any]]:
        return db.get_integration("zammad")

    @classmethod
    def test_connection(cls, url: str, api_token: str) -> Dict[str, Any]:
        try:
            clean_url = url.rstrip("/")
            headers = {
                "Authorization": f"Token token={api_token}",
                "Content-Type": "application/json"
            }
            resp = requests.get(f"{clean_url}/api/v1/users/me", headers=headers, timeout=5)
            if resp.status_code == 200:
                user_info = resp.json()
                return {"success": True, "message": f"Connected to Zammad as {user_info.get('email')}"}
            else:
                return {"success": False, "message": f"Zammad auth failed: HTTP {resp.status_code}"}
        except Exception as e:
            return {"success": False, "message": f"Connection error: {str(e)}"}

    @classmethod
    def create_ticket(
        cls,
        finding: Dict[str, Any],
        assignee_name: Optional[str] = None,
        assignee_email: Optional[str] = None
    ) -> Dict[str, Any]:
        author_email = finding.get("author_email") or ""
        author_name = finding.get("author_name") or "Developer"

        # Check if a user with the same email exists in the platform to assign ticket directly to them
        if not assignee_email and author_email:
            matched_user = db.get_user_by_email(author_email)
            if matched_user:
                assignee_name = matched_user.get("username")
                assignee_email = matched_user.get("email")

        assigned_to = assignee_name or finding.get("ticket_assigned_to") or author_name
        assigned_email = assignee_email or finding.get("ticket_assigned_email") or author_email or "unknown@domain.local"

        cfg = cls.get_config()
        if not cfg or not cfg.get("enabled"):
            mock_id = f"ZAM-{finding.get('id', '1')[:4].upper()}"
            return {
                "success": True,
                "ticket_key": mock_id,
                "ticket_url": f"https://mock-zammad.internal/#ticket/zoom/{mock_id}",
                "assigned_to": assigned_to,
                "assigned_email": assigned_email,
                "assignee": assigned_to,
                "is_mock": True
            }

        url = cfg.get("url", "").rstrip("/")
        token = cfg.get("api_token", "")
        group = cfg.get("group", "Users")

        headers = {
            "Authorization": f"Token token={token}",
            "Content-Type": "application/json"
        }

        # Zammad priorities: 1: low, 2: normal, 3: high
        priority_map = {
            "CRITICAL": 3,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }

        body_text = f"""
Vulnerability Finding: {finding.get('title')}
Severity: {finding.get('severity')} | CVSS: {finding.get('cvss_score')} | EPSS: {finding.get('epss_score')}
Composite Risk: {finding.get('composite_risk_score')} / 100 ({finding.get('quadrant')})
Location: {finding.get('file_path')}:{finding.get('line_start')}
Developer / Committer (Assigned): {assigned_to} <{assigned_email}> (Commit: {finding.get('commit_hash', 'HEAD')})
Standards Compliance: {', '.join(finding.get('standards', []))}

Description:
{finding.get('description')}

Code Context:
{finding.get('code_snippet')}

Remediation Action:
{finding.get('remediation')}
"""

        payload = {
            "title": f"[AegisSec] {finding.get('title')} ({assigned_to})",
            "group": group,
            "customer": assigned_email,
            "owner": assigned_email,
            "priority_id": priority_map.get(finding.get("severity"), 2),
            "article": {
                "subject": f"[AegisSec] {finding.get('title')}",
                "body": body_text,
                "type": "note",
                "internal": False
            }
        }

        try:
            resp = requests.post(f"{url}/api/v1/tickets", json=payload, headers=headers, timeout=10)
            if resp.status_code in (200, 201):
                data = resp.json()
                t_id = str(data.get("id"))
                return {
                    "success": True,
                    "ticket_key": t_id,
                    "ticket_url": f"{url}/#ticket/zoom/{t_id}",
                    "assigned_to": assigned_to,
                    "assigned_email": assigned_email,
                    "assignee": assigned_to,
                    "is_mock": False
                }
            else:
                return {"success": False, "message": f"Zammad API error {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"success": False, "message": f"Zammad dispatch error: {str(e)}"}
