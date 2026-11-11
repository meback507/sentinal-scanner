"""
AegisSec - Jira Ticketing Integration Connector
Creates Jira Cloud / Server issues from security findings with full vulnerability triage context.
"""

import requests
import base64
from typing import Dict, Any, Optional
from ..db import db


class JiraConnector:
    @classmethod
    def get_config(cls) -> Optional[Dict[str, Any]]:
        return db.get_integration("jira")

    @classmethod
    def test_connection(cls, url: str, email: str, api_token: str) -> Dict[str, Any]:
        try:
            auth_str = f"{email}:{api_token}"
            b64_auth = base64.b64encode(auth_str.encode()).decode()
            headers = {
                "Authorization": f"Basic {b64_auth}",
                "Accept": "application/json"
            }
            clean_url = url.rstrip("/")
            resp = requests.get(f"{clean_url}/rest/api/3/myself", headers=headers, timeout=5)
            if resp.status_code == 200:
                user_data = resp.json()
                return {"success": True, "message": f"Connected to Jira as {user_data.get('displayName')}"}
            else:
                return {"success": False, "message": f"Jira auth failed: HTTP {resp.status_code}"}
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
            # Mock successful creation for demonstration if no live Jira account configured
            mock_key = f"SEC-{finding.get('id', '1')[:4].upper()}"
            return {
                "success": True,
                "ticket_key": mock_key,
                "ticket_url": f"https://mock-jira.internal/browse/{mock_key}",
                "assigned_to": assigned_to,
                "assigned_email": assigned_email,
                "assignee": assigned_to,
                "is_mock": True
            }

        url = cfg.get("url", "").rstrip("/")
        email = cfg.get("email", "")
        token = cfg.get("api_token", "")
        project_key = cfg.get("project_key", "SEC")
        issue_type = cfg.get("issue_type", "Bug")

        auth_str = f"{email}:{token}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {b64_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        severity_map = {
            "CRITICAL": "Highest",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low"
        }

        description_text = f"""
*AegisSec Security Finding Alert*
*Title:* {finding.get('title')}
*Type:* {finding.get('type', '').upper()}
*Severity:* {finding.get('severity')} (CVSS: {finding.get('cvss_score')}, EPSS: {finding.get('epss_score')})
*Quadrant:* {finding.get('quadrant')} (SLA: {finding.get('sla_days')} days)
*File / Location:* {finding.get('file_path')}:{finding.get('line_start')}
*Developer / Committer (Assigned):* {assigned_to} <{assigned_email}> (Commit: {finding.get('commit_hash', 'HEAD')} on {finding.get('commit_date', 'N/A')})
*Standards:* {', '.join(finding.get('standards', []))}

*Description:*
{finding.get('description')}

*Code Snippet:*
{{code}}
{finding.get('code_snippet')}
{{code}}

*Remediation Guidance:*
{finding.get('remediation')}
"""

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": f"[AegisSec] {finding.get('title')} ({assigned_to})",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": description_text}]
                        }
                    ]
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": severity_map.get(finding.get("severity"), "Medium")},
                "labels": ["aegissec", "appsec", finding.get("type", "vuln"), f"author-{assigned_to.replace(' ', '_').lower()}"]
            }
        }

        # Assign ticket directly to the matched person / code author
        if assigned_email and assigned_email != "unknown@domain.local":
            payload["fields"]["assignee"] = {"name": assigned_to, "emailAddress": assigned_email}

        try:
            resp = requests.post(f"{url}/rest/api/3/issue", json=payload, headers=headers, timeout=10)
            if resp.status_code in (200, 201):
                data = resp.json()
                key = data.get("key")
                return {
                    "success": True,
                    "ticket_key": key,
                    "ticket_url": f"{url}/browse/{key}",
                    "assigned_to": assigned_to,
                    "assigned_email": assigned_email,
                    "assignee": assigned_to,
                    "is_mock": False
                }
            else:
                return {"success": False, "message": f"Jira API error {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"success": False, "message": f"Jira dispatch error: {str(e)}"}
