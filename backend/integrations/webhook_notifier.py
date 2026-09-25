"""
Sentinel AppSec - Enterprise Chat & Webhook Notifier
Dispatches real-time security alerts to Slack, Microsoft Teams, Discord, and Generic Webhooks.
"""

import requests
import json
import hmac
import hashlib
import time
from typing import Dict, Any, List, Optional
from ..db import db


class WebhookNotifier:
    """
    Multi-channel alert dispatcher for security events, scan completions, and critical threat alerts.
    """

    @classmethod
    def get_config(cls) -> Dict[str, Any]:
        cfg = db.get_integration("webhooks")
        if not cfg:
            return {
                "enabled": False,
                "slack_webhook_url": "",
                "teams_webhook_url": "",
                "discord_webhook_url": "",
                "generic_webhook_url": "",
                "generic_secret": "",
                "notify_on_scan_completed": True,
                "notify_on_critical_finding": True,
                "notify_on_cisa_kev": True,
                "min_severity": "HIGH"  # 'CRITICAL', 'HIGH', 'MEDIUM', 'ALL'
            }
        return cfg

    @classmethod
    def save_config(cls, config: Dict[str, Any]) -> Dict[str, Any]:
        db.set_integration("webhooks", config)
        return config

    @classmethod
    def test_webhook(cls, webhook_type: str, webhook_url: str, secret: Optional[str] = "") -> Dict[str, Any]:
        """
        Sends a live test notification or simulated payload preview to the target channel.
        """
        if not webhook_url or not webhook_url.startswith("http"):
            return {
                "success": False,
                "message": "Invalid or missing webhook URL. Must start with http:// or https://",
                "simulated": True
            }

        title = "🧪 Sentinel AppSec - Webhook Connectivity Test"
        message = "This is an automated verification probe from Sentinel AppSec security platform."
        fields = [
            {"title": "Status", "value": "Operational / Connected", "short": True},
            {"title": "Timestamp", "value": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), "short": True}
        ]

        try:
            if webhook_type == "slack":
                payload = cls._build_slack_payload(title, message, fields, severity="LOW", action_url=None)
            elif webhook_type == "teams":
                payload = cls._build_teams_payload(title, message, fields, severity="LOW", action_url=None)
            elif webhook_type == "discord":
                payload = cls._build_discord_payload(title, message, fields, severity="LOW", action_url=None)
            else:
                payload = cls._build_generic_payload("test_event", title, message, fields, severity="LOW", action_url=None)

            headers = {"Content-Type": "application/json"}
            if webhook_type == "generic" and secret:
                body_bytes = json.dumps(payload).encode("utf-8")
                sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
                headers["X-Sentinel-Signature"] = f"sha256={sig}"

            resp = requests.post(webhook_url, json=payload, headers=headers, timeout=6)
            if resp.status_code in (200, 201, 204):
                return {
                    "success": True,
                    "status_code": resp.status_code,
                    "message": f"Successfully delivered test alert to {webhook_type.capitalize()}!"
                }
            else:
                return {
                    "success": False,
                    "status_code": resp.status_code,
                    "message": f"{webhook_type.capitalize()} server responded with HTTP {resp.status_code}: {resp.text[:150]}"
                }
        except Exception as e:
            # Fallback for offline testing or simulated demonstration
            return {
                "success": False,
                "message": f"Webhook dispatch error: {str(e)}",
                "payload_preview": payload if 'payload' in locals() else None
            }

    @classmethod
    def dispatch_scan_completed(cls, project_name: str, project_id: str, summary: Dict[str, Any], server_url: str = "") -> Dict[str, Any]:
        """
        Dispatches scan completion summary across all enabled webhook channels.
        """
        cfg = cls.get_config()
        if not cfg.get("enabled") and not any([cfg.get("slack_webhook_url"), cfg.get("teams_webhook_url"), cfg.get("discord_webhook_url")]):
            return {"dispatched": False, "reason": "Webhooks disabled or unconfigured"}

        crit_count = summary.get("critical", 0)
        high_count = summary.get("high", 0)
        med_count = summary.get("medium", 0)
        low_count = summary.get("low", 0)
        total = crit_count + high_count + med_count + low_count

        severity = "CRITICAL" if crit_count > 0 else ("HIGH" if high_count > 0 else "LOW")
        title = f"🛡️ Sentinel Scan Completed: {project_name}"
        desc = f"Static analysis & software composition audit finished with **{total}** total findings."

        action_url = f"{server_url.rstrip('/')}/?project_id={project_id}" if server_url else None
        fields = [
            {"title": "Project", "value": project_name, "short": True},
            {"title": "Overall Posture", "value": summary.get("posture_score", "78%"), "short": True},
            {"title": "Critical Hazards", "value": f"🚨 {crit_count}", "short": True},
            {"title": "High Severity", "value": f"⚠️ {high_count}", "short": True},
            {"title": "Medium / Low", "value": f"⚡ {med_count} / 🟢 {low_count}", "short": True},
            {"title": "Action Quadrants", "value": f"Act Now: {summary.get('act_now_count', 0)}", "short": True}
        ]

        return cls._fanout_alert("scan_completed", title, desc, fields, severity, action_url, cfg)

    @classmethod
    def dispatch_urgent_threat(cls, finding: Dict[str, Any], server_url: str = "") -> Dict[str, Any]:
        """
        Dispatches an immediate alert when an Act Now or CISA KEV vulnerability is confirmed.
        """
        cfg = cls.get_config()
        if not cfg.get("enabled") and not any([cfg.get("slack_webhook_url"), cfg.get("teams_webhook_url"), cfg.get("discord_webhook_url")]):
            return {"dispatched": False, "reason": "Webhooks disabled"}

        title = f"🚨 URGENT THREAT: {finding.get('title', 'Weaponized Vulnerability Detected')}"
        desc = (
            f"Vulnerability `{finding.get('id', '')}` in `{finding.get('file_path', 'unknown')}` "
            f"has been escalated to **ACT NOW** (CVSS {finding.get('cvss_score', 9.0)}, EPSS {finding.get('epss_score', 0.85)})."
        )
        if finding.get("cisa_kev"):
            desc += "\n⚠️ **Flagged in CISA Known Exploited Vulnerabilities (KEV) Catalog!**"

        action_url = f"{server_url.rstrip('/')}/?finding_id={finding.get('id', '')}" if server_url else None
        fields = [
            {"title": "Code Author", "value": f"{finding.get('author_name', 'Unknown')} <{finding.get('author_email', 'unknown')}>", "short": True},
            {"title": "CWE / Standards", "value": f"{finding.get('cwe_id', 'CWE-Unknown')} | {', '.join(finding.get('standards', [])[:2])}", "short": True},
            {"title": "SLA Deadline", "value": f"{finding.get('sla_days', 2)} days", "short": True},
            {"title": "Location", "value": f"`{finding.get('file_path')}:{finding.get('line_start')}`", "short": True}
        ]

        return cls._fanout_alert("urgent_threat", title, desc, fields, "CRITICAL", action_url, cfg)

    # --- Channel Specific Formatters ---

    @classmethod
    def _build_slack_payload(cls, title: str, desc: str, fields: List[Dict], severity: str, action_url: Optional[str]) -> Dict[str, Any]:
        color_map = {"CRITICAL": "#E63946", "HIGH": "#F4A261", "MEDIUM": "#E9C46A", "LOW": "#2A9D8F"}
        color = color_map.get(severity.upper(), "#457B9D")

        slack_fields = [{"type": "mrkdwn", "text": f"*{f['title']}*:\n{f['value']}"} for f in fields]
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": title[:150], "emoji": True}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": desc}
            },
            {
                "type": "section",
                "fields": slack_fields[:10]
            }
        ]
        if action_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Inspect in Sentinel", "emoji": True},
                        "url": action_url,
                        "style": "primary" if severity in ("CRITICAL", "HIGH") else "default"
                    }
                ]
            })

        return {
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks
                }
            ]
        }

    @classmethod
    def _build_teams_payload(cls, title: str, desc: str, fields: List[Dict], severity: str, action_url: Optional[str]) -> Dict[str, Any]:
        facts = [{"name": f["title"], "value": str(f["value"])} for f in fields]
        theme_color = "E63946" if severity == "CRITICAL" else ("F4A261" if severity == "HIGH" else "2A9D8F")
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": title,
            "sections": [
                {
                    "activityTitle": title,
                    "activitySubtitle": desc,
                    "facts": facts,
                    "markdown": True
                }
            ]
        }
        if action_url:
            payload["potentialAction"] = [
                {
                    "@type": "OpenURI",
                    "name": "View in Sentinel Dashboard",
                    "targets": [{"os": "default", "uri": action_url}]
                }
            ]
        return payload

    @classmethod
    def _build_discord_payload(cls, title: str, desc: str, fields: List[Dict], severity: str, action_url: Optional[str]) -> Dict[str, Any]:
        color_int = 0xE63946 if severity == "CRITICAL" else (0xF4A261 if severity == "HIGH" else 0x2A9D8F)
        discord_fields = [{"name": f["title"], "value": str(f["value"]), "inline": f.get("short", True)} for f in fields]
        embed = {
            "title": title[:256],
            "description": desc[:2048],
            "color": color_int,
            "fields": discord_fields[:25],
            "footer": {"text": "Sentinel AppSec Platform • Automated Guardrail"}
        }
        if action_url:
            embed["url"] = action_url
        return {"embeds": [embed]}

    @classmethod
    def _build_generic_payload(cls, event_type: str, title: str, desc: str, fields: List[Dict], severity: str, action_url: Optional[str]) -> Dict[str, Any]:
        return {
            "event": event_type,
            "title": title,
            "description": desc,
            "severity": severity,
            "fields": {f["title"]: f["value"] for f in fields},
            "action_url": action_url,
            "timestamp": time.time(),
            "source": "Sentinel-AppSec-Engine"
        }

    @classmethod
    def _fanout_alert(cls, event_type: str, title: str, desc: str, fields: List[Dict], severity: str, action_url: Optional[str], cfg: Dict[str, Any]) -> Dict[str, Any]:
        results = {}
        # Slack
        if cfg.get("slack_webhook_url"):
            try:
                p = cls._build_slack_payload(title, desc, fields, severity, action_url)
                r = requests.post(cfg["slack_webhook_url"], json=p, timeout=5)
                results["slack"] = {"status": r.status_code, "ok": r.status_code in (200, 204)}
            except Exception as e:
                results["slack"] = {"error": str(e), "ok": False}

        # Teams
        if cfg.get("teams_webhook_url"):
            try:
                p = cls._build_teams_payload(title, desc, fields, severity, action_url)
                r = requests.post(cfg["teams_webhook_url"], json=p, timeout=5)
                results["teams"] = {"status": r.status_code, "ok": r.status_code in (200, 204)}
            except Exception as e:
                results["teams"] = {"error": str(e), "ok": False}

        # Discord
        if cfg.get("discord_webhook_url"):
            try:
                p = cls._build_discord_payload(title, desc, fields, severity, action_url)
                r = requests.post(cfg["discord_webhook_url"], json=p, timeout=5)
                results["discord"] = {"status": r.status_code, "ok": r.status_code in (200, 204)}
            except Exception as e:
                results["discord"] = {"error": str(e), "ok": False}

        # Generic
        if cfg.get("generic_webhook_url"):
            try:
                p = cls._build_generic_payload(event_type, title, desc, fields, severity, action_url)
                headers = {"Content-Type": "application/json"}
                secret = cfg.get("generic_secret")
                if secret:
                    body_bytes = json.dumps(p).encode("utf-8")
                    sig = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
                    headers["X-Sentinel-Signature"] = f"sha256={sig}"
                r = requests.post(cfg["generic_webhook_url"], json=p, headers=headers, timeout=5)
                results["generic"] = {"status": r.status_code, "ok": r.status_code in (200, 204)}
            except Exception as e:
                results["generic"] = {"error": str(e), "ok": False}

        return {"dispatched": True, "channels": results}
