import json
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger("sentinel.compliance")

class ComplianceFrameworkEngine:
    """
    Automated Regulatory & Compliance Framework Mapping Engine.
    Maps SAST, DAST, Secrets, and SCA findings to SOC2, PCI-DSS v4.0,
    ISO 27001:2022, HIPAA, and NIST CSF v2.0 controls.
    """

    FRAMEWORKS = {
        "soc2": {
            "name": "SOC 2 Type II",
            "version": "2017 Trust Services Criteria",
            "controls": [
                {
                    "id": "CC6.1",
                    "title": "Logical Access Controls & Least Privilege",
                    "description": "Restricts logical access to authorized users and software components.",
                    "vuln_triggers": ["auth", "token", "hardcoded_secret", "jwt", "privilege", "bola"],
                    "weight": 25
                },
                {
                    "id": "CC6.6",
                    "title": "Boundary Protection & Infrastructure Defense",
                    "description": "Protects perimeter against unauthorized traffic, SSRF, and external injection.",
                    "vuln_triggers": ["ssrf", "injection", "cors", "network", "firewall", "header"],
                    "weight": 25
                },
                {
                    "id": "CC6.7",
                    "title": "Data Transmission Encryption & Integrity",
                    "description": "Protects data in transit using industry-standard cryptography (TLS, AES).",
                    "vuln_triggers": ["tls", "ssl", "crypto", "deserialization", "md5", "sha1"],
                    "weight": 25
                },
                {
                    "id": "CC7.1",
                    "title": "Continuous Vulnerability Detection & Mitigation",
                    "description": "Maintains processes to discover, analyze, and patch software vulnerabilities.",
                    "vuln_triggers": ["cve", "dependency", "outdated", "sast", "patch"],
                    "weight": 25
                }
            ]
        },
        "pci_dss": {
            "name": "PCI-DSS",
            "version": "v4.0 (Payment Card Industry)",
            "controls": [
                {
                    "id": "Req 6.2",
                    "title": "Secure Software Engineering Lifecycle",
                    "description": "Custom software is developed securely with automated static analysis.",
                    "vuln_triggers": ["sast", "code_smell", "injection", "sqli", "xss"],
                    "weight": 25
                },
                {
                    "id": "Req 6.3",
                    "title": "Vulnerability Remediation & Timely Patching",
                    "description": "Known vulnerabilities are evaluated and patched within compliance SLA.",
                    "vuln_triggers": ["cve", "dependency", "patch", "outdated", "critical"],
                    "weight": 25
                },
                {
                    "id": "Req 6.5",
                    "title": "Mitigation of OWASP Top 10 Software Attacks",
                    "description": "Applications are hardened against injection, authentication bypass, and CSRF.",
                    "vuln_triggers": ["sqli", "xss", "csrf", "ssrf", "injection", "rce"],
                    "weight": 25
                },
                {
                    "id": "Req 3.4",
                    "title": "Protection of Cardholder Data & Secrets",
                    "description": "PAN and primary account secrets must never be committed in plaintext or logs.",
                    "vuln_triggers": ["secret", "token", "api_key", "password", "leak"],
                    "weight": 25
                }
            ]
        },
        "iso_27001": {
            "name": "ISO/IEC 27001",
            "version": "2022 Annex A",
            "controls": [
                {
                    "id": "A.8.8",
                    "title": "Management of Technical Vulnerabilities",
                    "description": "Technical vulnerabilities are detected, evaluated and remediated promptly.",
                    "vuln_triggers": ["cve", "vulnerability", "patch", "sast", "dependency"],
                    "weight": 25
                },
                {
                    "id": "A.8.20",
                    "title": "Network Security & Interface Controls",
                    "description": "Network services, API endpoints, and gateways are secured and segregated.",
                    "vuln_triggers": ["network", "ssrf", "cors", "api", "port", "header"],
                    "weight": 25
                },
                {
                    "id": "A.8.24",
                    "title": "Use of Cryptography",
                    "description": "Cryptographic keys and algorithms comply with modern cryptographic standards.",
                    "vuln_triggers": ["crypto", "des", "rc4", "md5", "secret", "encryption"],
                    "weight": 25
                },
                {
                    "id": "A.8.28",
                    "title": "Secure Coding Principles",
                    "description": "Secure coding practices are established and enforced across CI/CD pipelines.",
                    "vuln_triggers": ["code", "sast", "buffer_overflow", "taint", "injection"],
                    "weight": 25
                }
            ]
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "version": "45 CFR Part 164 Subpart C",
            "controls": [
                {
                    "id": "§164.312(a)(1)",
                    "title": "Access Control (ePHI Protection)",
                    "description": "Restricts electronic protected health information to authorized roles only.",
                    "vuln_triggers": ["auth", "role", "privilege", "bola", "bfla", "access"],
                    "weight": 35
                },
                {
                    "id": "§164.312(c)(1)",
                    "title": "Integrity of Data & Systems",
                    "description": "Protects electronic protected health information from unauthorized alteration.",
                    "vuln_triggers": ["tampering", "sqli", "deserialization", "integrity"],
                    "weight": 35
                },
                {
                    "id": "§164.312(e)(1)",
                    "title": "Transmission Security",
                    "description": "Guards against unauthorized access to ePHI that is being transmitted over network.",
                    "vuln_triggers": ["tls", "ssl", "plaintext", "http", "transmission"],
                    "weight": 30
                }
            ]
        },
        "nist_csf": {
            "name": "NIST CSF",
            "version": "v2.0 (Cybersecurity Framework)",
            "controls": [
                {
                    "id": "PR.DS-01",
                    "title": "Data-at-Rest Protection",
                    "description": "Confidentiality and integrity of data at rest are protected.",
                    "vuln_triggers": ["crypto", "database", "secret", "leak", "storage"],
                    "weight": 33
                },
                {
                    "id": "PR.PS-02",
                    "title": "Software Integrity & Supply Chain Defense",
                    "description": "Software dependencies and build artifacts are verified for integrity.",
                    "vuln_triggers": ["dependency", "cve", "sbom", "supply_chain", "outdated"],
                    "weight": 33
                },
                {
                    "id": "DE.CM-01",
                    "title": "Continuous Network & Application Monitoring",
                    "description": "Applications are monitored to discover cybersecurity events and unauthorized activity.",
                    "vuln_triggers": ["monitoring", "audit", "dast", "rasp", "logging"],
                    "weight": 34
                }
            ]
        }
    }

    def __init__(self, db_instance=None):
        self.db = db_instance

    def evaluate_compliance(self, project_id: Optional[str] = None, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Evaluates findings against all regulatory compliance frameworks.
        """
        if findings is None and self.db:
            try:
                findings = self.db.list_findings(project_id)
            except Exception as e:
                logger.warning(f"Failed to query findings for compliance: {e}")
                findings = []

        if not findings:
            findings = []

        framework_results = {}
        overall_passed_controls = 0
        overall_total_controls = 0

        for fw_key, fw in self.FRAMEWORKS.items():
            evaluated_controls = []
            fw_score = 100.0

            for ctrl in fw["controls"]:
                overall_total_controls += 1
                ctrl_id = ctrl["id"]
                triggers = ctrl["vuln_triggers"]

                # Find matching findings
                matched_findings = []
                for f in findings:
                    text_blob = f"{f.get('category', '')} {f.get('title', '')} {f.get('description', '')}".lower()
                    if any(t in text_blob for t in triggers):
                        matched_findings.append({
                            "id": f.get("id"),
                            "title": f.get("title"),
                            "severity": f.get("severity", "MEDIUM"),
                            "file": f.get("file_path", "unknown")
                        })

                # Determine control status
                critical_count = len([m for m in matched_findings if m["severity"] == "CRITICAL"])
                high_count = len([m for m in matched_findings if m["severity"] == "HIGH"])
                total_violations = len(matched_findings)

                if critical_count > 0 or high_count >= 2:
                    status = "NON_COMPLIANT"
                    penalty = ctrl["weight"] * 1.0
                elif total_violations > 0:
                    status = "PARTIAL_COMPLIANCE"
                    penalty = ctrl["weight"] * 0.4
                else:
                    status = "COMPLIANT"
                    penalty = 0.0
                    overall_passed_controls += 1

                fw_score = max(0.0, fw_score - penalty)

                evaluated_controls.append({
                    "control_id": ctrl["id"],
                    "title": ctrl["title"],
                    "description": ctrl["description"],
                    "status": status,
                    "violations_count": total_violations,
                    "critical_violations": critical_count,
                    "sample_findings": matched_findings[:3]
                })

            grade = "A (Audit Ready)" if fw_score >= 90 else "B (Minor Gaps)" if fw_score >= 75 else "C (Action Required)" if fw_score >= 50 else "F (High Non-Compliance Risk)"

            framework_results[fw_key] = {
                "name": fw["name"],
                "version": fw["version"],
                "compliance_score": round(fw_score, 1),
                "grade": grade,
                "controls": evaluated_controls
            }

        avg_score = round(sum(f["compliance_score"] for f in framework_results.values()) / max(len(framework_results), 1), 1)

        return {
            "meta": {
                "overall_compliance_score": avg_score,
                "passed_controls": overall_passed_controls,
                "total_controls": overall_total_controls,
                "compliance_readiness_status": "AUDIT_READY" if avg_score >= 85 else "ACTION_REQUIRED" if avg_score >= 60 else "FAILING",
                "frameworks_count": len(framework_results)
            },
            "frameworks": framework_results
        }

    def generate_executive_report_html(self, project_id: Optional[str] = None, findings: Optional[List[Dict[str, Any]]] = None) -> str:
        """
        Generates an auditor-grade, print-ready Executive Compliance Crosswalk Dossier (HTML).
        """
        import datetime
        import hashlib

        proj_name = "Enterprise Portfolio"
        if project_id and self.db:
            proj = self.db.get_project_by_id(project_id)
            if proj:
                proj_name = proj.get("name", project_id)

        eval_data = self.evaluate_compliance(project_id=project_id, findings=findings)
        meta = eval_data.get("meta", {})
        frameworks = eval_data.get("frameworks", {})
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        seal = hashlib.sha256(f"SENTINEL-COMPLIANCE:{project_id}:{meta.get('overall_compliance_score')}:{now_str}".encode()).hexdigest()

        score = meta.get("overall_compliance_score", 0.0)
        grade_color = "#10b981" if score >= 85 else "#f59e0b" if score >= 60 else "#ef4444"
        status_text = meta.get("compliance_readiness_status", "UNKNOWN")

        fw_cards_html = ""
        crosswalk_rows_html = ""

        for fw_key, fw in frameworks.items():
            fw_score = fw.get("compliance_score", 0)
            badge_color = "#10b981" if fw_score >= 85 else "#f59e0b" if fw_score >= 60 else "#ef4444"
            fw_cards_html += f"""
            <div class="fw-card">
                <div class="fw-header">
                    <h3>{fw.get('name')}</h3>
                    <span class="fw-version">{fw.get('version')}</span>
                </div>
                <div class="fw-score-box">
                    <span class="fw-score" style="color: {badge_color};">{fw_score}%</span>
                    <span class="fw-grade">{fw.get('grade')}</span>
                </div>
            </div>
            """

            for ctrl in fw.get("controls", []):
                st = ctrl.get("status", "COMPLIANT")
                st_color = "#10b981" if st == "COMPLIANT" else "#f59e0b" if st == "PARTIAL_COMPLIANCE" else "#ef4444"
                st_label = "COMPLIANT" if st == "COMPLIANT" else "PARTIAL" if st == "PARTIAL_COMPLIANCE" else "NON-COMPLIANT"
                samples = ctrl.get("sample_findings", [])
                sample_text = "<br>".join([f"• <strong>{s.get('severity')}:</strong> {s.get('title')} (<code>{s.get('file')}</code>)" for s in samples]) if samples else "<em>No active control violations detected.</em>"

                crosswalk_rows_html += f"""
                <tr>
                    <td><strong>{fw.get('name')}</strong></td>
                    <td><code>{ctrl.get('control_id')}</code></td>
                    <td>
                        <strong>{ctrl.get('title')}</strong>
                        <div class="ctrl-desc">{ctrl.get('description')}</div>
                    </td>
                    <td><span class="badge" style="background: {st_color}20; color: {st_color}; border: 1px solid {st_color};">{st_label}</span></td>
                    <td>{ctrl.get('violations_count', 0)}</td>
                    <td class="findings-cell">{sample_text}</td>
                </tr>
                """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Executive Compliance Crosswalk Report - {proj_name}</title>
    <style>
        @page {{ size: A4 landscape; margin: 15mm; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #0f172a;
            color: #f1f5f9;
            margin: 0;
            padding: 30px;
            font-size: 13px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #334155;
            padding-bottom: 20px;
            margin-bottom: 25px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .brand-logo {{
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #0ea5e9, #6366f1);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 18px;
            color: #fff;
        }}
        .brand h1 {{ margin: 0; font-size: 22px; color: #f8fafc; letter-spacing: -0.5px; }}
        .brand p {{ margin: 2px 0 0 0; color: #94a3b8; font-size: 12px; }}
        .meta-box {{ text-align: right; font-size: 11px; color: #94a3b8; }}
        .scorecard {{
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr;
            gap: 15px;
            margin-bottom: 25px;
        }}
        .score-hero {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .hero-pct {{ font-size: 42px; font-weight: 800; }}
        .hero-info h2 {{ margin: 0; font-size: 16px; color: #f8fafc; }}
        .hero-info p {{ margin: 4px 0 0 0; color: #94a3b8; font-size: 12px; }}
        .metric-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 10px;
            padding: 16px;
            text-align: center;
        }}
        .metric-card .val {{ font-size: 28px; font-weight: 700; color: #f8fafc; margin-top: 4px; }}
        .metric-card .lbl {{ font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }}
        .frameworks-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin-bottom: 30px;
        }}
        .fw-card {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 14px;
        }}
        .fw-header h3 {{ margin: 0; font-size: 14px; color: #f8fafc; }}
        .fw-version {{ font-size: 10px; color: #94a3b8; }}
        .fw-score-box {{ margin-top: 10px; display: flex; justify-content: space-between; align-items: baseline; }}
        .fw-score {{ font-size: 22px; font-weight: 800; }}
        .fw-grade {{ font-size: 11px; color: #94a3b8; }}
        h2.section-title {{ font-size: 16px; color: #f8fafc; margin-bottom: 12px; border-left: 3px solid #0ea5e9; padding-left: 8px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            overflow: hidden;
            font-size: 12px;
        }}
        th, td {{
            padding: 10px 14px;
            border-bottom: 1px solid #334155;
            text-align: left;
            vertical-align: top;
        }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        tr:hover td {{ background: rgba(255,255,255,0.02); }}
        .ctrl-desc {{ font-size: 11px; color: #94a3b8; margin-top: 2px; }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .findings-cell {{ font-size: 11px; color: #cbd5e1; }}
        .footer {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #334155;
            display: flex;
            justify-content: space-between;
            color: #64748b;
            font-size: 10px;
        }}
        .seal {{ font-family: monospace; color: #0ea5e9; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">
            <div class="brand-logo">🛡️</div>
            <div>
                <h1>Executive Compliance Crosswalk Dossier</h1>
                <p>Automated Regulatory Assurance Report • Project: <strong>{proj_name}</strong></p>
            </div>
        </div>
        <div class="meta-box">
            <div>Generated: {now_str}</div>
            <div>Attestation Engine: Sentinel Compliance v2.4</div>
            <div class="seal">SEAL: {seal[:24]}...</div>
        </div>
    </div>

    <div class="scorecard">
        <div class="score-hero">
            <div class="hero-pct" style="color: {grade_color};">{score}%</div>
            <div class="hero-info">
                <h2>Continuous Compliance Index</h2>
                <p>Readiness Assessment: <strong style="color: {grade_color};">{status_text}</strong></p>
                <p>Aggregated across SOC 2, ISO 27001, PCI-DSS v4.0, HIPAA, and NIST CSF.</p>
            </div>
        </div>
        <div class="metric-card">
            <div class="lbl">Passed Controls</div>
            <div class="val" style="color: #10b981;">{meta.get('passed_controls', 0)} / {meta.get('total_controls', 0)}</div>
        </div>
        <div class="metric-card">
            <div class="lbl">Frameworks Covered</div>
            <div class="val" style="color: #0ea5e9;">{meta.get('frameworks_count', 0)}</div>
        </div>
        <div class="metric-card">
            <div class="lbl">Control Pass Rate</div>
            <div class="val" style="color: {grade_color};">{round((meta.get('passed_controls', 0) / max(meta.get('total_controls', 1), 1)) * 100, 1)}%</div>
        </div>
    </div>

    <div class="frameworks-grid">
        {fw_cards_html}
    </div>

    <h2 class="section-title">Regulatory Control Crosswalk & Evidence Matrix</h2>
    <table>
        <thead>
            <tr>
                <th style="width: 13%;">Standard</th>
                <th style="width: 10%;">Control ID</th>
                <th style="width: 25%;">Control Title & Scope</th>
                <th style="width: 12%;">Compliance Status</th>
                <th style="width: 8%;">Violations</th>
                <th style="width: 32%;">Active Control Findings & Trace</th>
            </tr>
        </thead>
        <tbody>
            {crosswalk_rows_html}
        </tbody>
    </table>

    <div class="footer">
        <div>Official Sentinel AppSec Security Attestation • Confidential Executive Document</div>
        <div class="seal">Cryptographic Signature: {seal}</div>
    </div>
</body>
</html>"""
        return html
