"""
AegisSec - Report Exporter Engine
Generates Executive HTML/PDF-ready reports, SARIF v2.1.0, CycloneDX SBOM, and CSV formats.
"""

import json
import csv
import io
import datetime
from typing import List, Dict, Any


class ReportGenerator:
    @classmethod
    def generate_html_report(cls, project: Dict[str, Any], scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        total = len(findings)
        crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in findings if f["severity"] == "HIGH")
        med = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low = sum(1 for f in findings if f["severity"] == "LOW")

        # Standards coverage
        standards_counts: Dict[str, int] = {}
        for f in findings:
            for s in f.get("standards", []):
                prefix = s.split(":")[0]
                standards_counts[prefix] = standards_counts.get(prefix, 0) + 1

        quadrant_counts = {"ACT_NOW": 0, "CRITICAL_PATCH": 0, "OPPORTUNISTIC": 0, "ROUTINE": 0}
        for f in findings:
            q = f.get("quadrant", "ROUTINE")
            quadrant_counts[q] = quadrant_counts.get(q, 0) + 1

        findings_rows = ""
        for f in findings:
            badge_cls = f"badge-{f['severity'].lower()}"
            st_badges = "".join([f'<span class="std-badge">{s}</span>' for s in f.get("standards", [])])
            snippet_html = f"<pre><code>{f.get('code_snippet', '')}</code></pre>" if f.get('code_snippet') else ""

            author_str = f"{f.get('author_name', 'Unknown')} ({f.get('author_email', '')}) - Commit #{f.get('commit_hash', 'HEAD')}"
            findings_rows += f"""
            <tr class="finding-row">
                <td><span class="badge {badge_cls}">{f['severity']}</span></td>
                <td>
                    <div class="finding-title">{f['title']}</div>
                    <div class="finding-loc"><code>{f['file_path']}:{f.get('line_start', 1)}</code> | {f['type'].upper()}</div>
                    <div style="font-size: 12px; color: var(--primary); margin-bottom: 6px;"><strong>Authored by:</strong> {author_str}</div>
                    <div class="finding-desc">{f['description']}</div>
                    {snippet_html}
                    <div class="remediation-box"><strong>Remediation:</strong> {f['remediation']}</div>
                    <div class="std-container">{st_badges}</div>
                </td>
                <td>
                    <div class="metric-val"><strong>CVSS:</strong> {f['cvss_score']}</div>
                    <div class="metric-val"><strong>EPSS:</strong> {f['epss_score']} ({round(f['epss_percentile']*100, 1)}%)</div>
                    <div class="metric-val"><strong>Risk Score:</strong> {f['composite_risk_score']}/100</div>
                    <span class="quad-badge quad-{f['quadrant'].lower()}">{f['quadrant']}</span>
                </td>
            </tr>
            """

        std_summary_html = "".join([
            f'<div class="std-card"><span class="std-num">{cnt}</span><span class="std-name">{std}</span></div>'
            for std, cnt in sorted(standards_counts.items(), key=lambda x: x[1], reverse=True)
        ])

        now_str = datetime.datetime.now().strftime("%B %d, %Y - %H:%M UTC")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AegisSec Executive Report - {project.get('name')}</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #1e293b;
            --border: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --primary: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: var(--bg);
            color: var(--text-primary);
            margin: 0;
            padding: 40px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            border-bottom: 2px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 30px;
        }}
        .logo-box {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-box h1 {{
            margin: 0;
            font-size: 28px;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .meta-info {{
            text-align: right;
            color: var(--text-secondary);
            font-size: 14px;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 30px;
        }}
        .kpi-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .kpi-val {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        .kpi-label {{
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .badge-low {{ background: rgba(16, 185, 129, 0.2); color: var(--low); border: 1px solid var(--low); }}
        
        .std-summary {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 30px;
        }}
        .std-card {{
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 8px 14px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .std-num {{
            font-weight: 700;
            color: var(--primary);
        }}
        .findings-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        .findings-table th {{
            background: #1e293b;
            padding: 14px 16px;
            text-align: left;
            font-size: 13px;
            color: var(--text-secondary);
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }}
        .findings-table td {{
            padding: 18px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            color: #fff;
            margin-bottom: 4px;
        }}
        .finding-loc {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }}
        .finding-desc {{
            font-size: 14px;
            color: #cbd5e1;
            margin-bottom: 10px;
        }}
        .remediation-box {{
            background: #0f172a;
            border-left: 3px solid var(--primary);
            padding: 10px 14px;
            border-radius: 4px;
            font-size: 13px;
            color: #e2e8f0;
            margin-bottom: 10px;
        }}
        .std-badge {{
            background: #1e293b;
            border: 1px solid #475569;
            color: #cbd5e1;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            margin-right: 4px;
            display: inline-block;
        }}
        pre {{
            background: #0b0f19;
            border: 1px solid #1e293b;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            overflow-x: auto;
            color: #f87171;
        }}
        .quad-badge {{
            font-size: 11px;
            font-weight: bold;
            padding: 3px 6px;
            border-radius: 4px;
            display: inline-block;
            margin-top: 6px;
        }}
        .quad-act_now {{ background: #ef4444; color: white; }}
        .quad-critical_patch {{ background: #f97316; color: white; }}
        .quad-opportunistic {{ background: #eab308; color: black; }}
        .quad-routine {{ background: #10b981; color: white; }}
        @media print {{
            body {{ padding: 0; background: white; color: black; }}
            .findings-table {{ border: 1px solid #ddd; }}
            .findings-table th, .findings-table td {{ border-bottom: 1px solid #ddd; color: black; }}
            .remediation-box {{ background: #f4f4f5; color: black; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo-box">
            <h1>AegisSec</h1>
            <span style="font-size: 18px; color: var(--text-secondary);">| Unified SAST & SCA Security Audit Report</span>
        </div>
        <div class="meta-info">
            <div><strong>Project:</strong> {project.get('name')} ({project.get('git_branch', 'main')})</div>
            <div><strong>Scan ID:</strong> {scan.get('id', 'N/A')}</div>
            <div><strong>Generated:</strong> {now_str}</div>
        </div>
    </div>

    <div class="kpi-grid">
        <div class="kpi-card">
            <div class="kpi-val" style="color: var(--primary);">{total}</div>
            <div class="kpi-label">Total Vulnerabilities</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" style="color: var(--critical);">{crit}</div>
            <div class="kpi-label">Critical Exploits</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" style="color: var(--high);">{high}</div>
            <div class="kpi-label">High Severity Flaws</div>
        </div>
        <div class="kpi-card">
            <div class="kpi-val" style="color: #38bdf8;">{scan.get('composite_risk_score', 0)}/100</div>
            <div class="kpi-label">Overall Risk Score</div>
        </div>
    </div>

    <h3>Standards & Compliance Matrix Impact</h3>
    <div class="std-summary">
        {std_summary_html}
    </div>

    <h3>Detailed Vulnerability Findings & Prioritized Remediation</h3>
    <table class="findings-table">
        <thead>
            <tr>
                <th style="width: 100px;">Severity</th>
                <th>Finding, Context & Remediation</th>
                <th style="width: 160px;">Prioritization</th>
            </tr>
        </thead>
        <tbody>
            {findings_rows if findings_rows else '<tr><td colspan="3" style="text-align: center;">No vulnerabilities found. Clean security posture!</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""
        return html

    @classmethod
    def generate_sarif(cls, project: Dict[str, Any], scan: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """
        Generates standard OASIS SARIF v2.1.0 JSON format for GitHub Code Scanning / IDE integration.
        """
        rules = []
        rule_ids_seen = set()
        results = []

        for f in findings:
            r_id = f.get("rule_id") or f.get("cwe_id") or "AEGIS-GENERIC"
            if r_id not in rule_ids_seen:
                rule_ids_seen.add(r_id)
                rules.append({
                    "id": r_id,
                    "name": f.get("title", ""),
                    "shortDescription": {"text": f.get("title", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "help": {"text": f.get("remediation", "")},
                    "properties": {
                        "tags": f.get("standards", []),
                        "security-severity": str(f.get("cvss_score", 5.0))
                    }
                })

            # Severity mapping to SARIF level: error, warning, note
            level = "error" if f.get("severity") in ("CRITICAL", "HIGH") else "warning" if f.get("severity") == "MEDIUM" else "note"

            results.append({
                "ruleId": r_id,
                "level": level,
                "message": {"text": f.get("description", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.get("file_path", "")
                            },
                            "region": {
                                "startLine": f.get("line_start", 1),
                                "endLine": f.get("line_end", 1)
                            }
                        }
                    }
                ]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AegisSec SAST & SCA Engine",
                            "semanticVersion": "1.0.0",
                            "informationUri": "https://aegissec.internal",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }
        return json.dumps(sarif_doc, indent=2)

    @classmethod
    def generate_cyclonedx_sbom(cls, project: Dict[str, Any], dependencies: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str:
        """
        Generates CycloneDX v1.5 JSON SBOM for software supply chain transparency (ISO-5230 OpenChain).
        """
        components = []
        for dep in dependencies:
            components.append({
                "type": "library",
                "name": dep.get("name"),
                "version": dep.get("version"),
                "purl": f"pkg:{dep.get('ecosystem', 'generic')}/{dep.get('name')}@{dep.get('version')}",
                "licenses": [
                    {"license": {"id": dep.get("license", "MIT")}}
                ]
            })

        vulns = []
        for f in findings:
            if f.get("type") == "sca" and f.get("cve_id"):
                vulns.append({
                    "id": f.get("cve_id"),
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{f.get('cve_id')}"},
                    "ratings": [
                        {
                            "score": f.get("cvss_score"),
                            "severity": f.get("severity", "medium").lower(),
                            "method": "CVSSv31",
                            "vector": f.get("cvss_vector")
                        }
                    ],
                    "description": f.get("description"),
                    "recommendation": f.get("remediation")
                })

        cyclonedx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{project.get('id')}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.now().isoformat(),
                "component": {
                    "type": "application",
                    "name": project.get("name"),
                    "version": "1.0.0"
                }
            },
            "components": components,
            "vulnerabilities": vulns
        }
        return json.dumps(cyclonedx_doc, indent=2)

    @classmethod
    def generate_csv(cls, findings: List[Dict[str, Any]]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "ID", "Type", "Severity", "Title", "File Path", "Line Start",
            "Age (Days)", "First Seen",
            "Author Name", "Author Email", "Commit Hash",
            "CVSS", "EPSS", "Risk Score", "Quadrant", "CWE", "CVE", "Standards", "Status"
        ])
        for f in findings:
            writer.writerow([
                f.get("id"),
                f.get("type"),
                f.get("severity"),
                f.get("title"),
                f.get("file_path"),
                f.get("line_start"),
                f.get("age_days", 0),
                f.get("first_seen_date") or (f.get("first_seen", "")[:10] if f.get("first_seen") else ""),
                f.get("author_name", "Unknown"),
                f.get("author_email", ""),
                f.get("commit_hash", "HEAD"),
                f.get("cvss_score"),
                f.get("epss_score"),
                f.get("composite_risk_score"),
                f.get("quadrant"),
                f.get("cwe_id"),
                f.get("cve_id"),
                "; ".join(f.get("standards", [])),
                f.get("status")
            ])
        return output.getvalue()

    @classmethod
    def generate_openvex(cls, project: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """
        Generates standard OpenVEX v0.2.0 document for machine-readable vulnerability exploitability exchange.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        doc_id = f"https://aegissec.internal/vex/{project.get('id', 'default')}/{int(datetime.datetime.now().timestamp())}"

        statements = []
        for f in findings:
            cve_or_id = f.get("cve_id") or f.get("cwe_id") or f.get("id")
            pkg_name = f.get("package_name") or project.get("name", "app")
            version = f.get("installed_version") or "1.0.0"
            subproduct_id = f"pkg:generic/{pkg_name}@{version}"

            status_curr = f.get("status", "open")
            reachability = f.get("reachability_status") or f.get("reachability") or ""

            if status_curr == "resolved":
                status = "fixed"
                justification = None
                action_statement = f"Remediated via version upgrade to {f.get('fixed_version', 'latest')} or secure code patch."
            elif status_curr == "false_positive" or reachability == "DORMANT":
                status = "not_affected"
                justification = "vulnerable_code_not_in_execute_path" if reachability == "DORMANT" else "inline_mitigations_already_exist"
                action_statement = None
            elif reachability == "REACHABLE" or f.get("cisa_kev"):
                status = "affected"
                justification = None
                action_statement = f.get("remediation") or "Apply immediate patch or upgrade per vendor security advisory."
            else:
                status = "under_investigation"
                justification = None
                action_statement = "Triage evaluation in progress by AppSec team."

            statement = {
                "vulnerability": {
                    "name": cve_or_id,
                    "description": f.get("title")
                },
                "timestamp": now,
                "products": [
                    {
                        "@id": subproduct_id,
                        "identifiers": {
                            "purl": subproduct_id
                        }
                    }
                ],
                "status": status
            }
            if justification:
                statement["justification"] = justification
            if action_statement:
                statement["action_statement"] = action_statement

            statements.append(statement)

        vex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": doc_id,
            "author": "AegisSec / Sentinel Scanner AST Platform",
            "role": "Security Compliance & Vulnerability Management Engine",
            "timestamp": now,
            "version": 1,
            "tooling": "AegisSec-AST-v2.1",
            "statements": statements
        }
        return json.dumps(vex_doc, indent=2)

