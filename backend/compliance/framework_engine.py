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
