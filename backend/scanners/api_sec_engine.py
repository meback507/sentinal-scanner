"""
AegisSec - OpenAPI & Swagger Security Engine
Audits API specifications against OWASP API Security Top 10 (2023):
BOLA, Broken Authentication, Mass Assignment, Resource Exhaustion, and Insecure Transport.
"""

import os
import json
import yaml
from typing import List, Dict, Any
from ..standards.taxonomy import map_finding_to_standards
from ..prioritization.risk_engine import risk_engine


class APISecEngine:
    def __init__(self):
        pass

    def scan_directory(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(target_dir):
            return findings

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "vendor", ".venv", "__pycache__"]]

            for fname in files:
                low_name = fname.lower()
                if not any(k in low_name for k in ["openapi", "swagger"]):
                    continue
                if not (low_name.endswith(".json") or low_name.endswith(".yaml") or low_name.endswith(".yml")):
                    continue

                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target_dir)

                spec = self._load_spec(fpath)
                if not spec or not isinstance(spec, dict):
                    continue

                # Verify it is an OpenAPI / Swagger document
                if "openapi" not in spec and "swagger" not in spec:
                    continue

                spec_findings = self._audit_spec(spec, rel_path)
                findings.extend(spec_findings)

        return findings

    def _load_spec(self, fpath: str) -> Optional[Dict[str, Any]]:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            if fpath.endswith(".json"):
                return json.loads(content)
            return yaml.safe_load(content)
        except Exception:
            return None

    def _audit_spec(self, spec: Dict[str, Any], rel_path: str) -> List[Dict[str, Any]]:
        findings = []
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])

        # 1. Insecure Transport Check (HTTP without HTTPS)
        servers = spec.get("servers", [])
        schemes = spec.get("schemes", [])
        insecure_urls = [s.get("url", "") for s in servers if s.get("url", "").startswith("http://")]
        if ("http" in schemes and "https" not in schemes) or (len(insecure_urls) > 0 and not any(s.get("url", "").startswith("https://") for s in servers)):
            findings.append(self._build_finding(
                rule_id="API-TRANS-001",
                title="Insecure Cleartext Transport Scheme (HTTP) in API Specification",
                description="The API specification declares unencrypted HTTP server endpoints, exposing credentials and payload data to man-in-the-middle interception.",
                remediation="Enforce HTTPS schemes across all API server definitions and redirect HTTP traffic to TLS 1.3 endpoints.",
                severity="HIGH",
                cwe="CWE-319",
                file_path=rel_path,
                line=1,
                snippet=str(insecure_urls or schemes),
                standards=["OWASP-API:API2:2023", "ISO-27001:A.8.24", "PCI-DSS:Req-4.1"],
                cvss=7.5,
                epss=0.08
            ))

        # 2. Iterate Paths & Operations
        for path_url, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            has_path_id = "{" in path_url and "}" in path_url

            for method in ["get", "post", "put", "patch", "delete"]:
                op = path_item.get(method)
                if not op or not isinstance(op, dict):
                    continue

                op_sec = op.get("security")
                effective_sec = op_sec if op_sec is not None else global_security

                # API1:2023 - BOLA (Broken Object Level Authorization)
                if has_path_id and (effective_sec == [] or effective_sec is None):
                    findings.append(self._build_finding(
                        rule_id="API-BOLA-001",
                        title=f"OWASP API1:2023 BOLA - Unauthenticated ID Endpoint ({method.upper()} {path_url})",
                        description=f"Endpoint accesses discrete object IDs via URL parameter without declaring security requirements, inviting unauthorized IDOR / BOLA enumeration.",
                        remediation="Apply authentication requirement and implement strict object-level ownership checks verifying caller identity against resource author.",
                        severity="CRITICAL",
                        cwe="CWE-284",
                        file_path=rel_path,
                        line=1,
                        snippet=f"{method.upper()} {path_url}",
                        standards=["OWASP-API:API1:2023", "OWASP:A01:2021", "ISO-27001:A.8.25"],
                        cvss=9.3,
                        epss=0.58
                    ))

                # API2:2023 - Broken Authentication on Admin/Sensitive Endpoints
                low_url = path_url.lower()
                is_sensitive = any(w in low_url for w in ["admin", "payment", "payout", "privilege", "internal"])
                if is_sensitive and (effective_sec == [] or effective_sec is None):
                    findings.append(self._build_finding(
                        rule_id="API-AUTH-001",
                        title=f"OWASP API2:2023 Broken Authentication - Sensitive Admin Endpoint ({method.upper()} {path_url})",
                        description=f"Privileged administrative operation exposes functionality without mandatory authentication requirement.",
                        remediation="Bind route to strong OAuth2/Bearer token security scheme with role-based scope enforcement (e.g. `roles: admin`).",
                        severity="CRITICAL",
                        cwe="CWE-306",
                        file_path=rel_path,
                        line=1,
                        snippet=f"{method.upper()} {path_url}",
                        standards=["OWASP-API:API2:2023", "NIST-800-53:IA-2", "ISO-27001:A.8.28"],
                        cvss=9.8,
                        epss=0.72
                    ))

                # API3:2023 - Mass Assignment / Dangerous Mutable Properties
                if method in ["post", "put", "patch"]:
                    body_schema = self._extract_request_body_schema(op, spec)
                    properties = body_schema.get("properties", {}) if isinstance(body_schema, dict) else {}
                    dangerous_props = [p for p in properties.keys() if p.lower() in ["role", "is_admin", "admin", "permissions", "verified", "balance"]]
                    if dangerous_props:
                        findings.append(self._build_finding(
                            rule_id="API-MASS-001",
                            title=f"OWASP API3:2023 Mass Assignment - Sensitive Property Exposed ({', '.join(dangerous_props)})",
                            description=f"Request body schema allows direct client assignment of sensitive privilege properties ({dangerous_props}) on {method.upper()} {path_url}.",
                            remediation="Do not bind domain model directly to request schemas; use strict Data Transfer Objects (DTO) omitting privilege fields.",
                            severity="HIGH",
                            cwe="CWE-915",
                            file_path=rel_path,
                            line=1,
                            snippet=f"{method.upper()} {path_url} -> {dangerous_props}",
                            standards=["OWASP-API:API3:2023", "CWE-915", "ISO-27001:A.8.25"],
                            cvss=8.3,
                            epss=0.22
                        ))

                # API4:2023 - Unrestricted Resource Consumption (Missing Pagination on Collection GET)
                if method == "get" and not has_path_id:
                    params = op.get("parameters", [])
                    param_names = [p.get("name", "").lower() for p in params if isinstance(p, dict)]
                    has_pagination = any(k in param_names for k in ["limit", "page", "offset", "size", "cursor", "take"])
                    if not has_pagination:
                        findings.append(self._build_finding(
                            rule_id="API-DOS-001",
                            title=f"OWASP API4:2023 Unrestricted Resource Consumption - Missing Pagination ({method.upper()} {path_url})",
                            description=f"Collection endpoint {path_url} lacks pagination parameters, exposing backend database to memory exhaustion / Denial of Service via unbounded record fetching.",
                            remediation="Implement strict pagination limits (e.g. `limit` capped at 100 records and `cursor`/`offset` query parameters).",
                            severity="MEDIUM",
                            cwe="CWE-400",
                            file_path=rel_path,
                            line=1,
                            snippet=f"{method.upper()} {path_url}",
                            standards=["OWASP-API:API4:2023", "NIST-800-53:SC-5", "ISO-27001:A.8.28"],
                            cvss=5.3,
                            epss=0.03
                        ))

                # API7:2023 - Server Side Request Forgery (SSRF) via Parameter
                params = op.get("parameters", [])
                for p in params:
                    if isinstance(p, dict):
                        pname = p.get("name", "").lower()
                        if any(k in pname for k in ["url", "webhook", "callback", "redirect_uri"]) and pname not in ["status", "id"]:
                            findings.append(self._build_finding(
                                rule_id="API-SSRF-001",
                                title=f"OWASP API7:2023 Potential SSRF via URL Parameter '{p.get('name')}' ({method.upper()} {path_url})",
                                description=f"Endpoint accepts external URL in query/path parameter '{p.get('name')}' without declared IP restriction or schema URI validation.",
                                remediation="Validate external URLs against strict allowlists and disallow private IP ranges (RFC 1918 / AWS Metadata 169.254.169.254).",
                                severity="HIGH",
                                cwe="CWE-918",
                                file_path=rel_path,
                                line=1,
                                snippet=f"Param: {p.get('name')} on {method.upper()} {path_url}",
                                standards=["OWASP-API:API7:2023", "OWASP:A10:2021", "ISO-27001:A.8.25"],
                                cvss=8.6,
                                epss=0.34
                            ))

        return findings

    def _extract_request_body_schema(self, op: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
        rb = op.get("requestBody", {})
        if isinstance(rb, dict):
            content = rb.get("content", {})
            for media in ["application/json", "application/x-www-form-urlencoded"]:
                if media in content:
                    schema = content[media].get("schema", {})
                    return self._resolve_schema(schema, spec)
        # Swagger 2.0 parameters
        params = op.get("parameters", [])
        for p in params:
            if isinstance(p, dict) and p.get("in") == "body":
                return self._resolve_schema(p.get("schema", {}), spec)
        return {}

    def _resolve_schema(self, schema: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
        ref = schema.get("$ref")
        if ref and isinstance(ref, str):
            parts = ref.lstrip("#/").split("/")
            curr = spec
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return schema
            return curr
        return schema

    def _build_finding(self, rule_id: str, title: str, description: str, remediation: str, severity: str, cwe: str, file_path: str, line: int, snippet: str, standards: List[str], cvss: float, epss: float) -> Dict[str, Any]:
        prioritization = risk_engine.calculate_finding_priority(
            cvss_score=cvss,
            epss_score=epss,
            standards=standards
        )

        return {
            "type": "api",
            "title": f"[{rule_id}] {title}",
            "description": description,
            "remediation": remediation,
            "severity": severity,
            "cwe_id": cwe,
            "cve_id": None,
            "language": "openapi",
            "file_path": file_path,
            "line_start": line,
            "line_end": line,
            "code_snippet": snippet[:200],
            "cvss_score": cvss,
            "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if severity in ['CRITICAL', 'HIGH'] else 'L'}/I:{'H' if severity in ['CRITICAL', 'HIGH'] else 'L'}/A:N",
            "epss_score": epss,
            "epss_percentile": 0.50,
            "composite_risk_score": prioritization["composite_risk_score"],
            "quadrant": prioritization["quadrant"],
            "urgency": prioritization["urgency"],
            "sla_days": prioritization["sla_days"],
            "standards": standards,
            "status": "open"
        }
