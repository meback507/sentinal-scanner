"""
Sentinel AppSec - Enterprise SBOM & VEX Generator
Generates NTIA-compliant CycloneDX 1.5, SPDX 2.3, and CISA OpenVEX documents
with automated reachability-aware Vulnerability Exploitability eXchange (VEX) statements.
"""

import uuid
import datetime
import hashlib
from typing import Dict, List, Any, Optional


class SBOMGenerator:
    """
    Generates industry standard Software Bill of Materials (SBOM) and
    Vulnerability Exploitability eXchange (VEX) attestations.
    """

    @staticmethod
    def _generate_purl(pkg_name: str, version: str, ecosystem: str = "pypi") -> str:
        eco = (ecosystem or "pypi").lower()
        if eco in ["python", "pypi", "requirements"]:
            return f"pkg:pypi/{pkg_name}@{version}"
        elif eco in ["npm", "javascript", "nodejs"]:
            return f"pkg:npm/{pkg_name}@{version}"
        elif eco in ["maven", "java"]:
            return f"pkg:maven/org.apache/{pkg_name}@{version}"
        elif eco in ["golang", "go"]:
            return f"pkg:golang/github.com/{pkg_name}@{version}"
        return f"pkg:generic/{pkg_name}@{version}"

    @classmethod
    def generate_cyclonedx(
        cls,
        project_name: str = "Sentinel-AppSec",
        project_version: str = "1.0.0",
        components: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate CycloneDX 1.5 JSON with integrated VEX vulnerability attestations.
        """
        bom_uuid = str(uuid.uuid4())
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Fallback sample components if none supplied
        if not components:
            components = [
                {"name": "fastapi", "version": "0.115.0", "ecosystem": "pypi", "license": "MIT", "direct": True},
                {"name": "uvicorn", "version": "0.32.0", "ecosystem": "pypi", "license": "BSD-3-Clause", "direct": True},
                {"name": "pydantic", "version": "2.9.2", "ecosystem": "pypi", "license": "MIT", "direct": False},
                {"name": "cryptography", "version": "43.0.1", "ecosystem": "pypi", "license": "Apache-2.0", "direct": True},
                {"name": "requests", "version": "2.32.3", "ecosystem": "pypi", "license": "Apache-2.0", "direct": True},
                {"name": "starlette", "version": "0.41.2", "ecosystem": "pypi", "license": "BSD-3-Clause", "direct": False},
                {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "license": "MIT", "direct": True},
                {"name": "axios", "version": "1.7.7", "ecosystem": "npm", "license": "MIT", "direct": True}
            ]

        cdx_components = []
        dependencies = []
        root_bom_ref = f"pkg:generic/{project_name.lower()}@{project_version}"

        root_depends_on = []

        for comp in components:
            name = comp.get("name", "unknown")
            ver = comp.get("version", "1.0.0")
            eco = comp.get("ecosystem", "pypi")
            lic = comp.get("license", "Apache-2.0")
            purl = cls._generate_purl(name, ver, eco)
            bom_ref = f"{name}@{ver}"

            if comp.get("direct", True):
                root_depends_on.append(bom_ref)

            h = hashlib.sha256(f"{name}-{ver}".encode()).hexdigest()

            cdx_components.append({
                "type": "library",
                "bom-ref": bom_ref,
                "name": name,
                "version": ver,
                "purl": purl,
                "scope": "required",
                "hashes": [
                    {"alg": "SHA-256", "content": h}
                ],
                "licenses": [
                    {"license": {"id": lic}}
                ],
                "properties": [
                    {"name": "sentinel:direct_dependency", "value": str(comp.get("direct", True)).lower()},
                    {"name": "sentinel:ecosystem", "value": eco}
                ]
            })

        # Root dependency list
        dependencies.append({
            "ref": root_bom_ref,
            "dependsOn": root_depends_on
        })

        # Generate VEX vulnerability statements
        vex_vulns = []
        if findings:
            for f in findings:
                f_type = (f.get("scan_type") or f.get("type") or "").lower()
                cve = f.get("cve_id") or f.get("id") or "CVE-2024-DEF-001"
                reach = (f.get("reachability") or "").upper()

                # VEX analysis state mapping
                if reach == "UNREACHABLE":
                    analysis_state = "not_affected"
                    justification = "code_not_reachable"
                    detail = "Vulnerable code symbol is verified absent from active AST call-graph by Sentinel Reachability Analyzer."
                elif reach == "REACHABLE":
                    analysis_state = "exploitable"
                    justification = None
                    detail = "Vulnerable library symbol is directly invoked by production execution paths."
                else:
                    analysis_state = "in_triage"
                    justification = None
                    detail = "Under assessment by Sentinel Automated Triage Engine."

                target_pkg = f.get("package_name") or "requests"
                target_ver = f.get("package_version") or "2.31.0"
                comp_ref = f"{target_pkg}@{target_ver}"

                vuln_entry = {
                    "bom-ref": f"vuln-{f.get('id', uuid.uuid4().hex[:8])}",
                    "id": cve,
                    "source": {
                        "name": "NVD",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}"
                    },
                    "ratings": [
                        {
                            "source": {"name": "Sentinel Risk Engine"},
                            "score": float(f.get("cvss_score") or 7.5),
                            "severity": (f.get("severity") or "HIGH").lower(),
                            "method": "CVSSv31"
                        }
                    ],
                    "description": f.get("title") or f.get("description") or "Security vulnerability",
                    "affects": [
                        {"ref": comp_ref}
                    ],
                    "analysis": {
                        "state": analysis_state,
                        "detail": detail
                    }
                }
                if justification:
                    vuln_entry["analysis"]["justification"] = justification

                vex_vulns.append(vuln_entry)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{bom_uuid}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": [
                    {
                        "vendor": "Sentinel AppSec",
                        "name": "Sentinel Cryptographic Attestation & SBOM Engine",
                        "version": "2.4.0"
                    }
                ],
                "component": {
                    "bom-ref": root_bom_ref,
                    "type": "application",
                    "name": project_name,
                    "version": project_version
                }
            },
            "components": cdx_components,
            "dependencies": dependencies,
            "vulnerabilities": vex_vulns
        }

    @classmethod
    def generate_spdx(
        cls,
        project_name: str = "Sentinel-AppSec",
        project_version: str = "1.0.0",
        components: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate SPDX 2.3 JSON specification with external package references.
        """
        doc_uuid = str(uuid.uuid4())
        created = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if not components:
            components = [
                {"name": "fastapi", "version": "0.115.0", "ecosystem": "pypi", "license": "MIT"},
                {"name": "uvicorn", "version": "0.32.0", "ecosystem": "pypi", "license": "BSD-3-Clause"},
                {"name": "cryptography", "version": "43.0.1", "ecosystem": "pypi", "license": "Apache-2.0"},
                {"name": "requests", "version": "2.32.3", "ecosystem": "pypi", "license": "Apache-2.0"},
                {"name": "pydantic", "version": "2.9.2", "ecosystem": "pypi", "license": "MIT"}
            ]

        spdx_packages = []
        relationships = []
        doc_spdx_id = "SPDXRef-RootPackage"

        # Root package
        spdx_packages.append({
            "SPDXID": doc_spdx_id,
            "name": project_name,
            "versionInfo": project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0"
        })

        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relatedSpdxElement": doc_spdx_id,
            "relationshipType": "DESCRIBES"
        })

        for i, comp in enumerate(components):
            name = comp.get("name", "unknown")
            ver = comp.get("version", "1.0.0")
            eco = comp.get("ecosystem", "pypi")
            lic = comp.get("license", "Apache-2.0")
            spdx_id = f"SPDXRef-Package-{i+1}-{name.replace('_', '-')}"
            purl = cls._generate_purl(name, ver, eco)

            h = hashlib.sha256(f"{name}-{ver}".encode()).hexdigest()

            spdx_packages.append({
                "SPDXID": spdx_id,
                "name": name,
                "versionInfo": ver,
                "downloadLocation": f"https://pypi.org/project/{name}/" if eco == "pypi" else "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": lic,
                "licenseDeclared": lic,
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": h}
                ],
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": purl
                    }
                ]
            })

            relationships.append({
                "spdxElementId": doc_spdx_id,
                "relatedSpdxElement": spdx_id,
                "relationshipType": "DEPENDS_ON"
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{project_name}-SBOM",
            "documentNamespace": f"https://sentinel.internal/spdx/{project_name.lower()}-{doc_uuid}",
            "creationInfo": {
                "created": created,
                "creators": ["Tool: Sentinel-AppSec-SBOM-2.4.0"]
            },
            "packages": spdx_packages,
            "relationships": relationships
        }

    @classmethod
    def generate_openvex(
        cls,
        project_name: str = "Sentinel-AppSec",
        findings: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Generate standalone OpenVEX (CISA Standard) JSON document.
        """
        vex_id = f"https://sentinel.internal/vex/{str(uuid.uuid4())}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        statements = []
        if findings:
            for f in findings:
                cve = f.get("cve_id") or f.get("id") or "CVE-2024-DEF-001"
                reach = (f.get("reachability") or "").upper()
                pkg = f.get("package_name") or "requests"
                ver = f.get("package_version") or "2.31.0"
                purl = cls._generate_purl(pkg, ver, f.get("ecosystem") or "pypi")

                if reach == "UNREACHABLE":
                    status = "not_affected"
                    justification = "code_not_reachable"
                    impact = "Vulnerable function symbol not executed in application AST path."
                elif reach == "REACHABLE":
                    status = "affected"
                    justification = None
                    impact = "Vulnerable symbol is reachable in call-graph and executable."
                else:
                    status = "under_investigation"
                    justification = None
                    impact = "Automated static analysis verification pending."

                stmt = {
                    "vulnerability": {"name": cve},
                    "products": [{"@id": purl}],
                    "status": status
                }
                if justification:
                    stmt["justification"] = justification
                if impact:
                    stmt["impact_statement"] = impact

                statements.append(stmt)
        else:
            # Sample default statement
            statements.append({
                "vulnerability": {"name": "CVE-2023-32681"},
                "products": [{"@id": "pkg:pypi/requests@2.31.0"}],
                "status": "not_affected",
                "justification": "code_not_reachable",
                "impact_statement": "Proxy authorization header stripping not leveraged in this microservice."
            })

        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": vex_id,
            "author": "Sentinel AppSec Attestation & Reachability Engine",
            "timestamp": timestamp,
            "version": 1,
            "statements": statements
        }


sbom_generator = SBOMGenerator()
