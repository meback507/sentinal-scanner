"""
AegisSec - SCA (Software Composition Analysis) Engine
Discovers third-party dependencies, matches vulnerabilities (CVE/CVSS/EPSS), and enforces ISO-5230 OpenChain license compliance.
"""

import os
import re
import json
from typing import List, Dict, Any, Optional
from ..standards.taxonomy import map_finding_to_standards
from ..prioritization.risk_engine import risk_engine


# Built-in curated vulnerability database for common open-source dependencies
CURATED_VULN_DB = [
    {
        "ecosystem": "npm",
        "package": "lodash",
        "affected_versions": ["<4.17.21"],
        "cve": "CVE-2021-23337",
        "cwe": "CWE-94",
        "title": "Lodash Prototype Pollution & Command Injection",
        "description": "Command Injection in lodash template function allows malicious property injection via prototype.",
        "cvss": 7.4,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "fixed_version": "4.17.21"
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "affected_versions": ["<0.21.1", "<1.6.0"],
        "cve": "CVE-2023-45857",
        "cwe": "CWE-918",
        "title": "Axios Server-Side Request Forgery (SSRF)",
        "description": "Axios allows SSRF by following redirects with credentials retained on foreign domains.",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "fixed_version": "1.6.0"
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "affected_versions": ["<4.19.2"],
        "cve": "CVE-2024-29041",
        "cwe": "CWE-601",
        "title": "Express Open Redirect Vulnerability",
        "description": "Malformed URL handling in res.redirect permits untrusted open redirection.",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "fixed_version": "4.19.2"
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "affected_versions": ["<2.0.7", "<1.26.18"],
        "cve": "CVE-2023-45803",
        "cwe": "CWE-200",
        "title": "urllib3 Request Body Leakage during HTTP Redirect",
        "description": "urllib3 failed to strip the HTTP request body after a 303 See Other redirect.",
        "cvss": 6.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "fixed_version": "2.0.7"
    },
    {
        "ecosystem": "pypi",
        "package": "requests",
        "affected_versions": ["<2.31.0"],
        "cve": "CVE-2023-32681",
        "cwe": "CWE-200",
        "title": "Requests Forwarding Proxy-Authorization Header on Redirect",
        "description": "Leaking Proxy-Authorization headers to unauthorized destination hostnames during redirects.",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
        "fixed_version": "2.31.0"
    },
    {
        "ecosystem": "pypi",
        "package": "django",
        "affected_versions": ["<4.2.8", "<5.0.1"],
        "cve": "CVE-2023-46695",
        "cwe": "CWE-400",
        "title": "Django Potential Denial of Service in Text Translation",
        "description": "A very long or malformed language code in the Accept-Language header triggers a CPU DoS.",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "fixed_version": "4.2.8"
    },
    {
        "ecosystem": "maven",
        "package": "org.apache.logging.log4j:log4j-core",
        "affected_versions": ["<=2.14.1"],
        "cve": "CVE-2021-44228",
        "cwe": "CWE-502",
        "title": "Log4Shell - JNDI Remote Code Execution in Log4j",
        "description": "JNDI lookup features used in configuration or logged strings allow attackers to execute arbitrary Java code.",
        "cvss": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "fixed_version": "2.17.1"
    },
    {
        "ecosystem": "maven",
        "package": "org.springframework.boot:spring-boot",
        "affected_versions": ["<2.6.6"],
        "cve": "CVE-2022-22965",
        "cwe": "CWE-94",
        "title": "Spring4Shell - Remote Code Execution via Data Binding",
        "description": "Exploitable via ClassLoader manipulation when running on JDK 9+ as a WAR deployment.",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "fixed_version": "2.6.6"
    },
    {
        "ecosystem": "maven",
        "package": "org.springframework.boot:spring-boot-starter-parent",
        "affected_versions": ["<2.6.6"],
        "cve": "CVE-2022-22965",
        "cwe": "CWE-94",
        "title": "Spring4Shell - Remote Code Execution via Data Binding",
        "description": "Spring Boot starter parent contains Spring Framework component allowing unauthenticated Remote Code Execution via data binder ClassLoader access.",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "fixed_version": "2.6.6"
    },
    {
        "ecosystem": "maven",
        "package": "org.webjars:jquery",
        "affected_versions": ["<3.5.0"],
        "cve": "CVE-2020-11022",
        "cwe": "CWE-79",
        "title": "jQuery Cross-Site Scripting (XSS) via htmlPrefilter",
        "description": "Regex in jQuery before 3.5.0 used for HTML cleaning leads to arbitrary JavaScript execution upon untrusted HTML parsing.",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "fixed_version": "3.5.0"
    },
    {
        "ecosystem": "maven",
        "package": "org.webjars:bootstrap",
        "affected_versions": ["<3.4.1"],
        "cve": "CVE-2018-14041",
        "cwe": "CWE-79",
        "title": "Bootstrap XSS via Collapse and Tooltip Attributes",
        "description": "Vulnerability in Bootstrap data-target and tooltip attributes allows arbitrary script execution in client browsers.",
        "cvss": 6.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "fixed_version": "3.4.1"
    },
    {
        "ecosystem": "golang",
        "package": "golang.org/x/crypto",
        "affected_versions": ["<0.17.0"],
        "cve": "CVE-2023-48795",
        "cwe": "CWE-310",
        "title": "Terrapin SSH Protocol Flaw in Go Crypto",
        "description": "Prefix truncation attack against the SSH transport protocol allows sequence manipulation.",
        "cvss": 5.9,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "fixed_version": "0.17.0"
    }
]

# License definitions for OpenChain ISO-5230 compliance
LICENSE_REGISTRY = {
    "lodash": "MIT",
    "axios": "MIT",
    "express": "MIT",
    "react": "MIT",
    "urllib3": "MIT",
    "requests": "Apache-2.0",
    "django": "BSD-3-Clause",
    "flask": "BSD-3-Clause",
    "fastapi": "MIT",
    "log4j-core": "Apache-2.0",
    "gpl-sample": "GPL-3.0",
    "agpl-sample": "AGPL-3.0"
}

RESTRICTED_LICENSES = {"GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-3.0", "SSPL"}


class SCAEngine:
    def scan_directory(self, target_dir: str) -> Dict[str, Any]:
        """
        Discovers dependency manifests, parses installed packages, and correlates vulnerabilities and licenses.
        Returns: { 'dependencies': [...], 'findings': [...] }
        """
        all_dependencies: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        manifest_parsers = [
            ("requirements.txt", self._parse_requirements_txt),
            ("package.json", self._parse_package_json),
            ("package-lock.json", self._parse_package_lock_json),
            ("pom.xml", self._parse_pom_xml),
            ("go.mod", self._parse_go_mod),
            ("Cargo.toml", self._parse_cargo_toml)
        ]

        for root, _, files in os.walk(target_dir):
            for filename in files:
                rel_path = os.path.relpath(os.path.join(root, filename), target_dir)
                for pattern, parser_func in manifest_parsers:
                    if filename.lower() == pattern.lower():
                        full_path = os.path.join(root, filename)
                        deps = parser_func(full_path, rel_path)
                        all_dependencies.extend(deps)

        # Match dependencies against vulnerability database and license policy
        for dep in all_dependencies:
            # Analyze SCA Call-Graph Symbol Reachability
            reach_info = self._check_reachability(target_dir, dep["name"])

            # 1. Match CVEs
            matched_vulns = self._match_vulns(dep)
            for vuln in matched_vulns:
                risk = risk_engine.prioritize_finding(
                    cwe_id=vuln["cwe"],
                    vuln_name=vuln["title"],
                    cve_id=vuln["cve"],
                    provided_cvss=vuln["cvss"],
                    provided_vector=vuln["vector"]
                )
                standards = map_finding_to_standards(vuln["cwe"], "sca vulnerability")

                findings.append({
                    "rule_id": f"SCA-{vuln['cve']}",
                    "type": "sca",
                    "title": f"[{vuln['ecosystem'].upper()}] {dep['name']} - {vuln['title']}",
                    "description": vuln["description"],
                    "remediation": f"Upgrade {dep['name']} from version {dep['version']} to fixed version {vuln['fixed_version']}.",
                    "severity": risk["severity"],
                    "cwe_id": vuln["cwe"],
                    "cve_id": vuln["cve"],
                    "package_name": dep["name"],
                    "installed_version": dep["version"],
                    "fixed_version": vuln["fixed_version"],
                    "license": dep.get("license", "Unknown"),
                    "file_path": dep["manifest_path"],
                    "line_start": dep.get("line", 1),
                    "line_end": dep.get("line", 1),
                    "code_snippet": f"{dep['name']} == {dep['version']}",
                    "cvss_score": risk["metrics"]["cvss_score"],
                    "cvss_vector": risk["cvss_vector"],
                    "epss_score": risk["metrics"]["epss_score"],
                    "epss_percentile": risk["metrics"]["epss_percentile"],
                    "composite_risk_score": risk["composite_score"],
                    "quadrant": risk["quadrant"],
                    "urgency": risk["urgency"],
                    "sla_days": risk["sla_days"],
                    "reachability": reach_info["reachability"],
                    "reachability_label": reach_info["label"],
                    "reachability_files": reach_info["files"],
                    "standards": standards,
                    "status": "open"
                })

            # 2. Check License Compliance (ISO-5230 OpenChain)
            pkg_license = dep.get("license") or LICENSE_REGISTRY.get(dep["name"].lower(), "MIT")
            if pkg_license in RESTRICTED_LICENSES:
                risk = risk_engine.prioritize_finding(
                    cwe_id="CWE-1104",
                    vuln_name="Copyleft License Incompatibility",
                    provided_cvss=6.0
                )
                standards = ["ISO-5230:LIC-02", "ISO-27001:A.8.25", "CIS:CIS-2.3"]
                findings.append({
                    "rule_id": "SCA-LIC-RESTRICTED",
                    "type": "sca",
                    "title": f"Restricted License Detected: {dep['name']} ({pkg_license})",
                    "description": f"Package {dep['name']} is licensed under {pkg_license}, which imposes viral copyleft requirements on commercial software under ISO/IEC 5230.",
                    "remediation": "Replace with a permissively licensed alternative (MIT, Apache-2.0, BSD) or obtain a dual commercial license.",
                    "severity": "MEDIUM",
                    "cwe_id": "CWE-1104",
                    "cve_id": None,
                    "package_name": dep["name"],
                    "installed_version": dep["version"],
                    "fixed_version": None,
                    "license": pkg_license,
                    "file_path": dep["manifest_path"],
                    "line_start": dep.get("line", 1),
                    "line_end": dep.get("line", 1),
                    "code_snippet": f"License: {pkg_license}",
                    "cvss_score": 6.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    "epss_score": 0.02,
                    "epss_percentile": 0.35,
                    "composite_risk_score": 45.0,
                    "quadrant": "ROUTINE",
                    "urgency": "LOW",
                    "sla_days": 90,
                    "standards": standards,
                    "status": "open"
                })

        return {
            "dependencies": all_dependencies,
            "findings": findings
        }

    def _check_reachability(self, target_dir: str, pkg_name: str) -> Dict[str, Any]:
        """
        Statically checks if source code files in target_dir import or call symbols from pkg_name.
        """
        pkg_clean = pkg_name.lower().replace("-", "_")
        matched_files = []
        is_called = False

        if not target_dir or not os.path.exists(target_dir):
            return {"reachability": "IMPORTED", "label": "Imported in Manifest", "files": []}

        import_pattern = re.compile(rf"""(?:import\s+{pkg_clean}|from\s+{pkg_clean}|require\s*\(\s*['"]{pkg_name}['"]\)|import\s*.*\s*from\s*['"]{pkg_name}['"])""", re.IGNORECASE)
        call_pattern = re.compile(rf"""\b{pkg_clean}\.[a-zA-Z0-9_]+\s*\(""", re.IGNORECASE)

        try:
            for root, _, files in os.walk(target_dir):
                for file in files:
                    if file.endswith((".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".c", ".cpp")):
                        fpath = os.path.join(root, file)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                text = f.read()
                            if import_pattern.search(text):
                                rel = os.path.relpath(fpath, target_dir)
                                matched_files.append(rel)
                                if call_pattern.search(text):
                                    is_called = True
                        except Exception:
                            pass
        except Exception:
            pass

        if is_called:
            return {"reachability": "REACHABLE", "label": "Reachable & Exploitable (Symbol Invoked in Code)", "files": matched_files}
        elif matched_files:
            return {"reachability": "IMPORTED", "label": "Imported (Symbol Uncalled)", "files": matched_files}
        else:
            return {"reachability": "DORMANT", "label": "Dormant / Transitive Package", "files": []}

    def _match_vulns(self, dep: Dict[str, Any]) -> List[Dict[str, Any]]:
        matched = []
        name = dep["name"].lower()
        version = dep["version"]

        for entry in CURATED_VULN_DB:
            if entry["package"].lower() == name or entry["package"].lower().endswith(f":{name}"):
                # Basic semver check
                if self._is_version_vulnerable(version, entry["affected_versions"]):
                    matched.append(entry)
        return matched

    def _is_version_vulnerable(self, version: str, affected_ranges: List[str]) -> bool:
        if not version or version == "*" or version == "latest":
            return True

        # Clean version string
        v_clean = re.sub(r'^[^\d]*', '', version).split("-")[0]
        try:
            v_parts = [int(p) for p in v_clean.split(".") if p.isdigit()]
        except Exception:
            return False

        for rng in affected_ranges:
            if rng.startswith("<="):
                target = [int(p) for p in rng[2:].split(".") if p.isdigit()]
                if v_parts <= target:
                    return True
            elif rng.startswith("<"):
                target = [int(p) for p in rng[1:].split(".") if p.isdigit()]
                if v_parts < target:
                    return True
        return False

    # --- Manifest Parsers ---
    def _parse_requirements_txt(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match package==version or package>=version
                    match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z\.\-]+)', line)
                    if match:
                        pkg, ver = match.group(1), match.group(2)
                        deps.append({
                            "ecosystem": "pypi",
                            "name": pkg,
                            "version": ver,
                            "license": LICENSE_REGISTRY.get(pkg.lower(), "Unknown"),
                            "manifest_path": rel_path,
                            "line": idx
                        })
        except Exception:
            pass
        return deps

    def _parse_package_json(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            merged = {}
            merged.update(data.get("dependencies", {}))
            merged.update(data.get("devDependencies", {}))
            for pkg, ver_spec in merged.items():
                clean_ver = re.sub(r'[\^~>=<]', '', str(ver_spec)).strip()
                deps.append({
                    "ecosystem": "npm",
                    "name": pkg,
                    "version": clean_ver,
                    "license": LICENSE_REGISTRY.get(pkg.lower(), "MIT"),
                    "manifest_path": rel_path,
                    "line": 1
                })
        except Exception:
            pass
        return deps

    def _parse_package_lock_json(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            packages = data.get("packages", {}) or data.get("dependencies", {})
            for pkg_key, pkg_info in packages.items():
                pkg_name = pkg_key.replace("node_modules/", "")
                if not pkg_name:
                    continue
                version = pkg_info.get("version", "")
                if version:
                    deps.append({
                        "ecosystem": "npm",
                        "name": pkg_name,
                        "version": version,
                        "license": pkg_info.get("license", LICENSE_REGISTRY.get(pkg_name.lower(), "MIT")),
                        "manifest_path": rel_path,
                        "line": 1
                    })
        except Exception:
            pass
        return deps

    def _parse_pom_xml(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Parse parent pom version
            parent_match = re.search(r'<parent>[\s\S]*?<groupId>(.*?)<\/groupId>[\s\S]*?<artifactId>(.*?)<\/artifactId>[\s\S]*?<version>(.*?)<\/version>[\s\S]*?<\/parent>', content)
            parent_ver = parent_match.group(3).strip() if parent_match else None
            if parent_match:
                p_group = parent_match.group(1).strip()
                p_art = parent_match.group(2).strip()
                deps.append({
                    "ecosystem": "maven",
                    "name": f"{p_group}:{p_art}",
                    "version": parent_ver,
                    "license": "Apache-2.0",
                    "manifest_path": rel_path,
                    "line": 1
                })
                # If parent is spring-boot-starter-parent, add spring-boot as well
                if "spring-boot" in p_art:
                    deps.append({
                        "ecosystem": "maven",
                        "name": "org.springframework.boot:spring-boot",
                        "version": parent_ver,
                        "license": "Apache-2.0",
                        "manifest_path": rel_path,
                        "line": 1
                    })

            dep_blocks = re.findall(r'<dependency>[\s\S]*?<\/dependency>', content)
            for block in dep_blocks:
                g_match = re.search(r'<groupId>(.*?)<\/groupId>', block)
                a_match = re.search(r'<artifactId>(.*?)<\/artifactId>', block)
                v_match = re.search(r'<version>(.*?)<\/version>', block)
                if a_match:
                    group_id = g_match.group(1).strip() if g_match else ""
                    art_id = a_match.group(1).strip()
                    pkg_name = f"{group_id}:{art_id}" if group_id else art_id
                    version = v_match.group(1).strip() if v_match else (parent_ver or "1.0.0")
                    deps.append({
                        "ecosystem": "maven",
                        "name": pkg_name,
                        "version": version,
                        "license": LICENSE_REGISTRY.get(art_id.lower(), "Apache-2.0"),
                        "manifest_path": rel_path,
                        "line": 1
                    })
        except Exception:
            pass
        return deps

    def _parse_go_mod(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    match = re.match(r'^([a-zA-Z0-9\.\-_/]+)\s+v([0-9\.\-a-zA-Z]+)', line)
                    if match:
                        deps.append({
                            "ecosystem": "golang",
                            "name": match.group(1),
                            "version": match.group(2),
                            "license": "BSD-3-Clause",
                            "manifest_path": rel_path,
                            "line": idx
                        })
        except Exception:
            pass
        return deps

    def _parse_cargo_toml(self, path: str, rel_path: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                in_deps = False
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if line == "[dependencies]":
                        in_deps = True
                        continue
                    if line.startswith("[") and in_deps:
                        in_deps = False
                        continue
                    if in_deps and "=" in line:
                        parts = line.split("=", 1)
                        pkg = parts[0].strip()
                        ver = parts[1].strip().strip('"\'')
                        deps.append({
                            "ecosystem": "crates",
                            "name": pkg,
                            "version": ver,
                            "license": "MIT",
                            "manifest_path": rel_path,
                            "line": idx
                        })
        except Exception:
            pass
        return deps
