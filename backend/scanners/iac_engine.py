"""
AegisSec - Infrastructure as Code (IaC) & Container Security Engine
Scans Dockerfiles, docker-compose, Terraform, Kubernetes manifests, and CI/CD workflows
for misconfigurations, privilege escalations, and security violations.
"""

import os
import re
from typing import List, Dict, Any
from ..standards.taxonomy import map_finding_to_standards
from ..prioritization.risk_engine import risk_engine


IAC_RULES = [
    # --- Dockerfile & Container Hardening ---
    {
        "id": "IAC-DOCKER-001",
        "name": "Container Process Running as Root User",
        "cwe": "CWE-250",
        "file_types": ["dockerfile"],
        "severity": "HIGH",
        "description": "Dockerfile does not specify a non-root USER instruction. Running containerized processes as root increases blast radius upon container breakout.",
        "remediation": "Create a dedicated unprivileged user and switch to it before CMD/ENTRYPOINT (e.g. `RUN useradd -m appuser && USER appuser`).",
        "standards": ["CIS:CIS-Docker-4.1", "NIST-800-53:AC-6", "ISO-27001:A.8.28"],
        "cvss": 7.8,
        "epss": 0.05
    },
    {
        "id": "IAC-DOCKER-002",
        "name": "Insecure Pipe to Shell (curl/wget | sh)",
        "cwe": "CWE-78",
        "file_types": ["dockerfile", "ci"],
        "regex": r"""(?i)(?:curl|wget)\s+[^\n\|]+\|\s*(?:ba)?sh""",
        "severity": "HIGH",
        "description": "Piping untrusted remote scripts directly into bash executes unverified code without checksum or integrity verification.",
        "remediation": "Download the script first, verify its SHA-256 cryptographic checksum, and then execute.",
        "standards": ["OWASP:A03:2021", "NIST-SSDF:PW.8", "ISO-27001:A.8.25"],
        "cvss": 8.1,
        "epss": 0.18
    },
    {
        "id": "IAC-DOCKER-003",
        "name": "Unpinned or Mutable Base Image Tag (:latest)",
        "cwe": "CWE-1104",
        "file_types": ["dockerfile"],
        "regex": r"""(?i)^FROM\s+[a-zA-Z0-9_\-\.\/]+:(?:latest)\b|^FROM\s+[a-zA-Z0-9_\-\.\/]+(?:\s+AS\s+\w+)?$""",
        "severity": "MEDIUM",
        "description": "Base image uses mutable ':latest' tag or omits tag, breaking build reproducibility and exposing deployments to unexpected supply chain modifications.",
        "remediation": "Pin base images to an immutable SHA-256 digest or explicit semantic version (e.g. `FROM alpine:3.19.1@sha256:...`).",
        "standards": ["CIS:CIS-Docker-4.3", "NIST-SSDF:PW.8", "ISO-27001:A.8.25"],
        "cvss": 5.3,
        "epss": 0.02
    },
    {
        "id": "IAC-DOCKER-004",
        "name": "Dangerous Daemon Port Exposed (SSH / Docker Socket)",
        "cwe": "CWE-200",
        "file_types": ["dockerfile", "compose"],
        "regex": r"""(?i)EXPOSE\s+.*(?:22|2375|2376)\b|ports:\s*.*\b(?:22:22|2375:2375)""",
        "severity": "HIGH",
        "description": "Exposing SSH (port 22) or unauthenticated Docker daemon sockets (2375/2376) inside application containers invites lateral privilege escalation.",
        "remediation": "Remove SSH from containers. Use `docker exec` or cloud session managers for container inspection instead.",
        "standards": ["CIS:CIS-Docker-5.1", "ISO-27001:A.8.20"],
        "cvss": 7.5,
        "epss": 0.12
    },
    {
        "id": "IAC-DOCKER-005",
        "name": "Missing Container Healthcheck Definition",
        "cwe": "CWE-778",
        "file_types": ["dockerfile"],
        "severity": "LOW",
        "description": "Dockerfile lacks HEALTHCHECK instruction, preventing container orchestrators from detecting hung or unhealthy processes.",
        "remediation": "Add a `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:8000/health || exit 1` instruction.",
        "standards": ["CIS:CIS-Docker-4.6", "ISO-27001:A.8.28"],
        "cvss": 3.7,
        "epss": 0.01
    },

    # --- Terraform Misconfigurations ---
    {
        "id": "IAC-TF-001",
        "name": "S3 Bucket Public Read/Write Access Enabled",
        "cwe": "CWE-732",
        "file_types": ["terraform"],
        "regex": r"""(?i)acl\s*=\s*["'](?:public-read|public-read-write)["']""",
        "severity": "CRITICAL",
        "description": "Cloud object storage bucket is configured with public read/write ACL, risking catastrophic data exfiltration or public overwrite.",
        "remediation": "Set `acl = \"private\"` and enable `aws_s3_bucket_public_access_block` to enforce strict block on public ACLs.",
        "standards": ["CIS:CIS-AWS-2.1.5", "ISO-27001:A.8.12", "NIST-800-53:AC-3"],
        "cvss": 9.1,
        "epss": 0.62
    },
    {
        "id": "IAC-TF-002",
        "name": "Overly Permissive IAM Wildcard Action (*)",
        "cwe": "CWE-269",
        "file_types": ["terraform"],
        "regex": r"""(?i)["']Action["']\s*:\s*(?:\[\s*["']\*["']\s*\]|["']\*["'])""",
        "severity": "HIGH",
        "description": "IAM Policy grants blanket wildcard administrative permissions (`Action: *`), violating the principle of least privilege.",
        "remediation": "Scope IAM policy statements to specific, required actions (e.g. `s3:GetObject`, `sqs:SendMessage`).",
        "standards": ["CIS:CIS-AWS-1.16", "NIST-800-53:AC-6", "ISO-27001:A.8.2"],
        "cvss": 8.2,
        "epss": 0.15
    },
    {
        "id": "IAC-TF-003",
        "name": "Unencrypted Cloud Storage or Database Volume",
        "cwe": "CWE-311",
        "file_types": ["terraform"],
        "regex": r"""(?i)(?:storage_encrypted|encrypted)\s*=\s*false""",
        "severity": "HIGH",
        "description": "Storage volume or database instance explicitly disables encryption at rest.",
        "remediation": "Set `storage_encrypted = true` and specify a customer-managed KMS key.",
        "standards": ["ISO-27001:A.8.24", "PCI-DSS:Req-3.4", "NIST-800-53:SC-28"],
        "cvss": 7.4,
        "epss": 0.04
    },

    # --- Kubernetes Manifests ---
    {
        "id": "IAC-K8S-001",
        "name": "Kubernetes Privileged Container Execution",
        "cwe": "CWE-250",
        "file_types": ["k8s"],
        "regex": r"""(?i)privileged\s*:\s*true""",
        "severity": "CRITICAL",
        "description": "Pod security context grants root host access via `privileged: true`. Containers can manipulate host kernel devices and escape isolation.",
        "remediation": "Remove `privileged: true` and grant fine-grained Linux capabilities (e.g. `capabilities: add: [\"NET_BIND_SERVICE\"]`) only if strictly required.",
        "standards": ["CIS:CIS-K8s-5.2.1", "NIST-800-53:AC-6", "ISO-27001:A.8.28"],
        "cvss": 9.5,
        "epss": 0.45
    },
    {
        "id": "IAC-K8S-002",
        "name": "Pod Shares Host Process or Network Namespace",
        "cwe": "CWE-250",
        "file_types": ["k8s"],
        "regex": r"""(?i)(?:hostPID|hostNetwork|hostIPC)\s*:\s*true""",
        "severity": "HIGH",
        "description": "Pod shares the host process ID, network, or IPC namespace, allowing processes in the container to inspect or kill host processes.",
        "remediation": "Set `hostPID: false`, `hostNetwork: false`, and `hostIPC: false`.",
        "standards": ["CIS:CIS-K8s-5.2.2", "ISO-27001:A.8.20"],
        "cvss": 8.0,
        "epss": 0.11
    },

    # --- GitHub Actions CI/CD Workflows ---
    {
        "id": "IAC-CI-001",
        "name": "Overly Permissive CI Workflow Permissions (write-all)",
        "cwe": "CWE-269",
        "file_types": ["ci"],
        "regex": r"""(?i)permissions\s*:\s*write-all""",
        "severity": "HIGH",
        "description": "GitHub Actions workflow grants blanket `write-all` permissions to the GITHUB_TOKEN, creating supply chain escalation paths on PR execution.",
        "remediation": "Explicitly grant least-privilege token scopes (e.g. `permissions: contents: read, pull-requests: write`).",
        "standards": ["CIS:CIS-GitHub-1.2", "NIST-SSDF:PW.8", "ISO-27001:A.8.25"],
        "cvss": 7.6,
        "epss": 0.08
    },
    {
        "id": "IAC-CI-002",
        "name": "Unpinned 3rd-Party GitHub Action Branch Tag",
        "cwe": "CWE-829",
        "file_types": ["ci"],
        "regex": r"""(?i)uses\s*:\s*[a-zA-Z0-9_\-\.\/]+@(?:main|master)\b""",
        "severity": "MEDIUM",
        "description": "Workflow invokes third-party action using mutable branch reference (@main/@master) instead of an immutable full-length commit SHA.",
        "remediation": "Pin action to immutable full commit hash (e.g. `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`).",
        "standards": ["CIS:CIS-GitHub-1.3", "NIST-SSDF:PW.8", "ISO-27001:A.8.25"],
        "cvss": 6.1,
        "epss": 0.05
    }
]


class IaCEngine:
    def __init__(self):
        pass

    def scan_directory(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        if not os.path.exists(target_dir):
            return findings

        for root, dirs, files in os.walk(target_dir):
            # Exclude vendor and hidden directories
            dirs[:] = [d for d in dirs if d not in [".git", "node_modules", "vendor", ".venv", "__pycache__"]]

            for fname in files:
                fpath = os.path.join(root, fname)
                rel_path = os.path.relpath(fpath, target_dir)
                file_type = self._classify_file(fname, rel_path)
                if not file_type:
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    file_content = "".join(lines)
                except Exception:
                    continue

                # Run pattern-based checks
                for rule in IAC_RULES:
                    if file_type not in rule["file_types"]:
                        continue

                    regex_pat = rule.get("regex")
                    if regex_pat:
                        for idx, line in enumerate(lines):
                            if re.search(regex_pat, line):
                                finding = self._build_finding(rule, rel_path, idx + 1, idx + 1, line.strip())
                                findings.append(finding)
                    else:
                        # Structural check (e.g. missing USER or missing HEALTHCHECK in Dockerfile)
                        if rule["id"] == "IAC-DOCKER-001":
                            has_user = any(re.match(r"""(?i)^\s*USER\s+\S+""", l) for l in lines)
                            if not has_user and len(lines) > 0:
                                finding = self._build_finding(rule, rel_path, 1, 1, lines[0].strip())
                                findings.append(finding)
                        elif rule["id"] == "IAC-DOCKER-005":
                            has_hc = any(re.match(r"""(?i)^\s*HEALTHCHECK\b""", l) for l in lines)
                            if not has_hc and len(lines) > 0:
                                finding = self._build_finding(rule, rel_path, 1, 1, lines[0].strip())
                                findings.append(finding)

        return findings

    def _classify_file(self, fname: str, rel_path: str) -> str:
        low_name = fname.lower()
        low_path = rel_path.lower()

        if low_name == "dockerfile" or low_name.startswith("dockerfile.") or low_name == "containerfile":
            return "dockerfile"
        if "docker-compose" in low_name and (low_name.endswith(".yml") or low_name.endswith(".yaml")):
            return "compose"
        if low_name.endswith(".tf") or low_name.endswith(".tfvars"):
            return "terraform"
        if ".github/workflows" in low_path and (low_name.endswith(".yml") or low_name.endswith(".yaml")):
            return "ci"
        if (low_name.endswith(".yaml") or low_name.endswith(".yml")) and any(k in low_path for k in ["k8s", "helm", "manifest", "deploy", "kubernetes"]):
            return "k8s"
        return ""

    def _build_finding(self, rule: Dict[str, Any], file_path: str, line_start: int, line_end: int, snippet: str) -> Dict[str, Any]:
        severity = rule["severity"]
        cvss = rule.get("cvss", 7.0)
        epss = rule.get("epss", 0.05)

        prioritization = risk_engine.calculate_finding_priority(
            cvss_score=cvss,
            epss_score=epss,
            standards=rule["standards"]
        )

        return {
            "type": "iac",
            "title": f"[{rule['id']}] {rule['name']}",
            "description": rule["description"],
            "remediation": rule["remediation"],
            "severity": severity,
            "cwe_id": rule["cwe"],
            "cve_id": None,
            "language": "iac",
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": snippet[:200],
            "cvss_score": cvss,
            "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if severity in ['CRITICAL', 'HIGH'] else 'L'}/I:{'H' if severity in ['CRITICAL', 'HIGH'] else 'L'}/A:N",
            "epss_score": epss,
            "epss_percentile": 0.50,
            "composite_risk_score": prioritization["composite_risk_score"],
            "quadrant": prioritization["quadrant"],
            "urgency": prioritization["urgency"],
            "sla_days": prioritization["sla_days"],
            "standards": rule["standards"],
            "status": "open"
        }
