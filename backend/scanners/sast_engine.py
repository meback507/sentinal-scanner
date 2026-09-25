"""
AegisSec - SAST (Static Application Security Testing) Engine
Analyzes source code across languages for vulnerabilities, secret leaks, injection flaws, and MISRA/safety violations.
"""

import os
import re
import ast
from typing import List, Dict, Any
from ..standards.taxonomy import map_finding_to_standards
from ..prioritization.risk_engine import risk_engine


# Built-in multi-language SAST rule patterns
CORE_BUILTIN_RULES = [
    # --- Secrets & Credentials ---
    {
        "id": "SEC-001",
        "name": "Hardcoded API Key or Secret Token",
        "cwe": "CWE-798",
        "languages": ["python", "javascript", "typescript", "java", "go", "c", "cpp", "php", "ruby"],
        "regex": r"""(?i)(?:api_key|apikey|secret|token|password|passwd|private_key|aws_secret_access_key)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{16,}['"]""",
        "description": "Hardcoded credentials or API secrets found in source code, violating ISO 27001 (A.8.12) and CIS Software Supply Chain controls.",
        "remediation": "Extract secrets into environment variables, HashiCorp Vault, or cloud secret managers (AWS Secrets Manager/Azure Key Vault)."
    },
    {
        "id": "SEC-002",
        "name": "Hardcoded Private Cryptographic Key Block",
        "cwe": "CWE-798",
        "languages": ["python", "javascript", "typescript", "java", "go", "c", "cpp", "php", "ruby", "shell"],
        "regex": r"""-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----""",
        "description": "Hardcoded private encryption key embedded in source code.",
        "remediation": "Immediately revoke and rotate this private key. Inject keys via secure deployment secrets."
    },

    # --- SQL Injection ---
    {
        "id": "INJ-001",
        "name": "SQL Injection via String Concatenation or Formatting",
        "cwe": "CWE-89",
        "languages": ["python", "javascript", "typescript", "java", "php", "go"],
        "regex": r"""(?i)(?:execute|query|raw|cursor\.execute)\s*\(\s*(?:f['"].*SELECT.*\{|['"].*SELECT.*['"]\s*\+|\`.*SELECT.*\$\{)""",
        "description": "SQL query dynamically constructed using raw string interpolation instead of parameterized queries.",
        "remediation": "Use parameterized queries or ORM query builders (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)))"
    },

    # --- Command Injection & RCE ---
    {
        "id": "RCE-001",
        "name": "OS Command Injection via Shell Execution",
        "cwe": "CWE-78",
        "languages": ["python", "javascript", "typescript", "php", "ruby"],
        "regex": r"""(?i)(?:os\.system|subprocess\.call|subprocess\.Popen|exec|shell_exec|system|popen)\s*\(\s*(?:f['"]|[^\)]*shell\s*=\s*True|[^\)]*\+)""",
        "description": "Executing system shell commands with concatenated or unsanitized input leads to Remote Code Execution.",
        "remediation": "Avoid invoking shell directly; pass arguments as an immutable array with shell=False, or use safe native APIs."
    },

    # --- Insecure Deserialization ---
    {
        "id": "DES-001",
        "name": "Insecure Deserialization via Python pickle or unsafe yaml",
        "cwe": "CWE-502",
        "languages": ["python"],
        "regex": r"""(?i)(?:pickle\.loads|cPickle\.loads|_pickle\.loads|yaml\.load\s*\([^\)]*(?!Loader=yaml\.SafeLoader))""",
        "description": "Unpickling untrusted data or loading YAML without SafeLoader can lead to arbitrary code execution.",
        "remediation": "Use JSON or `yaml.safe_load()`. Avoid deserializing untrusted binary streams with pickle."
    },

    # --- Cross-Site Scripting (XSS) ---
    {
        "id": "XSS-001",
        "name": "DOM-Based Cross-Site Scripting via innerHTML",
        "cwe": "CWE-79",
        "languages": ["javascript", "typescript"],
        "regex": r"""(?i)(?:\.innerHTML|\.outerHTML|document\.write)\s*=\s*""",
        "description": "Writing unescaped data directly into the DOM allows malicious script injection in user browsers.",
        "remediation": "Use textContent, innerText, or modern framework data bindings (React JSX / Vue templates) which escape content by default."
    },

    # --- Weak Cryptography ---
    {
        "id": "CRY-001",
        "name": "Use of Broken / Deprecated Hash Algorithm (MD5/SHA1)",
        "cwe": "CWE-327",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        "regex": r"""(?i)(?:hashlib\.md5|hashlib\.sha1|crypto\.createHash\(['"](?:md5|sha1)['"]\)|MD5_Init|SHA1_Init)""",
        "description": "MD5 and SHA1 are cryptographically broken with known collision attacks.",
        "remediation": "Migrate to SHA-256, SHA-3, or password-hashing functions like Argon2id or bcrypt."
    },

    # --- Automotive / Safety / MISRA C/C++ ---
    {
        "id": "MISRA-001",
        "name": "MISRA C:2012 Rule 21.3 / ISO 26262 ASIL: Dynamic Memory Allocation in Safety-Critical Code",
        "cwe": "CWE-401",
        "languages": ["c", "cpp"],
        "regex": r"""\b(?:malloc|calloc|realloc|free)\s*\(""",
        "description": "Dynamic heap allocation causes non-deterministic execution times, heap fragmentation, and potential memory leaks in safety-critical automotive software.",
        "remediation": "Use statically allocated buffers or deterministic memory pools configured at startup."
    },
    {
        "id": "MISRA-002",
        "name": "MISRA C:2012 / CWE-119: Unbounded String Function Usage (strcpy / sprintf / gets)",
        "cwe": "CWE-119",
        "languages": ["c", "cpp"],
        "regex": r"""\b(?:strcpy|sprintf|gets|strcat)\s*\(""",
        "description": "Unbounded string operations do not check buffer bounds, causing buffer overflow vulnerabilities and memory corruption.",
        "remediation": "Use bounded alternatives like `strncpy`, `snprintf`, or safe string wrappers with explicit length validation."
    },
    {
        "id": "AUTOSAR-001",
        "name": "AUTOSAR C++14 Rule A18-5-2: Unbounded C++ Dynamic Allocation 'new' in Real-time loop",
        "cwe": "CWE-119",
        "languages": ["cpp"],
        "regex": r"""\bnew\s+[a-zA-Z0-9_]+(?:\[|\()""",
        "description": "Heap allocation via operator new inside safety-critical loops violates AUTOSAR real-time deterministic safety.",
        "remediation": "Allocate required objects during system initialization or use stack-based RAII objects."
    },

    # --- Path Traversal ---
    {
        "id": "PTH-001",
        "name": "Arbitrary File Path Traversal",
        "cwe": "CWE-22",
        "languages": ["python", "javascript", "typescript", "java", "go", "php"],
        "regex": r"""(?i)(?:open|fs\.readFile|fs\.readFileSync)\s*\(\s*(?:req\.params|req\.query|request\.args|\.\./)""",
        "description": "Directly referencing user-supplied path variables permits directory traversal and unauthorized file reading.",
        "remediation": "Validate input against a whitelist or use `os.path.abspath` to verify the path remains within the intended root directory."
    }
]

from ..rules.sonar_rules_db import SONARQUBE_SAST_RULES

# Built-in multi-language SAST default rule set: incorporates core security patterns and complete SonarQube RSPEC rules
BUILTIN_SAST_RULES = list(CORE_BUILTIN_RULES) + [dict(r) for r in SONARQUBE_SAST_RULES]


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".php": "php",
    ".rb": "ruby",
    ".sh": "shell",
    ".bash": "shell"
}


class SASTEngine:
    def __init__(self, custom_rules: List[Dict[str, Any]] = None, include_open_db: bool = True):
        self.rules = list(BUILTIN_SAST_RULES)
        if include_open_db:
            try:
                from ..rules.open_rule_database import open_rule_db
                open_rules = open_rule_db.get_all_rules(active_only=True)
                for r in open_rules:
                    if not any(existing.get("id") == r.get("id") for existing in self.rules):
                        self.rules.append(r)
            except Exception:
                pass
        if custom_rules:
            for r in custom_rules:
                if not any(existing.get("id") == r.get("id") for existing in self.rules):
                    self.rules.append(r)

    def scan_directory(self, target_dir: str, max_files: int = 2000) -> List[Dict[str, Any]]:
        """
        Recursively scans a directory for security flaws using regex and AST analysis.
        """
        # Automatically discover and load project-level custom rules (.sentinel/rules.yaml)
        try:
            from ..rules.rule_manager import rule_manager
            proj_rules = rule_manager.load_project_rules(target_dir)
            for r in proj_rules:
                if r.get("type", "sast").lower() in ["sast", "secret", "sast_pattern"]:
                    if not any(existing.get("id") == r.get("id") for existing in self.rules):
                        self.rules.append(r)
        except Exception as e:
            pass

        findings = []
        files_scanned = 0

        for root, dirs, files in os.walk(target_dir):
            # Skip noise directories
            dirs[:] = [d for d in dirs if d not in [
                ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"
            ]]

            for file in files:
                if files_scanned >= max_files:
                    break

                ext = os.path.splitext(file)[1].lower()
                lang = LANGUAGE_EXTENSIONS.get(ext)
                if not lang:
                    continue

                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, target_dir)

                file_findings = self.scan_file(full_path, rel_path, lang)
                findings.extend(file_findings)
                files_scanned += 1

        return findings

    def scan_file(self, full_path: str, rel_path: str, language: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        content = "".join(lines)

        # 1. Pattern / Regex Rule Matching
        for rule in self.rules:
            if language not in rule.get("languages", []):
                continue

            pattern_str = rule.get("regex")
            if not pattern_str:
                continue

            try:
                for match in re.finditer(pattern_str, content):
                    # Compute line number
                    start_char = match.start()
                    line_start = content.count("\n", 0, start_char) + 1
                    line_end = line_start + match.group(0).count("\n")

                    snippet = self._extract_snippet(lines, line_start, line_end)
                    standards = map_finding_to_standards(rule.get("cwe"), rule.get("name"))
                    risk = risk_engine.prioritize_finding(
                        cwe_id=rule.get("cwe"),
                        vuln_name=rule.get("name")
                    )

                    finding_data = {
                        "rule_id": rule.get("id"),
                        "type": "sast",
                        "title": rule.get("name"),
                        "description": rule.get("description"),
                        "remediation": rule.get("remediation"),
                        "severity": risk["severity"],
                        "cwe_id": rule.get("cwe"),
                        "cve_id": None,
                        "language": language,
                        "file_path": rel_path,
                        "line_start": line_start,
                        "line_end": line_end,
                        "code_snippet": snippet,
                        "cvss_score": risk["metrics"]["cvss_score"],
                        "cvss_vector": risk["cvss_vector"],
                        "epss_score": risk["metrics"]["epss_score"],
                        "epss_percentile": risk["metrics"]["epss_percentile"],
                        "composite_risk_score": risk["composite_score"],
                        "quadrant": risk["quadrant"],
                        "urgency": risk["urgency"],
                        "sla_days": risk["sla_days"],
                        "standards": standards,
                        "status": "open"
                    }
                    if rule.get("sonar_key"):
                        finding_data["sonar_key"] = rule.get("sonar_key")
                    if rule.get("sonar_rule_id"):
                        finding_data["sonar_rule_id"] = rule.get("sonar_rule_id")
                    if rule.get("sonar_type"):
                        finding_data["sonar_type"] = rule.get("sonar_type")
                    if rule.get("sonar_severity"):
                        finding_data["sonar_severity"] = rule.get("sonar_severity")
                    if rule.get("rule_source"):
                        finding_data["rule_source"] = rule.get("rule_source")

                    findings.append(finding_data)
            except Exception:
                continue

        # 2. Python-specific AST verification
        if language == "python":
            findings.extend(self._scan_python_ast(content, lines, rel_path))

        return findings

    def _scan_python_ast(self, content: str, lines: List[str], rel_path: str) -> List[Dict[str, Any]]:
        ast_findings = []
        try:
            tree = ast.parse(content)
        except Exception:
            return ast_findings

        for node in ast.walk(tree):
            # Check for eval() or exec()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec"):
                    line_no = node.lineno
                    snippet = self._extract_snippet(lines, line_no, line_no)
                    risk = risk_engine.prioritize_finding("CWE-95", "Dynamic Code Evaluation (eval/exec)")
                    ast_findings.append({
                        "rule_id": "PY-AST-001",
                        "type": "sast",
                        "title": f"Use of dynamic code execution via {node.func.id}()",
                        "description": "Calling eval() or exec() on untrusted or dynamic strings creates arbitrary code execution vulnerabilities.",
                        "remediation": "Use `ast.literal_eval()` if evaluating safe literals, or rewrite using static dictionary lookups.",
                        "severity": risk["severity"],
                        "cwe_id": "CWE-95",
                        "cve_id": None,
                        "language": "python",
                        "file_path": rel_path,
                        "line_start": line_no,
                        "line_end": line_no,
                        "code_snippet": snippet,
                        "cvss_score": risk["metrics"]["cvss_score"],
                        "cvss_vector": risk["cvss_vector"],
                        "epss_score": risk["metrics"]["epss_score"],
                        "epss_percentile": risk["metrics"]["epss_percentile"],
                        "composite_risk_score": risk["composite_score"],
                        "quadrant": risk["quadrant"],
                        "urgency": risk["urgency"],
                        "sla_days": risk["sla_days"],
                        "standards": map_finding_to_standards("CWE-95", "eval"),
                        "status": "open"
                    })
        return ast_findings

    def _extract_snippet(self, lines: List[str], line_start: int, line_end: int, context_lines: int = 2) -> str:
        idx_start = max(0, line_start - 1 - context_lines)
        idx_end = min(len(lines), line_end + context_lines)
        
        snippet_lines = []
        for i in range(idx_start, idx_end):
            curr_line_no = i + 1
            prefix = " > " if line_start <= curr_line_no <= line_end else "   "
            line_text = lines[i].rstrip("\r\n")
            snippet_lines.append(f"{curr_line_no:4d}{prefix}{line_text}")
        return "\n".join(snippet_lines)
