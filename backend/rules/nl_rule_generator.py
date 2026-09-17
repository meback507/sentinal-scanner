"""
AegisSec - Natural Language to SAST & SCA Rule Generator
Synthesizes custom security rules from plain human instructions with an offline semantic engine and optional LLM bridge.
"""

import re
import yaml
import uuid
from typing import Dict, Any, List, Optional
from ..standards.taxonomy import map_finding_to_standards


class NLRuleGenerator:
    """
    Translates human natural language into executable SAST pattern/AST rules or SCA dependency policies.
    """

    @classmethod
    def generate_from_text(cls, human_prompt: str, target_ecosystem: str = "auto") -> Dict[str, Any]:
        prompt = human_prompt.strip().lower()
        rule_id = f"RULE-{uuid.uuid4().hex[:6].upper()}"

        # 1. Determine Rule Category: SCA Policy vs SAST Code Rule
        is_sca = any(k in prompt for k in ["dependency", "package", "library", "license", "npm", "pypi", "pom", "gpl", "agpl", "version"])
        
        if is_sca and not any(k in prompt for k in ["code", "function", "variable", "pointer"]):
            return cls._synthesize_sca_rule(rule_id, human_prompt, prompt)
        else:
            return cls._synthesize_sast_rule(rule_id, human_prompt, prompt)

    @classmethod
    def _synthesize_sast_rule(cls, rule_id: str, original_prompt: str, prompt: str) -> Dict[str, Any]:
        # Detect Languages
        languages = []
        if "python" in prompt or ".py" in prompt:
            languages.append("python")
        if "javascript" in prompt or "js" in prompt or "node" in prompt:
            languages.append("javascript")
        if "typescript" in prompt or "ts" in prompt:
            languages.append("typescript")
        if "c++" in prompt or "cpp" in prompt:
            languages.append("cpp")
        if " c " in prompt or prompt.startswith("c ") or prompt.endswith(" c") or "misra" in prompt:
            languages.append("c")
            if "cpp" not in languages:
                languages.append("cpp")
        if "java" in prompt and "javascript" not in prompt:
            languages.append("java")
        if "go" in prompt or "golang" in prompt:
            languages.append("go")

        if not languages:
            languages = ["python", "javascript", "typescript", "c", "cpp", "java", "go"]

        # Detect Vulnerability Intent & Synthesize Regex Pattern
        regex = ""
        cwe = "CWE-699"
        title = original_prompt.capitalize()
        severity = "MEDIUM"
        remediation = "Follow secure coding guidelines according to ISO-27001 (A.8.28)."

        # Case: Secrets / Keys / Tokens
        if any(k in prompt for k in ["secret", "token", "password", "key", "credential", "auth"]):
            cwe = "CWE-798"
            severity = "HIGH"
            regex = r"""(?i)(?:bearer|token|secret|password|api_key|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{12,}['"]"""
            title = "Detect Hardcoded Secret or Token"
            remediation = "Never store sensitive tokens in source code. Inject via environment variables or secret vaults."

        # Case: SQL Injection
        elif any(k in prompt for k in ["sql", "sqli", "database query", "select from"]):
            cwe = "CWE-89"
            severity = "CRITICAL"
            regex = r"""(?i)(?:execute|raw|query)\s*\(\s*(?:f['"].*SELECT|['"].*SELECT.*['"]\s*\+)"""
            title = "Detect SQL Injection via String Concatenation"
            remediation = "Use parameterized SQL queries with bind variables to prevent SQL injection."

        # Case: Dynamic Code Execution / Eval / Exec
        elif any(k in prompt for k in ["eval", "exec", "dynamic execution"]):
            cwe = "CWE-95"
            severity = "CRITICAL"
            regex = r"""\b(?:eval|exec)\s*\("""
            title = "Detect Dynamic Code Evaluation via eval/exec"
            remediation = "Refactor code to use explicit control flow or safe data serialization like JSON."

        # Case: MISRA / Automotive / Memory allocation (malloc/free)
        elif any(k in prompt for k in ["malloc", "free", "dynamic memory", "misra", "autosar", "heap"]):
            cwe = "CWE-401"
            severity = "HIGH"
            languages = ["c", "cpp"]
            regex = r"""\b(?:malloc|calloc|realloc|free)\s*\("""
            title = "MISRA C:2012 / ISO-26262: Prohibit Dynamic Heap Memory"
            remediation = "In automotive and safety systems, allocate static buffers at initialization to avoid heap fragmentation."

        # Case: Insecure Deserialization / Pickle
        elif any(k in prompt for k in ["pickle", "unserialize", "deserialization", "yaml.load"]):
            cwe = "CWE-502"
            severity = "CRITICAL"
            languages = ["python"]
            regex = r"""(?i)(?:pickle\.loads|yaml\.load\s*\([^\)]*(?!SafeLoader))"""
            title = "Detect Insecure Object Deserialization"
            remediation = "Use safe parsers (e.g. yaml.safe_load) or structured schemas (JSON/Protobuf)."

        # Case: Debug Mode Enabled
        elif any(k in prompt for k in ["debug mode", "debug = true", "debug=true"]):
            cwe = "CWE-489"
            severity = "HIGH"
            regex = r"""(?i)\bDEBUG\s*=\s*True\b"""
            title = "Detect Debug Mode Enabled in Production"
            remediation = "Ensure DEBUG is disabled in production environments using environment variable checks."

        # Case: Weak Cryptography / Randomness
        elif any(k in prompt for k in ["math.random", "random", "insecure random"]):
            cwe = "CWE-330"
            severity = "MEDIUM"
            regex = r"""\bMath\.random\(\)"""
            title = "Detect Insecure Pseudo-Random Number Generator"
            remediation = "Use cryptographically secure PRNGs such as window.crypto.getRandomValues() or Python secrets module."

        # Case: Unencrypted HTTP URLs
        elif any(k in prompt for k in ["http://", "unencrypted", "cleartext"]):
            cwe = "CWE-319"
            severity = "MEDIUM"
            regex = r"""['"]http:\/\/[a-zA-Z0-9\.\-]+['"]"""
            title = "Detect Insecure Cleartext HTTP URLs"
            remediation = "Enforce HTTPS with TLS 1.3 for all endpoints."

        # Fallback keyword-based pattern
        else:
            words = [w for w in re.findall(r'[a-zA-Z0-9_]{3,}', prompt) if w not in ["detect", "flag", "rule", "code", "file", "find"]]
            if words:
                target_word = words[0]
                regex = rf"""\b{re.escape(target_word)}\s*\("""
                title = f"Detect Calls to {target_word}()"
                cwe = "CWE-699"
            else:
                regex = r"""(?i)(?:TODO|FIXME|HACK):?\s*security"""
                title = "Detect Unresolved Security Annotations"
                cwe = "CWE-546"

        standards = map_finding_to_standards(cwe, title)

        rule_dict = {
            "id": rule_id,
            "name": title,
            "type": "sast_pattern",
            "rule_category": "sast",
            "nl_prompt": original_prompt,
            "languages": languages,
            "severity": severity,
            "cwe": cwe,
            "standards": standards,
            "regex": regex,
            "description": f"Custom rule generated from instruction: '{original_prompt}'.",
            "remediation": remediation,
            "is_active": True
        }

        rule_yaml = yaml.dump(rule_dict, sort_keys=False)
        rule_dict["yaml_representation"] = rule_yaml
        return rule_dict

    @classmethod
    def _synthesize_sca_rule(cls, rule_id: str, original_prompt: str, prompt: str) -> Dict[str, Any]:
        license_match = re.search(r'\b(gpl-?[0-9\.]*|agpl-?[0-9\.]*|mit|apache-?[0-9\.]*|bsd)\b', prompt)
        banned_license = license_match.group(1).upper() if license_match else "AGPL-3.0"

        # Check for package name
        pkg_match = re.search(r'(?:package|library|dependency)\s+([a-zA-Z0-9_\-\./]+)', prompt)
        pkg_name = pkg_match.group(1) if pkg_match else "*"

        rule_dict = {
            "id": rule_id,
            "name": f"SCA Policy: Restrict {pkg_name} / License {banned_license}",
            "type": "sca_policy",
            "rule_category": "sca",
            "nl_prompt": original_prompt,
            "target_package": pkg_name,
            "banned_license": banned_license,
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "standards": ["ISO-5230:LIC-02", "ISO-27001:A.8.25", "NIST-SSDF:PW.8"],
            "description": f"Enforces dependency policy restricting package '{pkg_name}' or license '{banned_license}'.",
            "remediation": "Audit licenses against ISO/IEC 5230 OpenChain standard and substitute non-compliant packages.",
            "is_active": True
        }

        rule_yaml = yaml.dump(rule_dict, sort_keys=False)
        rule_dict["yaml_representation"] = rule_yaml
        return rule_dict

    @classmethod
    def test_rule_against_code(cls, rule_yaml_or_dict: Any, sample_code: str, language: str = "python") -> Dict[str, Any]:
        """
        Executes a generated rule against a live code snippet in the test bench sandbox.
        """
        if isinstance(rule_yaml_or_dict, str):
            try:
                rule = yaml.safe_load(rule_yaml_or_dict)
            except Exception as e:
                return {"success": False, "error": f"Invalid YAML syntax: {str(e)}", "matches": []}
        else:
            rule = rule_yaml_or_dict

        pattern = rule.get("regex")
        if not pattern:
            return {"success": False, "error": "No valid regex pattern found in rule.", "matches": []}

        matches = []
        lines = sample_code.splitlines()

        try:
            for match in re.finditer(pattern, sample_code):
                start_char = match.start()
                line_no = sample_code.count("\n", 0, start_char) + 1
                matched_text = match.group(0)
                
                # Context snippet
                ctx_start = max(0, line_no - 2)
                ctx_end = min(len(lines), line_no + 2)
                ctx_lines = []
                for i in range(ctx_start, ctx_end):
                    curr = i + 1
                    prefix = " > " if curr == line_no else "   "
                    line_content = lines[i] if i < len(lines) else ""
                    ctx_lines.append(f"{curr:3d}{prefix}{line_content}")

                matches.append({
                    "line": line_no,
                    "matched_text": matched_text,
                    "snippet": "\n".join(ctx_lines)
                })

            return {
                "success": True,
                "matched_count": len(matches),
                "matches": matches,
                "rule_name": rule.get("name"),
                "severity": rule.get("severity")
            }
        except Exception as e:
            return {"success": False, "error": str(e), "matches": []}
