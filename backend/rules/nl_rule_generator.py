"""
AegisSec - Natural Language to SAST & SCA Rule Generator
Synthesizes custom security rules from plain human instructions with an offline semantic engine and optional LLM bridge.
Avoids hardcoding by decomposing natural language requirements into an extensible semantic taxonomy.
"""

import re
import yaml
import uuid
from typing import Dict, Any, List, Optional
from ..standards.taxonomy import map_finding_to_standards


class SemanticConceptMatch:
    """Represents a matched security concept produced by semantic analysis."""
    def __init__(
        self,
        name: str,
        cwe: str,
        severity: str,
        regex: str,
        remediation: str,
        standards: List[str],
        sample_trigger_code: str,
        languages: Optional[List[str]] = None,
        rule_category: str = "sast"
    ):
        self.name = name
        self.cwe = cwe
        self.severity = severity
        self.regex = regex
        self.remediation = remediation
        self.standards = standards
        self.sample_trigger_code = sample_trigger_code
        self.languages = languages
        self.rule_category = rule_category


class SemanticRuleParser:
    """
    Generalized semantic parser that interprets natural language instructions
    into formal SAST/SCA security policies without hardcoding specific prompts.
    Uses token ontology, grammatical relations, and security taxonomy mapping.
    """

    # Mathematical & Arithmetic Hazard Lexicon
    DIV_MOD_OPS = {"divide", "divided", "dividing", "division", "div", "modulo", "mod", "remainder", "/", "//", "%"}
    ZERO_OPERANDS = {"zero", "0", "0.0", "0x0", "nil", "null", "none"}
    FLOAT_TYPES = {"float", "floating", "double", "float32", "float64"}
    EQUALITY_OPS = {"equal", "equals", "equality", "==", "!=", "comparing", "comparison", "exact"}

    # Memory & Lifecycle APIs
    MEMORY_APIS = {"malloc", "calloc", "realloc", "free", "alloca", "valloc", "brk", "sbrk"}

    # Dynamic Code Execution APIs
    EXEC_APIS = {"eval", "exec", "function", "system", "popen", "execve", "spawn"}

    # Insecure Buffer/String APIs
    UNSAFE_STRING_APIS = {"gets", "strcpy", "strcat", "sprintf", "vsprintf", "scanf"}

    # Pseudo-Random Number Generators
    PRNG_APIS = {"math.random", "rand", "random", "srand", "drand48"}

    # Deserialization APIs
    DESERIALIZE_APIS = {"pickle", "unserialize", "yaml.load", "readobject", "deserialization"}

    # Secrets & Credentials Lexicon
    SECRET_TOKENS = {"secret", "token", "password", "key", "credential", "auth", "bearer", "api_key", "client_secret", "private_key"}

    # Injection Lexicon
    INJECTION_TOKENS = {"sql", "sqli", "database query", "select from", "query execution", "sql injection"}

    # Stopwords for universal fallback extraction
    STOPWORDS = {
        "anything", "nothing", "everything", "something", "any", "all", "each", "every",
        "is", "are", "was", "were", "be", "been", "being", "not", "no", "nor",
        "possible", "impossible", "allowed", "disallowed", "permitted", "forbidden",
        "should", "must", "can", "cannot", "could", "would", "shall", "might",
        "to", "the", "a", "an", "of", "in", "for", "on", "with", "by", "from", "at", "as",
        "into", "through", "during", "before", "after", "above", "below", "under",
        "detect", "flag", "rule", "code", "file", "find", "check", "ensure", "prohibit",
        "disallow", "ban", "prevent", "avoid", "look", "search", "warn", "fail", "pass",
        "when", "where", "why", "how", "what", "which", "who", "whom", "this", "that"
    }

    @classmethod
    def parse_languages(cls, prompt_lower: str) -> List[str]:
        languages = []
        if "python" in prompt_lower or ".py" in prompt_lower:
            languages.append("python")
        if "javascript" in prompt_lower or "js" in prompt_lower or "node" in prompt_lower:
            languages.append("javascript")
        if "typescript" in prompt_lower or "ts" in prompt_lower:
            languages.append("typescript")
        if "c++" in prompt_lower or "cpp" in prompt_lower:
            languages.append("cpp")
        if " c " in prompt_lower or prompt_lower.startswith("c ") or prompt_lower.endswith(" c") or "misra" in prompt_lower:
            languages.append("c")
            if "cpp" not in languages:
                languages.append("cpp")
        if "java" in prompt_lower and "javascript" not in prompt_lower:
            languages.append("java")
        if "go" in prompt_lower or "golang" in prompt_lower:
            languages.append("go")
        if "csharp" in prompt_lower or "c#" in prompt_lower or ".net" in prompt_lower:
            languages.append("csharp")

        if not languages:
            languages = ["python", "javascript", "typescript", "c", "cpp", "java", "go"]
        return languages

    @classmethod
    def parse(cls, original_prompt: str, target_ecosystem: str = "auto") -> SemanticConceptMatch:
        prompt_lower = original_prompt.strip().lower()
        # Extract word and operator tokens
        tokens = set(re.findall(r"[a-zA-Z0-9_\.\/%]+", prompt_lower))
        languages = cls.parse_languages(prompt_lower)

        # 1. Arithmetic & Mathematical Hazard Analysis
        # Concept: Division or Modulo by Zero (CWE-369)
        has_div_op = bool(tokens & cls.DIV_MOD_OPS) or any(op in prompt_lower for op in ["/ 0", "/0", "% 0", "%0", "div 0"])
        has_zero_operand = bool(tokens & cls.ZERO_OPERANDS) or "0" in prompt_lower
        if has_div_op and has_zero_operand:
            regex = r"""(?:[/]{1,2}|%|\b(?:div|mod)\b)\s*(?:\(\s*0+(?:\.0*)?(?:[xX]0+)?\s*\)|0+(?:\.0*)?(?:[xX]0+)?\b)"""
            sample_code = (
                "def calculate_ratio(total, count):\n"
                "    # Violation: Division by zero hazard\n"
                "    result = total / 0\n"
                "    return result\n"
            )
            return SemanticConceptMatch(
                name="Prohibit Division or Modulo by Zero (CWE-369)",
                cwe="CWE-369",
                severity="HIGH",
                regex=regex,
                remediation="Ensure denominator/divisor is validated for non-zero before executing division or modulo operations.",
                standards=["CWE-369", "ISO-27001:A.8.28", "MISRA C:2012 Rule 12.4", "CERT:NUM52-J"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # Concept: Floating-Point Strict Equality (CWE-1077)
        has_float = bool(tokens & cls.FLOAT_TYPES)
        has_equality = bool(tokens & cls.EQUALITY_OPS) or "==" in prompt_lower
        if has_float and has_equality:
            regex = r"""\b(?:float|double)\b.*==|==\s*[-+]?[0-9]+\.[0-9]+"""
            sample_code = (
                "def check_limit(sensor_reading):\n"
                "    # Violation: Strict equality comparison on floating-point number\n"
                "    if sensor_reading == 36.6:\n"
                "        return True\n"
                "    return False\n"
            )
            return SemanticConceptMatch(
                name="Avoid Strict Floating-Point Equality Comparison (CWE-1077)",
                cwe="CWE-1077",
                severity="MEDIUM",
                regex=regex,
                remediation="Compare floating point values using an epsilon threshold tolerance (`abs(a - b) < EPSILON`).",
                standards=["CWE-1077", "MISRA C:2012 Rule 12.1"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 2. Insecure Configuration & Flag Assignment Analysis
        cfg_assign_match = re.search(
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)(?:\s+mode)?\s*(?:=|is|to|set to|\s+)?\s*(true|false|0|1|none|null|enabled|disabled)\b',
            prompt_lower
        )
        if cfg_assign_match:
            var_name = cfg_assign_match.group(1)
            target_val = cfg_assign_match.group(2)
            if target_val in ["true", "enabled", "1"]:
                val_regex = r"""(?:True|true|1|'true'|"true")"""
                sample_val = "True"
            else:
                val_regex = r"""(?:False|false|0|None|null|'false'|"false")"""
                sample_val = "False"

            regex = rf"""(?i)\b{re.escape(var_name)}\s*[:=]\s*{val_regex}\b"""
            var_lower = var_name.lower()
            if "debug" in var_lower:
                cwe = "CWE-489"
                title = f"Detect Debug Mode Enabled ({var_name})"
                severity = "HIGH"
                standards = ["CWE-489", "ISO-27001:A.8.28", "OWASP:A05:2021"]
            elif any(k in var_lower for k in ["ssl", "tls", "cert", "verify"]):
                cwe = "CWE-295"
                title = f"Detect Insecure TLS/SSL Verification ({var_name})"
                severity = "CRITICAL"
                standards = ["CWE-295", "ISO-27001:A.8.24", "OWASP:A07:2021"]
            else:
                cwe = "CWE-16"
                title = f"Detect Insecure Configuration Assignment ({var_name})"
                severity = "MEDIUM"
                standards = ["CWE-16", "ISO-27001:A.8.28"]

            sample_code = f"# Violation: Insecure configuration setting\n{var_name} = {sample_val}\n"
            return SemanticConceptMatch(
                name=title,
                cwe=cwe,
                severity=severity,
                regex=regex,
                remediation=f"Ensure '{var_name}' is set safely in production and verified through environment checks.",
                standards=standards,
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 3. Dynamic Heap Memory in Safety Systems (CWE-401 / MISRA)
        if any(k in prompt_lower for k in ["malloc", "free", "calloc", "realloc", "heap memory", "dynamic memory", "misra", "autosar"]):
            regex = r"""\b(?:malloc|calloc|realloc|free)\s*\("""
            sample_code = (
                "// Violation: Prohibited dynamic memory allocation (MISRA C:2012 Rule 21.3)\n"
                "void* buffer = malloc(1024);\n"
            )
            return SemanticConceptMatch(
                name="MISRA C:2012 / ISO-26262: Prohibit Dynamic Heap Memory",
                cwe="CWE-401",
                severity="HIGH",
                regex=regex,
                remediation="In safety-critical systems, allocate fixed static buffers during initialization.",
                standards=["ISO-26262-6:ASIL-D", "MISRA C:2012 Rule 21.3", "AUTOSAR C++14 Rule A18-5-2"],
                sample_trigger_code=sample_code,
                languages=["c", "cpp"]
            )

        # 4. SQL Injection (CWE-89)
        if any(k in prompt_lower for k in ["sql", "sqli", "database query", "select from", "cursor.execute"]):
            regex = r"""(?i)(?:execute|raw|query)\s*\(\s*(?:f['"].*SELECT|['"].*SELECT.*['"]\s*\+)"""
            sample_code = (
                "# Violation: SQL injection via string interpolation\n"
                'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
            )
            return SemanticConceptMatch(
                name="Detect SQL Injection via String Concatenation",
                cwe="CWE-89",
                severity="CRITICAL",
                regex=regex,
                remediation="Use parameterized queries with bind variables or an ORM with built-in escaping.",
                standards=["CWE-89", "ISO-27001:A.8.28", "OWASP:A03:2021"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 5. Dynamic Code Execution (CWE-95 / CWE-78)
        if bool(re.search(r'\b(?:eval|exec)\b(?!\.execute)|\b(?:eval|exec|system|popen)\s*\(|dynamic execution|command execution', prompt_lower)):
            regex = r"""\b(?:eval|exec|system|popen)\s*\("""
            sample_code = (
                "# Violation: Dynamic code or command execution\n"
                "result = eval(user_input)\n"
            )
            return SemanticConceptMatch(
                name="Detect Dynamic Code Evaluation via eval/exec",
                cwe="CWE-95",
                severity="CRITICAL",
                regex=regex,
                remediation="Avoid eval() or exec() with untrusted inputs; use strict parser or schema dispatchers.",
                standards=["CWE-95", "ISO-27001:A.8.28", "OWASP:A03:2021"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 6. Insecure Deserialization (CWE-502)
        if any(k in prompt_lower for k in ["pickle", "unserialize", "deserialization", "yaml.load"]):
            regex = r"""(?i)(?:pickle\.loads|yaml\.load\s*\([^\)]*(?!SafeLoader))"""
            sample_code = (
                "# Violation: Insecure object deserialization\n"
                "import pickle\n"
                "data = pickle.loads(untrusted_payload)\n"
            )
            return SemanticConceptMatch(
                name="Detect Insecure Object Deserialization",
                cwe="CWE-502",
                severity="CRITICAL",
                regex=regex,
                remediation="Use safe structured deserializers such as json.loads or yaml.safe_load.",
                standards=["CWE-502", "ISO-27001:A.8.28", "OWASP:A08:2021"],
                sample_trigger_code=sample_code,
                languages=["python"]
            )

        # 7. Hardcoded Secrets & Credentials (CWE-798)
        if any(k in prompt_lower for k in ["secret", "token", "password", "key", "credential", "api_key", "bearer"]):
            regex = r"""(?i)(?:bearer|token|secret|password|api_key|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.]{12,}['"]"""
            sample_code = (
                "# Violation: Hardcoded credential or secret\n"
                'api_key = "ghp_98472938472983749283749823"\n'
            )
            return SemanticConceptMatch(
                name="Detect Hardcoded Secret or Token",
                cwe="CWE-798",
                severity="HIGH",
                regex=regex,
                remediation="Store secrets in a secure secret manager or inject via environment variables at runtime.",
                standards=["CWE-798", "ISO-27001:A.8.12", "NIST-SSDF:PW.4.1", "OWASP:A07:2021"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 8. Weak Cryptography / PRNG (CWE-330)
        if any(k in prompt_lower for k in ["math.random", "rand", "random", "prng", "crypto"]):
            regex = r"""\b(?:Math\.random\(\)|rand\(\)|random\.random\(\))"""
            sample_code = (
                "# Violation: Cryptographically insecure random generator\n"
                "token = Math.random();\n"
            )
            return SemanticConceptMatch(
                name="Detect Insecure Pseudo-Random Number Generator",
                cwe="CWE-330",
                severity="MEDIUM",
                regex=regex,
                remediation="Use cryptographically secure PRNGs (window.crypto.getRandomValues or secrets module).",
                standards=["CWE-330", "ISO-27001:A.8.24"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 9. Cleartext HTTP URLs (CWE-319)
        if any(k in prompt_lower for k in ["http://", "unencrypted", "cleartext"]):
            regex = r"""['"]http:\/\/[a-zA-Z0-9\.\-]+['"]"""
            sample_code = (
                '# Violation: Unencrypted HTTP endpoint\n'
                'api_endpoint = "http://api.internal.service/data"\n'
            )
            return SemanticConceptMatch(
                name="Detect Insecure Cleartext HTTP URLs",
                cwe="CWE-319",
                severity="MEDIUM",
                regex=regex,
                remediation="Enforce HTTPS with TLS 1.3 for all internal and external endpoints.",
                standards=["CWE-319", "ISO-27001:A.8.24"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 10. Prohibited API Call / Function Call Extractor (Generalized)
        func_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(\s*\)', prompt_lower)
        if func_match:
            target_func = func_match.group(1)
            regex = rf"""\b{re.escape(target_func)}\s*\("""
            sample_code = f"# Violation: Prohibited call to {target_func}()\n{target_func}()\n"
            return SemanticConceptMatch(
                name=f"Detect Calls to {target_func}()",
                cwe="CWE-676",
                severity="MEDIUM",
                regex=regex,
                remediation=f"Review use of '{target_func}()' and replace with approved secure alternatives.",
                standards=["CWE-676", "ISO-27001:A.8.28"],
                sample_trigger_code=sample_code,
                languages=languages
            )

        # 11. Universal Linguistic / Code-Symbol Fallback
        candidate_words = [
            w for w in re.findall(r'[a-zA-Z0-9_]{3,}', prompt_lower)
            if w not in cls.STOPWORDS
        ]
        if candidate_words:
            target_word = candidate_words[0]
            regex = rf"""\b{re.escape(target_word)}\b"""
            title = f"Detect Occurrences of '{target_word}'"
            sample_code = f"# Violation: Detected pattern matching '{target_word}'\nresult = process_{target_word}()\n"
            cwe = "CWE-699"
        else:
            regex = r"""(?i)(?:TODO|FIXME|HACK):?\s*security"""
            title = "Detect Unresolved Security Annotations"
            sample_code = "# TODO: security review required before deploy\n"
            cwe = "CWE-546"

        return SemanticConceptMatch(
            name=title,
            cwe=cwe,
            severity="MEDIUM",
            regex=regex,
            remediation="Ensure code conforms to organizational security policies and ISO-27001 secure coding guidelines.",
            standards=map_finding_to_standards(cwe, title),
            sample_trigger_code=sample_code,
            languages=languages
        )


class NLRuleGenerator:
    """
    Translates human natural language into executable SAST pattern/AST rules or SCA dependency policies.
    """

    @classmethod
    def generate_from_text(cls, human_prompt: str, target_ecosystem: str = "auto") -> Dict[str, Any]:
        """
        Synthesizes an AegisSec custom rule from natural language.
        If an active LLM integration is configured, queries the LLM; otherwise falls back to SemanticRuleParser.
        """
        try:
            from ..integrations.llm_service import LLMService
            llm_res = LLMService.generate_rule(human_prompt, target_ecosystem)
            if llm_res and llm_res.get("success") and llm_res.get("rule"):
                return llm_res["rule"]
        except Exception:
            pass

        return cls._synthesize_core_rule(human_prompt, target_ecosystem)

    @classmethod
    def _synthesize_core_rule(cls, human_prompt: str, target_ecosystem: str = "auto") -> Dict[str, Any]:
        """
        Core synthesis engine that translates natural language to SAST or SCA rule without external API dependencies.
        """
        prompt = human_prompt.strip().lower()
        rule_id = f"RULE-{uuid.uuid4().hex[:6].upper()}"

        # 1. Determine Rule Category: SCA Policy vs SAST Code Rule
        is_sca = any(k in prompt for k in ["dependency", "package", "library", "license", "npm", "pypi", "pom", "gpl", "agpl", "version"])
        
        if is_sca and not any(k in prompt for k in ["code", "function", "variable", "pointer", "/ 0", "div", "divided"]):
            return cls._synthesize_sca_rule(rule_id, human_prompt, prompt, target_ecosystem)
        else:
            return cls._synthesize_sast_rule(rule_id, human_prompt, prompt, target_ecosystem)

    @classmethod
    def _synthesize_sast_rule(cls, rule_id: str, original_prompt: str, prompt: str, target_ecosystem: str = "auto") -> Dict[str, Any]:
        parsed = SemanticRuleParser.parse(original_prompt, target_ecosystem)
        standards = parsed.standards if parsed.standards else map_finding_to_standards(parsed.cwe, parsed.name)

        rule_dict = {
            "id": rule_id,
            "name": parsed.name,
            "type": "sast_pattern",
            "rule_category": "sast",
            "nl_prompt": original_prompt,
            "languages": parsed.languages,
            "severity": parsed.severity,
            "cwe": parsed.cwe,
            "standards": standards,
            "regex": parsed.regex,
            "description": f"Custom rule generated from instruction: '{original_prompt}'.",
            "remediation": parsed.remediation,
            "sample_trigger_code": parsed.sample_trigger_code,
            "is_active": True
        }

        rule_yaml = yaml.dump(rule_dict, sort_keys=False)
        rule_dict["yaml_representation"] = rule_yaml
        return rule_dict

    @classmethod
    def _synthesize_sca_rule(cls, rule_id: str, original_prompt: str, prompt: str, target_ecosystem: str = "auto") -> Dict[str, Any]:
        license_match = re.search(r'\b(gpl-?[0-9\.]*|agpl-?[0-9\.]*|mit|apache-?[0-9\.]*|bsd)\b', prompt)
        banned_license = license_match.group(1).upper() if license_match else "AGPL-3.0"

        # Check for package name
        pkg_match = re.search(r'(?:dependency\s+package|package|library|dependency)\s+([a-zA-Z0-9_\-\./]+)', prompt)
        pkg_name = pkg_match.group(1) if pkg_match else "*"

        # Check for version
        ver_match = re.search(r'(?:below|under|version|<|<=)\s*v?([0-9\.]+)', prompt)
        banned_ver = f"<{ver_match.group(1)}" if ver_match else "<4.17.21"

        rule_dict = {
            "id": rule_id,
            "name": f"SCA Policy: Restrict {pkg_name} / License {banned_license}",
            "type": "sca_policy",
            "rule_category": "sca",
            "nl_prompt": original_prompt,
            "ecosystem": "npm" if target_ecosystem == "auto" else target_ecosystem,
            "target_package": pkg_name,
            "banned_license": banned_license,
            "banned_version_range": banned_ver,
            "severity": "HIGH",
            "cwe": "CWE-1104",
            "standards": ["ISO-5230:LIC-02", "ISO-27001:A.8.25", "NIST-SSDF:PW.8"],
            "description": f"Enforces dependency policy restricting package '{pkg_name}' or license '{banned_license}'.",
            "remediation": "Audit licenses against ISO/IEC 5230 OpenChain standard and substitute non-compliant packages.",
            "sample_trigger_code": f'{{"dependencies": {{"{pkg_name}": "4.17.20"}}}}' if pkg_name != "*" else '{"license": "AGPL-3.0"}',
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
            compiled = re.compile(pattern, re.MULTILINE)
            for match in compiled.finditer(sample_code):
                start_char = match.start()
                line_no = sample_code.count("\n", 0, start_char) + 1
                matched_text = match.group(0)

                # Context snippet (up to 2 lines before and after)
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
                "severity": rule.get("severity"),
                "cwe": rule.get("cwe"),
                "violation_detected": len(matches) > 0
            }
        except Exception as e:
            return {"success": False, "error": str(e), "matches": []}
