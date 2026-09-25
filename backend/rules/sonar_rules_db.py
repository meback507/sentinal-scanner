"""
AegisSec / Sentinel - Comprehensive SonarQube SAST RSPEC Rules Database
Direct implementation of SonarQube Security Vulnerabilities and Security Hotspots
mapped across Python, JavaScript, TypeScript, Java, C, C++, Go, PHP, Ruby, and Shell.

Each rule includes the official SonarSource RSPEC identifier (Sxxxx), Sonar rule type,
Sonar severity level, CWE, OWASP Top 10, clean code attributes, robust regex detection patterns,
and concrete remediation steps.
"""

from typing import List, Dict, Any

SONARQUBE_SAST_RULES: List[Dict[str, Any]] = [
    # -------------------------------------------------------------------------
    # 1. SQL Injection (SonarQube RSPEC S2077, S3649)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2077",
        "sonar_key": "S2077",
        "sonar_rule_id": "python:S2077",
        "name": "Formatting SQL queries is security-sensitive (SQL Injection)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "php", "go", "ruby"],
        "cwe": "CWE-89",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "PCI-DSS:Req-6.5.1", "CWE-89"],
        "regex": r"""(?i)(?:execute|query|raw|cursor\.execute|createQuery)\s*\(\s*(?:f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\{|['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*['"]\s*\+|\`.*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*\$\{)""",
        "description": "Constructing SQL queries dynamically by formatting strings concatenates user-controlled data directly into the query, enabling SQL injection (SonarQube S2077).",
        "remediation": "Use parameterized queries or ORM query builders with bind parameters instead of string interpolation (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 2. Hardcoded Credentials (SonarQube RSPEC S2068, S6418)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2068",
        "sonar_key": "S2068",
        "sonar_rule_id": "common:S2068",
        "name": "Hard-coded credentials are security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go", "php", "ruby"],
        "cwe": "CWE-798",
        "owasp": "OWASP:A07:2021",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.12", "PCI-DSS:Req-8.2", "CWE-798"],
        "regex": r"""(?i)(?:password|passwd|pwd|db_pass|secret_key|client_secret)\s*[:=]\s*['"][a-zA-Z0-9_\-\.!@#$%^&*]{8,}['"]""",
        "description": "Hard-coding sensitive credentials directly in source code allows anyone with repository access to impersonate authorized identities (SonarQube S2068).",
        "remediation": "Extract secrets into environment variables, HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 3. Server-Side Request Forgery (SSRF) (SonarQube RSPEC S5144)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5144",
        "sonar_key": "S5144",
        "sonar_rule_id": "python:S5144",
        "name": "Server-side requests should not be vulnerable to SSRF attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go", "php"],
        "cwe": "CWE-918",
        "owasp": "OWASP:A10:2021",
        "standards": ["OWASP:A10:2021", "ISO-27001:A.8.28", "CWE-918"],
        "regex": r"""(?i)(?:requests\.(?:get|post|put|delete)|urllib\.request\.urlopen|axios\.(?:get|post)|http\.Get|fetch)\s*\(\s*(?:req\.(?:query|params|body)|request\.(?:args|form|GET|POST)|url\b)[^\)]*\)""",
        "description": "Fetching arbitrary URLs provided directly by client requests enables Server-Side Request Forgery (SSRF), allowing attackers to reach internal metadata services (e.g. AWS 169.254.169.254) or intranet systems (SonarQube S5144).",
        "remediation": "Validate target URLs against an explicit allowlist of domain names and block access to private/loopback IP address ranges.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 4. OS Command Injection (SonarQube RSPEC S5883, S2076)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5883",
        "sonar_key": "S5883",
        "sonar_rule_id": "python:S5883",
        "name": "Executing OS commands is security-sensitive (Command Injection)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "php", "ruby", "go"],
        "cwe": "CWE-78",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-78"],
        "regex": r"""(?i)(?:Runtime\.getRuntime\(\)\.exec|child_process\.exec|exec\.Command\("sh",\s*"-c"|subprocess\.Popen\s*\([^\)]*shell\s*=\s*True|os\.system\s*\(\s*(?:f['"]|.*\+))""",
        "description": "Executing OS commands with dynamic string concatenation permits shell command injection, allowing attackers to execute arbitrary system binaries (SonarQube S5883).",
        "remediation": "Pass command arguments as an array with shell=False, avoiding shell interpreters, or use dedicated safe programming language APIs.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 5. Cross-Site Scripting (XSS - Reflected & DOM) (SonarQube RSPEC S5131)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5131",
        "sonar_key": "S5131",
        "sonar_rule_id": "javascript:S5131",
        "name": "Endpoints should not be vulnerable to reflected cross-site scripting (XSS)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["javascript", "typescript", "python", "java", "php"],
        "cwe": "CWE-79",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-79"],
        "regex": r"""(?i)(?:res\.send|response\.write|res\.write|document\.write)\s*\(\s*(?:req\.query|req\.params|request\.args|req\.body)""",
        "description": "Reflecting unsanitized HTTP request parameters directly into the HTTP response body or DOM enables Cross-Site Scripting (XSS) (SonarQube S5131).",
        "remediation": "Contextually HTML-encode user input or use frameworks that auto-escape output (e.g. React JSX, Jinja2 autoescape).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 6. Weak Cryptographic Hash (MD5/SHA1) (SonarQube RSPEC S4790)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4790",
        "sonar_key": "S4790",
        "sonar_rule_id": "python:S4790",
        "name": "Using weak hashing algorithms is security-sensitive (MD5 / SHA-1)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go", "php"],
        "cwe": "CWE-327",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "PCI-DSS:Req-3.4", "CWE-327"],
        "regex": r"""(?i)(?:MessageDigest\.getInstance\(['"](?:MD5|SHA-1|SHA1)['"]\)|crypto\.createHash\(['"](?:md5|sha1)['"]\)|hashlib\.(?:md5|sha1)\s*\()""",
        "description": "MD5 and SHA-1 have known collision vulnerabilities and should not be used for security-critical hashing or digital signatures (SonarQube S4790).",
        "remediation": "Upgrade to SHA-256, SHA-512, or SHA-3 for digest integrity, and Argon2id or PBKDF2 for password hashing.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 7. Insecure Encryption Algorithms (DES/Blowfish/RC4/ECB) (SonarQube RSPEC S5542)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5542",
        "sonar_key": "S5542",
        "sonar_rule_id": "python:S5542",
        "name": "Encryption algorithms should be robust (Insecure Cipher / ECB Mode)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        "cwe": "CWE-327",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "PCI-DSS:Req-3.4", "CWE-327"],
        "regex": r"""(?i)(?:Cipher\.getInstance\(['"](?:DES|DESede|Blowfish|RC4|AES/ECB)['"]\)|AES\.new\([^,]+,\s*AES\.MODE_ECB\)|crypto\.createCipheriv\(['"](?:des|rc4|aes-128-ecb)['"])""",
        "description": "Legacy ciphers (DES, RC4, Blowfish) or ECB mode fail to provide semantic confidentiality and can leak structural plaintext patterns (SonarQube S5542).",
        "remediation": "Use AES-GCM (Authenticated Encryption with Associated Data) with a 256-bit key and random nonce/IV.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 8. Insecure Deserialization (SonarQube RSPEC S5135, S2631)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5135",
        "sonar_key": "S5135",
        "sonar_rule_id": "java:S5135",
        "name": "Deserializing untrusted data is security-sensitive (Insecure Deserialization)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "java", "javascript", "php"],
        "cwe": "CWE-502",
        "owasp": "OWASP:A08:2021",
        "standards": ["OWASP:A08:2021", "ISO-27001:A.8.28", "CWE-502"],
        "regex": r"""(?i)(?:ObjectInputStream\s*\([^\)]*\)\.readObject|unserialize\s*\(\s*\$_(?:GET|POST|REQUEST)|pickle\.loads\s*\(|yaml\.load\s*\([^\)]*Loader\s*=\s*(?:yaml\.)?(?:Loader|UnsafeLoader)\))""",
        "description": "Deserializing untrusted serialized object streams can trigger arbitrary code execution via gadget chains (SonarQube S5135).",
        "remediation": "Use safe data exchange formats such as JSON or Protocol Buffers, or enforce strict object class filtering during deserialization.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 9. Path / Directory Traversal (SonarQube RSPEC S2083)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2083",
        "sonar_key": "S2083",
        "sonar_rule_id": "python:S2083",
        "name": "I/O function calls should not be vulnerable to path injection attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go", "php", "c", "cpp"],
        "cwe": "CWE-22",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-22"],
        "regex": r"""(?i)(?:new\s+FileInputStream|new\s+File|fs\.readFile(?:Sync)?|open)\s*\(\s*(?:req\.(?:query|params)|request\.(?:args|GET)|\$_(?:GET|POST))""",
        "description": "Constructing file paths directly from user input allows path traversal sequences (../) to access unauthorized files on the filesystem (SonarQube S2083).",
        "remediation": "Canonicalize the path (e.g. os.path.realpath, Path.resolve()) and verify that the resolved path starts with the allowed base directory.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 10. XML External Entity (XXE) Injection (SonarQube RSPEC S2755)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2755",
        "sonar_key": "S2755",
        "sonar_rule_id": "java:S2755",
        "name": "XML parsers should not be vulnerable to XXE attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["java", "python", "javascript", "php"],
        "cwe": "CWE-611",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-611"],
        "regex": r"""(?i)(?:DocumentBuilderFactory\.newInstance\(\)|XMLInputFactory\.newInstance\(\)|SAXParserFactory\.newInstance\(\)|xml\.dom\.minidom\.parse|lxml\.etree\.XMLParser\s*\([^\)]*resolve_entities\s*=\s*True)""",
        "description": "Parsing XML documents with external entity resolution enabled allows attackers to read local files, execute SSRF, or trigger denial of service (SonarQube S2755).",
        "remediation": "Disable external DTDs and entity expansion: setFeature('http://apache.org/xml/features/disallow-doctype-decl', True).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 11. Open Redirect (SonarQube RSPEC S5146)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5146",
        "sonar_key": "S5146",
        "sonar_rule_id": "python:S5146",
        "name": "HTTP request redirections should not be open to forging attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-601",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-601"],
        "regex": r"""(?i)(?:redirect|res\.redirect|response\.sendRedirect)\s*\(\s*(?:req\.(?:query|params|body)|request\.(?:args|form)|next_url|\$_(?:GET|POST))""",
        "description": "Redirecting users to unvalidated URLs supplied by query parameters facilitates phishing attacks by redirecting victims to malicious lookalike domains (SonarQube S5146).",
        "remediation": "Validate target redirection URLs against a strict allowlist of internal or trusted domains, or use relative paths only.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 12. Insecure Cookie Flags (HttpOnly & Secure) (SonarQube RSPEC S2255, S2092)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2255",
        "sonar_key": "S2255",
        "sonar_rule_id": "javascript:S2255",
        "name": "Using cookies without the 'HttpOnly' flag is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-1004",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-1004"],
        "regex": r"""(?i)(?:set_cookie|res\.cookie)\s*\([^\)]*(?:httponly\s*=\s*False|httpOnly\s*:\s*false)""",
        "description": "Cookies without the 'HttpOnly' attribute can be accessed by client-side scripts, permitting session hijacking via Cross-Site Scripting (SonarQube S2255).",
        "remediation": "Always set the 'HttpOnly' flag to True for session and authentication cookies.",
        "is_active": True
    },
    {
        "id": "SONAR-S2092",
        "sonar_key": "S2092",
        "sonar_rule_id": "python:S2092",
        "name": "Using cookies without the 'secure' flag is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-614",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.24", "CWE-614"],
        "regex": r"""(?i)(?:set_cookie|res\.cookie)\s*\([^\)]*(?:secure\s*=\s*False|secure\s*:\s*false)""",
        "description": "Cookies lacking the 'Secure' flag can be transmitted over unencrypted HTTP connections, exposing tokens to man-in-the-middle eavesdropping (SonarQube S2092).",
        "remediation": "Always set the 'Secure' flag to True so cookies are only transmitted over TLS/HTTPS connections.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 13. Insecure CORS Configuration (SonarQube RSPEC S5122)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5122",
        "sonar_key": "S5122",
        "sonar_rule_id": "javascript:S5122",
        "name": "Enabling Cross-Origin Resource Sharing (CORS) is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-942",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-942"],
        "regex": r"""(?i)(?:Access-Control-Allow-Origin['"]?\s*[:=]\s*['"]\*['"]|allow_origins\s*=\s*\[['"]\*['"]\]|cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"])""",
        "description": "Permitting wildcard origins ('*') in CORS configurations exposes authenticated REST endpoints to arbitrary third-party web domains (SonarQube S5122).",
        "remediation": "Specify exact authorized origins rather than wildcard '*', and avoid reflecting the request Origin header dynamically.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 14. Weak Pseudorandom Number Generation (PRNG) (SonarQube RSPEC S2245)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2245",
        "sonar_key": "S2245",
        "sonar_rule_id": "python:S2245",
        "name": "Using pseudorandom number generators (PRNGs) is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        "cwe": "CWE-338",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-338"],
        "regex": r"""(?i)(?:new\s+java\.util\.Random\(\)|random\.(?:random|randint|choice)\s*\(|Math\.random\(\)|rand\(\))""",
        "description": "Standard pseudorandom generators produce deterministic sequences and are vulnerable to state recovery if used in security contexts (tokens, salts, password reset) (SonarQube S2245).",
        "remediation": "Use cryptographically secure PRNGs: Python 'secrets' module, Java 'SecureRandom', or Node.js 'crypto.randomBytes()'.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 15. Insecure SSL/TLS Protocols & Certificate Verification (SonarQube RSPEC S4423, S4830)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4423",
        "sonar_key": "S4423",
        "sonar_rule_id": "python:S4423",
        "name": "Weak SSL/TLS protocols should not be used",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        "cwe": "CWE-326",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "PCI-DSS:Req-4.1", "CWE-326"],
        "regex": r"""(?i)(?:PROTOCOL_SSLv23|PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1\b|PROTOCOL_TLSv1_1|TLSv1_client_method)""",
        "description": "SSLv2, SSLv3, TLS 1.0, and TLS 1.1 suffer from cryptographic vulnerabilities (POODLE, BEAST) and must be disabled (SonarQube S4423).",
        "remediation": "Configure TLS 1.2 or TLS 1.3 as the minimum acceptable protocol version.",
        "is_active": True
    },
    {
        "id": "SONAR-S4830",
        "sonar_key": "S4830",
        "sonar_rule_id": "common:S4830",
        "name": "Server certificates should be verified during SSL/TLS connections",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-295",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-295"],
        "regex": r"""(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|TrustAllCertificates|check_hostname\s*=\s*False)""",
        "description": "Disabling TLS certificate validation allows man-in-the-middle adversaries to intercept and modify encrypted network traffic (SonarQube S4830).",
        "remediation": "Ensure certificate verification is strictly enabled (verify=True, rejectUnauthorized: true).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 16. Dynamic Code Execution (SonarQube RSPEC S5334, S1523)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5334",
        "sonar_key": "S5334",
        "sonar_rule_id": "javascript:S5334",
        "name": "Dynamic code execution should not be vulnerable to injection",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "php", "ruby"],
        "cwe": "CWE-95",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-95"],
        "regex": r"""(?i)(?:Function\s*\([^)]*\)\s*\(|vm\.runIn(?:ThisContext|NewContext)\s*\(|eval\s*\(\s*(?:req\.|request\.args|[a-zA-Z0-9_]+\s*\+))""",
        "description": "Evaluating dynamic strings with JavaScript/Python eval or Function constructors enables arbitrary code execution (SonarQube S5334).",
        "remediation": "Avoid dynamic code evaluation; use structured data models or safe JSON parsing.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 17. NoSQL Injection (SonarQube RSPEC S5147)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5147",
        "sonar_key": "S5147",
        "sonar_rule_id": "javascript:S5147",
        "name": "NoSQL operations should not be vulnerable to injection attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["javascript", "typescript", "python"],
        "cwe": "CWE-943",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-943"],
        "regex": r"""(?i)(?:\$where\s*:\s*(?:req\.|request\.)|\.find\s*\(\s*(?:req\.body|req\.query)\s*\))""",
        "description": "Passing user-controlled request objects directly into MongoDB/NoSQL queries allows operator injection ($gt, $ne, $where) to bypass authentication (SonarQube S5147).",
        "remediation": "Sanitize user inputs by casting variables to strings or using query schema validators (e.g. mongo-sanitize, Joi).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 18. Server-Side Template Injection (SSTI) (SonarQube RSPEC S5145)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5145",
        "sonar_key": "S5145",
        "sonar_rule_id": "python:S5145",
        "name": "Template engines should not execute untrusted input directly (SSTI)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java"],
        "cwe": "CWE-1336",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-1336"],
        "regex": r"""(?i)(?:render_template_string\s*\(\s*(?:f['"]|[^\)]*\+)|nunjucks\.renderString\s*\(\s*(?:req\.|request\.)|Velocity\.evaluate\s*\()""",
        "description": "Rendering templates constructed dynamically from raw user input causes Server-Side Template Injection (SSTI), leading to RCE (SonarQube S5145).",
        "remediation": "Pass untrusted variables into static templates as context arguments rather than constructing template strings dynamically.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 19. Unverified JWT Tokens (SonarQube RSPEC S5659)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5659",
        "sonar_key": "S5659",
        "sonar_rule_id": "javascript:S5659",
        "name": "JWT tokens should be signed and verified",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-347",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-347"],
        "regex": r"""(?i)(?:jwt\.decode\s*\([^\)]*(?:verify\s*=\s*False|algorithms\s*=\s*\[['"]none['"]\])|jwt\.verify\s*\([^\)]*ignoreExpiration\s*:\s*true)""",
        "description": "Decoding JSON Web Tokens without cryptographic signature verification allows attackers to tamper with claims and escalate privileges (SonarQube S5659).",
        "remediation": "Always verify signatures using strong algorithms (RS256, ES256) with valid public keys and reject the 'none' algorithm.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 20. Regular Expression Denial of Service (ReDoS) (SonarQube RSPEC S5852)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5852",
        "sonar_key": "S5852",
        "sonar_rule_id": "common:S5852",
        "name": "Using slow regular expressions is security-sensitive (ReDoS)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java"],
        "cwe": "CWE-1333",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-1333"],
        "regex": r"""(?:\([a-zA-Z0-9_\-\.\*]+\+\)\+|\([a-zA-Z0-9_]+\|[a-zA-Z0-9_]+\)\+)""",
        "description": "Nested repetitions in regular expressions lead to catastrophic backtracking and CPU exhaustion when matched against non-matching inputs (SonarQube S5852).",
        "remediation": "Simplify regex patterns, avoid nested quantifier groups, and set matching execution timeouts.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 21. Hardcoded IP Addresses (SonarQube RSPEC S1313)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S1313",
        "sonar_key": "S1313",
        "sonar_rule_id": "common:S1313",
        "name": "Using hardcoded IP addresses is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MINOR",
        "severity": "LOW",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        "cwe": "CWE-546",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-546"],
        "regex": r"""['"]\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b['"]""",
        "description": "Hard-coding internal network IP addresses discloses internal network architecture and prevents flexible network re-addressing (SonarQube S1313).",
        "remediation": "Replace hard-coded IP addresses with configurable domain names or environment variables.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 22. Disabled CSRF Protection (SonarQube RSPEC S4502)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4502",
        "sonar_key": "S4502",
        "sonar_rule_id": "python:S4502",
        "name": "Disabling CSRF protection is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java"],
        "cwe": "CWE-352",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-352"],
        "regex": r"""(?i)(?:@csrf_exempt|\.csrf\(\)\.disable\(\)|csrf\s*:\s*false)""",
        "description": "Disabling Cross-Site Request Forgery (CSRF) protection exposes state-changing endpoints to unauthorized actions initiated from malicious origins (SonarQube S4502).",
        "remediation": "Enforce CSRF token validation on all state-altering requests (POST, PUT, DELETE, PATCH).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 23. LDAP Injection (SonarQube RSPEC S2078)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2078",
        "sonar_key": "S2078",
        "sonar_rule_id": "python:S2078",
        "name": "LDAP queries should not be vulnerable to injection attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript"],
        "cwe": "CWE-90",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-90"],
        "regex": r"""(?i)(?:ldap\.search|DirContext\.search)\s*\(\s*(?:f['"].*uid=|['"].*uid=.*['"]\s*\+)""",
        "description": "Constructing LDAP search filters via dynamic string concatenation allows LDAP injection, letting attackers bypass directory authentication (SonarQube S2078).",
        "remediation": "Escape all user-supplied characters in LDAP search filters using dedicated LDAP filter encoders.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 24. C/C++ Memory Safety & Unbounded Functions (SonarQube RSPEC S5814)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5814",
        "sonar_key": "S5814",
        "sonar_rule_id": "c:S5814",
        "name": "Unbounded string operations should not be used (Buffer Overflow)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["c", "cpp"],
        "cwe": "CWE-120",
        "owasp": "OWASP:A06:2021",
        "standards": ["ISO-26262:Part6", "MISRA-C:2012:Rule-21.3", "CWE-120"],
        "regex": r"""\b(?:gets\s*\(|strcpy\s*\(|strcat\s*\(|sprintf\s*\([^,]+,\s*[^,]+\))""",
        "description": "Calling unbounded string functions like gets, strcpy, or sprintf without destination length checks causes buffer overflows and memory corruption (SonarQube S5814).",
        "remediation": "Use safe bounded functions such as fgets, strncpy, snprintf, or C++ std::string.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 25. Zip Slip / Archive Path Traversal (SonarQube RSPEC S5042, S6096)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5042",
        "sonar_key": "S5042",
        "sonar_rule_id": "python:S5042",
        "name": "Extracting archives without validating file paths is security-sensitive (Zip Slip)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-22",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-22"],
        "regex": r"""(?i)(?:tarfile\.open\([^)]*\)\.extractall|zipfile\.ZipFile\([^)]*\)\.extractall|\.extractall\s*\((?![^)]*filter=)|tar\.extractall\s*\(|unzip\s+\$|unzipper\.Extract)""",
        "description": "Extracting archive files (ZIP, TAR) directly without verifying that entry filenames do not contain path traversal characters ('..') allows arbitrary file overwrite outside the target directory (Zip Slip vulnerability, SonarQube S5042).",
        "remediation": "Validate that canonicalized extracted paths reside strictly inside destination directory before writing, or use Python 3.12+ filter='data' in extractall().",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 26. Cleartext Protocols (SonarQube RSPEC S5332)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5332",
        "sonar_key": "S5332",
        "sonar_rule_id": "common:S5332",
        "name": "Using cleartext protocols is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go", "c", "cpp", "php"],
        "cwe": "CWE-319",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "PCI-DSS:Req-4.1", "CWE-319"],
        "regex": r"""(?i)['"](?:http://|ftp://|telnet://)(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|schemas\.|www\.w3\.org)[a-zA-Z0-9_\-\.]+(?:/[^'"]*)?['"]""",
        "description": "Transmitting data or communicating with services over cleartext protocols (HTTP, FTP, Telnet) exposes authentication credentials and confidential payloads to network eavesdropping and tampering (SonarQube S5332).",
        "remediation": "Upgrade to encrypted protocols such as HTTPS, SFTP, and SSH with verified certificates.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 27. Overly Permissive File Permissions (SonarQube RSPEC S2612)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2612",
        "sonar_key": "S2612",
        "sonar_rule_id": "python:S2612",
        "name": "Setting overly permissive file permissions is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "c", "cpp", "go", "shell"],
        "cwe": "CWE-732",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.12", "CWE-732"],
        "regex": r"""(?i)(?:chmod\s+(?:-R\s+)?777|os\.chmod\s*\([^,]+,\s*(?:0o777|0777|stat\.S_IRWXU\s*\|\s*stat\.S_IRWXG\s*\|\s*stat\.S_IRWXO)|fs\.chmod(?:Sync)?\s*\([^,]+,\s*(?:0o777|0777|'777'))""",
        "description": "Setting world-readable, world-writable, and world-executable permissions (0777) permits any local user or unprivileged process on the host to read, modify, or execute files (SonarQube S2612).",
        "remediation": "Apply the principle of least privilege: use restrictive permissions such as 0600 (owner read/write only) or 0750 (owner full, group read/exec).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 28. Insecure Temporary File Creation (SonarQube RSPEC S5443)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5443",
        "sonar_key": "S5443",
        "sonar_rule_id": "python:S5443",
        "name": "Using publicly writable directories for temporary files is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp"],
        "cwe": "CWE-377",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-377"],
        "regex": r"""(?i)(?:tempfile\.mktemp\s*\(|File\.createTempFile\s*\([^,]+,\s*[^,]+,\s*null\)|['"]/tmp/[a-zA-Z0-9_\-\.]+['"]\s*(?:in\s+open|\.open|new\s+File))""",
        "description": "Creating temporary files with predictable names or using shared writable directories like /tmp without O_EXCL flags introduces race condition vulnerabilities (symlink attacks, TOCTOU) (SonarQube S5443).",
        "remediation": "Use secure temporary file APIs like tempfile.NamedTemporaryFile() or Files.createTempFile() which enforce restricted file permissions and atomic creation.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 29. Timing Attacks in Cryptographic Comparisons (SonarQube RSPEC S5808)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5808",
        "sonar_key": "S5808",
        "sonar_rule_id": "python:S5808",
        "name": "Cryptographic comparisons should be done in constant time (Timing Attack)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-208",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-208"],
        "regex": r"""(?i)(?:password_hash|token|secret_key|api_signature|auth_token)\s*(?:==|===|!=|!==)\s*(?:req\.|request\.|input|user_token|\$_(?:POST|GET))""",
        "description": "Comparing cryptographic hashes, signatures, or security tokens with standard comparison operators (==, ===) terminates on the first mismatched byte, creating timing side-channels that attackers can exploit to forge signatures byte-by-byte (SonarQube S5808).",
        "remediation": "Use constant-time comparison methods: hmac.compare_digest() in Python, crypto.timingSafeEqual() in Node.js, or MessageDigest.isEqual() in Java.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 30. XPath Injection (SonarQube RSPEC S2091)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2091",
        "sonar_key": "S2091",
        "sonar_rule_id": "python:S2091",
        "name": "XPath queries should not be vulnerable to injection attacks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript", "php"],
        "cwe": "CWE-643",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-643"],
        "regex": r"""(?i)(?:\.xpath|evaluate|compile)\s*\(\s*(?:f['"].*//|['"].*//.*['"]\s*\+|\`.*//.*\$\{)""",
        "description": "Constructing XPath expressions dynamically using unvalidated user input enables XPath Injection, allowing attackers to extract unauthorized XML tree nodes or bypass authentication checks (SonarQube S2091).",
        "remediation": "Use parameterized XPath queries or precompiled XPath expressions with variable resolvers.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 31. Sensitive Data in Logs (SonarQube RSPEC S5838)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5838",
        "sonar_key": "S5838",
        "sonar_rule_id": "common:S5838",
        "name": "Logging sensitive information is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-532",
        "owasp": "OWASP:A09:2021",
        "standards": ["OWASP:A09:2021", "ISO-27001:A.8.12", "PCI-DSS:Req-3.4", "CWE-532"],
        "regex": r"""(?i)(?:logger\.(?:info|debug|warn|error)|console\.log|logging\.(?:info|debug|warning|error))\s*\([^\)]*(?:password|passwd|private_key|secret_key|credit_card|cvv|token)""",
        "description": "Writing sensitive information like plaintext passwords, API tokens, or credit card numbers into application logs exposes them to unauthorized internal operators and centralized log aggregators (SonarQube S5838).",
        "remediation": "Mask or scrub sensitive parameters before logging, or configure structured logging with redaction filters.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 32. Resource Leaks / Unclosed Connections (SonarQube RSPEC S2095)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2095",
        "sonar_key": "S2095",
        "sonar_rule_id": "java:S2095",
        "name": "Resources should be closed to prevent resource leaks",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "CODE_SMELL",
        "sonar_severity": "MAJOR",
        "severity": "LOW",
        "languages": ["python", "java", "javascript", "go"],
        "cwe": "CWE-772",
        "owasp": "OWASP:A05:2021",
        "standards": ["ISO-27001:A.8.28", "CWE-772"],
        "regex": r"""(?i)(?:socket\.socket\(\)|new\s+FileInputStream|new\s+FileOutputStream|sqlite3\.connect\([^\)]+\)|psycopg2\.connect\([^\)]+\))(?!.*\bwith\b)""",
        "description": "Failing to release system resources such as file handles, database connections, and network sockets leads to resource starvation and denial-of-service (SonarQube S2095).",
        "remediation": "Wrap resource allocations in deterministic cleanup constructs like 'with' statements in Python or try-with-resources in Java.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 33. Insecure Cookie SameSite Setting (SonarQube RSPEC S3330)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S3330",
        "sonar_key": "S3330",
        "sonar_rule_id": "javascript:S3330",
        "name": "Cookies should have 'SameSite' attribute configured",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-1275",
        "owasp": "OWASP:A01:2021",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-1275"],
        "regex": r"""(?i)(?:set_cookie|res\.cookie)\s*\([^\)]*(?:samesite\s*=\s*['"]None['"]|sameSite\s*:\s*['"]none['"])""",
        "description": "Setting cookie SameSite attribute to 'None' without strict validation permits cross-site requests to include credentials, increasing exposure to Cross-Site Request Forgery (CSRF) (SonarQube S3330).",
        "remediation": "Configure cookies with SameSite='Lax' or SameSite='Strict' to prevent unauthorized cross-site credential transmission.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 34. Insecure Mass Assignment (SonarQube RSPEC S5167)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5167",
        "sonar_key": "S5167",
        "sonar_rule_id": "python:S5167",
        "name": "Object binding should not be vulnerable to mass assignment",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "ruby", "php"],
        "cwe": "CWE-915",
        "owasp": "OWASP:A08:2021",
        "standards": ["OWASP:A08:2021", "ISO-27001:A.8.28", "CWE-915"],
        "regex": r"""(?i)(?:User\.objects\.filter\([^)]*\)\.update\(\*\*req\.(?:data|POST)|Object\.assign\s*\(\s*(?:user|account),\s*req\.body|\.update_attributes\s*\(\s*params\[)""",
        "description": "Binding incoming client request parameters directly into database model instances without property whitelisting allows attackers to overwrite administrative fields like is_admin or role (SonarQube S5167).",
        "remediation": "Use explicit Data Transfer Objects (DTOs), Pydantic schemas with whitelisted fields, or framework permit parameters (e.g. strong parameters).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 35. Missing Rate Limiting on Auth Endpoints (SonarQube RSPEC S6287)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6287",
        "sonar_key": "S6287",
        "sonar_rule_id": "python:S6287",
        "name": "Authentication endpoints should implement rate limiting",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-307",
        "owasp": "OWASP:A07:2021",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.28", "CWE-307"],
        "regex": r"""(?i)@app\.(?:post|put)\s*\(\s*['"]/(?:api/)?(?:login|signin|authenticate|auth/token)['"]\)(?![^@]*@limiter)""",
        "description": "Authentication and credential verification endpoints without rate limiting are susceptible to credential stuffing and brute force attacks (SonarQube S6287).",
        "remediation": "Apply IP-based and user-based rate limiting (e.g. slowapi, express-rate-limit) with progressive delays and account lockout policies.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 36. Hardcoded Database Credentials in URI (SonarQube RSPEC S2115)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2115",
        "sonar_key": "S2115",
        "sonar_rule_id": "common:S2115",
        "name": "Database connections should not expose hardcoded credentials",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go", "php"],
        "cwe": "CWE-798",
        "owasp": "OWASP:A07:2021",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.12", "CWE-798"],
        "regex": r"""(?i)['"](?:postgres|postgresql|mysql|mongodb|redis|amqp)://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-\.!@#$%^&*]+@[a-zA-Z0-9_\-\.]+""",
        "description": "Hardcoding database connection strings containing plaintext usernames and passwords in code exposes internal database infrastructure to unauthorized access (SonarQube S2115).",
        "remediation": "Store database connection strings in environment variables or cloud secret managers and inject them dynamically at runtime.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 37. Unsafe Dynamic Reflection / Object Instantiation (SonarQube RSPEC S5706)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5706",
        "sonar_key": "S5706",
        "sonar_rule_id": "java:S5706",
        "name": "Dynamic class loading and reflection should be restricted",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript", "php"],
        "cwe": "CWE-470",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-470"],
        "regex": r"""(?i)(?:Class\.forName\s*\(\s*(?:req\.|request\.)|getattr\s*\(\s*(?:__import__|sys\.modules),\s*(?:req\.|request\.)|new\s+\$class_name)""",
        "description": "Instantiating classes or executing methods derived directly from unvalidated client parameters allows attackers to trigger unsafe reflection gadgets and execute arbitrary code (SonarQube S5706).",
        "remediation": "Validate class and method names against a strict allowlist of permitted types before dynamic instantiation.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 38. Weak RSA Padding / Non-OAEP (SonarQube RSPEC S2277)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2277",
        "sonar_key": "S2277",
        "sonar_rule_id": "common:S2277",
        "name": "RSA algorithm should use OAEP padding instead of PKCS#1 v1.5",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript", "c", "cpp", "go"],
        "cwe": "CWE-780",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-780"],
        "regex": r"""(?i)(?:PKCS1_v1_5|Cipher\.getInstance\(['"]RSA/ECB/PKCS1Padding['"]\)|RSA\.PKCS1_PADDING)""",
        "description": "PKCS#1 v1.5 padding is vulnerable to adaptive chosen-ciphertext attacks (Bleichenbacher's attack) that allow decryption without the private key (SonarQube S2277).",
        "remediation": "Use RSA with Optimal Asymmetric Encryption Padding (RSA-OAEP) with SHA-256 for asymmetric encryption.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 41. JavaScript Prototype Pollution (SonarQube RSPEC S6035)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6035",
        "sonar_key": "S6035",
        "sonar_rule_id": "javascript:S6035",
        "name": "Modifying Object prototype or recursive merge is security-sensitive (Prototype Pollution)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["javascript", "typescript"],
        "cwe": "CWE-1321",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-1321"],
        "regex": r"""(?i)(?:(?:Object\.assign|_?\b(?:merge|extend|defaultsDeep))\s*\(\s*(?:\{\}|target|this)[^)]*(?:req\.body|__proto__|constructor\.prototype)|\[['"](?:__proto__|prototype|constructor)['"]\]\s*=)""",
        "description": "Modifying standard object prototypes or recursively merging untrusted inputs can allow attackers to inject properties into all objects across the JavaScript runtime (SonarQube S6035).",
        "remediation": "Use Object.create(null) for dictionary maps, freeze Object.prototype with Object.freeze(), or sanitize keys to reject '__proto__' and 'constructor'.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 42. Predictable / Static Initialization Vector (IV) (SonarQube RSPEC S3329)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S3329",
        "sonar_key": "S3329",
        "sonar_rule_id": "common:S3329",
        "name": "Cipher Block Chaining (CBC) with static or predictable IV is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript", "c", "cpp", "go", "php"],
        "cwe": "CWE-329",
        "owasp": "OWASP:A02:2021",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-329"],
        "regex": r"""(?i)(?:b['"][0-9a-fA-F]{16,32}['"]|bytes\(\s*16\s*\)|new\s+IvParameterSpec\(\s*new\s+byte\[16\]\)|new\s+Buffer\(\s*16\s*\)|crypto\.createCipheriv\(['"][^'"]+['"],\s*[^,]+,\s*(?:['"]0000000000000000['"]|Buffer\.alloc\(16\)))""",
        "description": "Using a static, zeroed, or predictable Initialization Vector (IV) in CBC encryption undermines confidentiality, enabling plaintext recovery and chosen-ciphertext attacks (SonarQube S3329).",
        "remediation": "Generate a unique, cryptographically strong random IV for every encryption operation (e.g. os.urandom(16) or crypto.randomBytes(16)).",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 43. GraphQL Introspection Enabled (SonarQube RSPEC S6350)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6350",
        "sonar_key": "S6350",
        "sonar_rule_id": "common:S6350",
        "name": "GraphQL schema introspection or unlimited query depth should not be enabled in production",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["javascript", "typescript", "python", "java", "go"],
        "cwe": "CWE-770",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-770"],
        "regex": r"""(?i)(?:introspection\s*:\s*true\b|validationRules\s*:\s*\[\s*\]|apolloServer\s*\(\s*\{[^\}]*introspection\s*:\s*true)""",
        "description": "Enabling GraphQL schema introspection in production allows attackers to discover hidden internal queries, mutations, and models (SonarQube S6350).",
        "remediation": "Disable introspection in production environments and configure maximum query depth / complexity limits.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 44. Sensitive Data in GET URL Parameters (SonarQube RSPEC S6358)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6358",
        "sonar_key": "S6358",
        "sonar_rule_id": "common:S6358",
        "name": "Sensitive information should not be transmitted in URL query parameters",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "MAJOR",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go", "php"],
        "cwe": "CWE-598",
        "owasp": "OWASP:A04:2021",
        "standards": ["OWASP:A04:2021", "ISO-27001:A.8.28", "CWE-598"],
        "regex": r"""(?i)(?:requests\.get|fetch|axios\.get)\s*\([^)]*[\?&](?:password|passwd|token|secret|api_key|access_token)=""",
        "description": "Passing authentication tokens or passwords in GET query parameters logs sensitive secrets in browser histories, web server access logs, and proxy traces (SonarQube S6358).",
        "remediation": "Send credentials in the HTTP Authorization header or request body via POST/PUT over HTTPS.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 45. Command Line Argument Injection (SonarQube RSPEC S6353)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6353",
        "sonar_key": "S6353",
        "sonar_rule_id": "common:S6353",
        "name": "Arguments passed to external commands should be validated to prevent argument injection",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp", "go", "php", "shell"],
        "cwe": "CWE-88",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-88"],
        "regex": r"""(?i)(?:subprocess\.Popen|subprocess\.run|execFile|child_process\.spawn)\s*\(\s*\[\s*['"](?:tar|curl|wget|find|git|ssh|rsync)['"],\s*(?:req\.|request\.|user_input)""",
        "description": "Passing unvalidated user inputs as leading flags or options to command-line utilities can result in argument injection (e.g. '--checkpoint-action=exec=...' in tar) (SonarQube S6353).",
        "remediation": "Prepend '--' before user arguments to delimit options from file arguments, or validate inputs against a strict allowlist.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 46. Spring Boot Actuator Endpoints Exposure (SonarQube RSPEC S5301)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5301",
        "sonar_key": "S5301",
        "sonar_rule_id": "java:S5301",
        "name": "Spring Boot Actuator endpoints should not be exposed to the public internet",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["java", "yaml"],
        "cwe": "CWE-200",
        "owasp": "OWASP:A05:2021",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-200"],
        "regex": r"""(?i)(?:management\.endpoints\.web\.exposure\.include\s*[:=]\s*(?:['"]\*['"]|\*)|management\.endpoint\.(?:env|heapdump|shutdown)\.enabled\s*[:=]\s*true)""",
        "description": "Exposing sensitive Spring Boot Actuator endpoints like /env, /heapdump, or /shutdown leaks internal environment variables, database credentials, and heap data (SonarQube S5301).",
        "remediation": "Restrict exposed actuator endpoints to 'health,info' and require administrative authentication for any diagnostic endpoints.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 47. Anonymous LDAP Binding (SonarQube RSPEC S5876)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5876",
        "sonar_key": "S5876",
        "sonar_rule_id": "common:S5876",
        "name": "LDAP connections should authenticate with verified credentials rather than anonymous bind",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ["python", "java", "javascript", "php"],
        "cwe": "CWE-287",
        "owasp": "OWASP:A07:2021",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.28", "CWE-287"],
        "regex": r"""(?i)(?:ldap\.initialize\([^)]*\)\.simple_bind_s\(\s*['"]['"],\s*['"]['"]\)|new\s+SimpleBindRequest\(\s*['"]['"],\s*['"]['"]\)|SECURITY_AUTHENTICATION,\s*['"]none['"])""",
        "description": "Connecting to directory services using anonymous binds (empty DN and password) bypasses authentication and exposes organizational user hierarchies (SonarQube S5876).",
        "remediation": "Always specify valid, authenticated bind credentials with appropriate role-based directory permissions.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 48. Hardcoded JWT Secret / HMAC Key (SonarQube RSPEC S6362)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6362",
        "sonar_key": "S6362",
        "sonar_rule_id": "common:S6362",
        "name": "JWT secret keys should not be hardcoded in application source code",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go", "php"],
        "cwe": "CWE-798",
        "owasp": "OWASP:A07:2021",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.12", "CWE-798"],
        "regex": r"""(?i)(?:jwt\.(?:sign|encode|decode|verify)\s*\(.+?,\s*['"][^"'\n]{8,}['"]|JWT_SECRET\s*[:=]\s*['"][^'"]+['"])""",
        "description": "Hardcoding JWT signing keys directly in application source code permits token forgery, privilege escalation, and full identity impersonation (SonarQube S6362).",
        "remediation": "Read JWT secret keys from securely managed environment variables or KMS services.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 49. Unrestricted File Upload Without MIME Validation (SonarQube RSPEC S5165)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5165",
        "sonar_key": "S5165",
        "sonar_rule_id": "common:S5165",
        "name": "Uploaded files should be validated for type, extension, and content before storage",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "php", "go"],
        "cwe": "CWE-434",
        "owasp": "OWASP:A04:2021",
        "standards": ["OWASP:A04:2021", "ISO-27001:A.8.28", "CWE-434"],
        "regex": r"""(?i)(?:file\.save\s*\(\s*(?:os\.path\.join\([^)]*file\.filename|UPLOAD_FOLDER\s*\+\s*file\.filename)|mv\s*\(\s*(?:uploads_dir|uploadDir)\s*\+\s*req\.files|move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\['tmp_name'\],\s*\$uploadfile\))""",
        "description": "Saving uploaded files directly using the client-provided filename without validating extensions or stripping directory traversal characters allows web shell uploads and arbitrary file writes (SonarQube S5165).",
        "remediation": "Generate random filenames for uploads (UUIDs), store files outside the web root, and validate file magic bytes rather than trusting client MIME types.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # 50. SQL Wildcard Injection in LIKE / ILIKE Clauses (SonarQube RSPEC S6351)
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6351",
        "sonar_key": "S6351",
        "sonar_rule_id": "common:S6351",
        "name": "User input in SQL LIKE clauses should be escaped to prevent wildcard injection",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php", "go"],
        "cwe": "CWE-89",
        "owasp": "OWASP:A03:2021",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-89"],
        "regex": r"""(?i)(?:WHERE.*LIKE\s+['"]%['"]\s*\+\s*(?:req\.|request\.)|f['"].*WHERE.*LIKE\s*['"]%\{|LIKE\s*f['"]%\{request)""",
        "description": "Interpolating unescaped user input directly into SQL LIKE/ILIKE patterns allows wildcard injection (% and _), leading to denial of service or exhaustive pattern extraction (SonarQube S6351).",
        "remediation": "Escape SQL wildcards (replace '%' with '\\%' and '_' with '\\_') before binding parameters to LIKE queries.",
        "is_active": True
    },

    # -------------------------------------------------------------------------
    # SonarQube RSPEC S4507: Delivering code in production with debug mode enab
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4507",
        "sonar_key": "S4507",
        "sonar_rule_id": "common:S4507",
        "name": "Delivering code in production with debug mode enabled is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-489",
        "owasp": "OWASP:A05:2021",
        "standards": ['OWASP:A05:2021', 'ISO-27001:A.8.28', 'CWE-489'],
        "regex": r"""(?i)(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV\s*[:=]\s*['\"]development['\"]|display_errors\s*=\s*(?:1|On))""",
        "description": "Enabling debug mode in production exposes verbose error messages, interactive consoles, and sensitive environment variables to remote attackers (SonarQube S4507).",
        "remediation": "Disable debug mode in production configurations (e.g. DEBUG = False or set NODE_ENV='production').",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S6096: Extracting archives should not be vulnerable to di
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6096",
        "sonar_key": "S6096",
        "sonar_rule_id": "common:S6096",
        "name": "Extracting archives should not be vulnerable to directory traversal (Zip Slip)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ['python', 'javascript', 'typescript', 'java', 'go'],
        "cwe": "CWE-22",
        "owasp": "OWASP:A01:2021",
        "standards": ['OWASP:A01:2021', 'ISO-27001:A.8.28', 'CWE-22'],
        "regex": r"""(?i)(?:tarfile\.open\([^)]*\)\.extractall|zipfile\.ZipFile\([^)]*\)\.extractall|unzip\s*\(\s*[^,)]+,\s*\{|admZip\.extractAllTo)""",
        "description": "Extracting archive members without validating entry relative paths allows Zip Slip attacks where paths with '../../' overwrite arbitrary system files (SonarQube S6096).",
        "remediation": "Validate target file canonical paths before extracting: ensure os.path.commonpath([dest, member_path]) == dest.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5804: Server-Side Template Injection (SSTI) is security-
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5804",
        "sonar_key": "S5804",
        "sonar_rule_id": "common:S5804",
        "name": "Server-Side Template Injection (SSTI) is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-1336",
        "owasp": "OWASP:A03:2021",
        "standards": ['OWASP:A03:2021', 'ISO-27001:A.8.28', 'CWE-1336'],
        "regex": r"""(?i)(?:render_template_string\s*\(\s*(?:req\.|request\.|f['\"]|.*\+)|jinja2\.Template\s*\(\s*(?:req\.|request\.)|ejs\.render\s*\(\s*(?:req\.body|req\.query))""",
        "description": "Passing user input directly into template engine compilation functions permits Server-Side Template Injection (SSTI), leading to Remote Code Execution (SonarQube S5804).",
        "remediation": "Store templates in static files and pass user input strictly as template context variables instead of compiling dynamic template strings.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5328: Disabling SSL/TLS certificate validation is securi
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5328",
        "sonar_key": "S5328",
        "sonar_rule_id": "common:S5328",
        "name": "Disabling SSL/TLS certificate validation is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "CRITICAL",
        "languages": ['python', 'javascript', 'typescript', 'java', 'go'],
        "cwe": "CWE-295",
        "owasp": "OWASP:A07:2021",
        "standards": ['OWASP:A07:2021', 'ISO-27001:A.8.28', 'CWE-295'],
        "regex": r"""(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning|TrustAllStrategy|CheckServerIdentity\s*:\s*\(\)\s*=>\s*true)""",
        "description": "Disabling TLS certificate or hostname verification enables Man-in-the-Middle (MitM) attacks allowing adversaries to eavesdrop on or alter network traffic (SonarQube S5328).",
        "remediation": "Keep certificate validation enabled (verify=True, rejectUnauthorized: true) and use valid public or internal CA certificates.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5247: Logging should not be vulnerable to log injection 
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5247",
        "sonar_key": "S5247",
        "sonar_rule_id": "common:S5247",
        "name": "Logging should not be vulnerable to log injection (CRLF Injection)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-117",
        "owasp": "OWASP:A09:2021",
        "standards": ['OWASP:A09:2021', 'ISO-27001:A.8.15', 'CWE-117'],
        "regex": r"""(?i)(?:logger\.(?:info|error|warn|debug)\s*\(\s*(?:f['\"].*(?:request\.|req\.)|['\"].*\s*\+\s*(?:request\.|req\.query|req\.headers)))""",
        "description": "Writing unescaped user input containing carriage return and newline characters (\r\n) into server logs permits log forging and log injection attacks (SonarQube S5247).",
        "remediation": "Strip carriage returns and newlines from user input before logging, or use structured JSON logging formatters.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5445: Creating temporary files without appropriate acces
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5445",
        "sonar_key": "S5445",
        "sonar_rule_id": "common:S5445",
        "name": "Creating temporary files without appropriate access permissions is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "HIGH",
        "severity": "HIGH",
        "languages": ['python', 'c', 'cpp', 'php'],
        "cwe": "CWE-377",
        "owasp": "OWASP:A01:2021",
        "standards": ['OWASP:A01:2021', 'ISO-27001:A.8.28', 'CWE-377'],
        "regex": r"""(?i)(?:tempfile\.mktemp\s*\(|os\.tempnam\s*\(|File\.createTempFile\s*\([^,)]+,\s*[^,)]+\)|tmpnam\s*\()""",
        "description": "Using insecure temporary file functions like mktemp creates race conditions (TOCTOU) and allows local attackers to hijack or tamper with file paths (SonarQube S5445).",
        "remediation": "Use secure atomic temp file creators such as tempfile.NamedTemporaryFile() or tempfile.mkstemp() with restricted umask (0600).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S2053: Salting passwords with static or missing salt is s
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2053",
        "sonar_key": "S2053",
        "sonar_rule_id": "common:S2053",
        "name": "Salting passwords with static or missing salt is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-916",
        "owasp": "OWASP:A02:2021",
        "standards": ['OWASP:A02:2021', 'PCI-DSS:Req-8.2', 'CWE-916'],
        "regex": r"""(?i)(?:hashlib\.sha256\s*\(\s*password\.encode|crypto\.createHash\(['\"]sha256['\"]\)\.update\((?:password|pwd)\)|hashlib\.md5\s*\(\s*password)""",
        "description": "Hashing passwords using single-iteration algorithms without unique cryptographically random salts allows precomputed rainbow table attacks (SonarQube S2053).",
        "remediation": "Use adaptive password hashing algorithms: Argon2id, bcrypt, or PBKDF2 with at least 100,000 iterations and per-user random salt.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S4426: Cryptographic keys should be robust and meet minim
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4426",
        "sonar_key": "S4426",
        "sonar_rule_id": "common:S4426",
        "name": "Cryptographic keys should be robust and meet minimum key lengths",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'go'],
        "cwe": "CWE-326",
        "owasp": "OWASP:A02:2021",
        "standards": ['OWASP:A02:2021', 'NIST-SSDF:PW.7', 'CWE-326'],
        "regex": r"""(?i)(?:RSA\.generate\s*\(\s*(?:512|1024)\s*\)|generateKeyPair\s*\(\s*['\"]rsa['\"],\s*\{[^}]*modulusLength\s*:\s*(?:512|1024)|KeyPairGenerator\.getInstance\(['\"]RSA['\"]\)\.initialize\s*\(\s*(?:512|1024)\))""",
        "description": "Generating RSA keys with modulus lengths below 2048 bits allows factoring attacks and key compromise using modern cloud compute (SonarQube S4426).",
        "remediation": "Use RSA key lengths of at least 2048 bits (recommended 3072 or 4096 bits) or modern elliptic curves (Ed25519, NIST P-256).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S4818: Sockets should use TLS/SSL encryption for network 
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4818",
        "sonar_key": "S4818",
        "sonar_rule_id": "common:S4818",
        "name": "Sockets should use TLS/SSL encryption for network communication",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'c', 'cpp'],
        "cwe": "CWE-319",
        "owasp": "OWASP:A02:2021",
        "standards": ['OWASP:A02:2021', 'ISO-27001:A.8.24', 'CWE-319'],
        "regex": r"""(?i)(?:socket\.socket\s*\(.*AF_INET.*SOCK_STREAM\)(?!.*ssl\.wrap_socket)|http\.client\.HTTPConnection\s*\(|new\s+Socket\s*\([^,)]+,\s*(?:80|21|23|25)\))""",
        "description": "Opening plain TCP sockets without TLS encapsulation transmits sensitive application payloads in cleartext across network perimeters (SonarQube S4818).",
        "remediation": "Wrap TCP sockets with TLS/SSL context (e.g. ssl.create_default_context().wrap_socket(sock)) or use HTTPS/WSS protocols.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S4823: Executing processes with untrusted command line ar
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4823",
        "sonar_key": "S4823",
        "sonar_rule_id": "common:S4823",
        "name": "Executing processes with untrusted command line arguments is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "HIGH",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'go'],
        "cwe": "CWE-88",
        "owasp": "OWASP:A03:2021",
        "standards": ['OWASP:A03:2021', 'ISO-27001:A.8.28', 'CWE-88'],
        "regex": r"""(?i)(?:subprocess\.run\s*\(\s*\[[^,\]]+,\s*(?:sys\.argv|req\.query|request\.args)|child_process\.execFile\s*\([^,]+,\s*\[\s*(?:req\.query|req\.body))""",
        "description": "Passing user-controlled arguments to CLI process invocations without strict whitelist validation enables argument injection attacks (SonarQube S4823).",
        "remediation": "Validate process arguments against an explicit whitelist of allowed characters or use end-of-options delimiters ('--') before arguments.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S2631: Regular expressions should not be vulnerable to ex
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2631",
        "sonar_key": "S2631",
        "sonar_rule_id": "common:S2631",
        "name": "Regular expressions should not be vulnerable to exponential backtracking (ReDoS)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-1333",
        "owasp": "OWASP:A05:2021",
        "standards": ['OWASP:A05:2021', 'CWE-1333'],
        "regex": r"""(?:re\.(?:compile|search|match|findall)\s*\(\s*r?['"][^'"]*(?:\([^'"]+\+?\)\+)[^'"]*['"]|(?:new\s+)?RegExp\s*\(\s*['"][^'"]*(?:\([^'"]+\+?\)\+)[^'"]*['"]|\/(?:[a-zA-Z0-9_\-\.]+\+)+\+\/)""",
        "description": "Complex regular expressions with overlapping or nested repetitions lead to catastrophic exponential backtracking and CPU denial of service (SonarQube S2631).",
        "remediation": "Simplify regex patterns to avoid nested quantifiers or set execution timeouts on regex operations.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S3649: Database queries should use parameterized APIs ins
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S3649",
        "sonar_key": "S3649",
        "sonar_rule_id": "common:S3649",
        "name": "Database queries should use parameterized APIs instead of raw string formatting",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-89",
        "owasp": "OWASP:A03:2021",
        "standards": ['OWASP:A03:2021', 'ISO-27001:A.8.28', 'CWE-89'],
        "regex": r"""(?i)(?:\.extra\s*\(\s*where\s*=\s*\[\s*f['\"]|\.raw\s*\(\s*f['\"]|\.query\s*\(\s*`SELECT[^`]*\$\{)""",
        "description": "Using raw ORM query extensions with dynamic f-strings concatenates unescaped user data directly into SQL execution contexts (SonarQube S3649).",
        "remediation": "Use ORM parameter binding: Model.objects.raw('SELECT * FROM t WHERE id = %s', [user_id]).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S6242: Sensitive information should not be stored unencry
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6242",
        "sonar_key": "S6242",
        "sonar_rule_id": "common:S6242",
        "name": "Sensitive information should not be stored unencrypted in local client storage",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR",
        "severity": "MEDIUM",
        "languages": ['javascript', 'typescript'],
        "cwe": "CWE-312",
        "owasp": "OWASP:A04:2021",
        "standards": ['OWASP:A04:2021', 'ISO-27001:A.8.12', 'CWE-312'],
        "regex": r"""(?i)localStorage\.setItem\s*\(\s*['\"](?:password|credit_card|cvv|api_secret|auth_token_plain)['\"]""",
        "description": "Saving plaintext credentials or private encryption keys to browser LocalStorage leaves them accessible to any script via XSS (SonarQube S6242).",
        "remediation": "Store sensitive session identifiers in HttpOnly, Secure, SameSite cookies instead of accessible LocalStorage.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S6363: LDAP queries should not be vulnerable to LDAP inje
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S6363",
        "sonar_key": "S6363",
        "sonar_rule_id": "common:S6363",
        "name": "LDAP queries should not be vulnerable to LDAP injection",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'php'],
        "cwe": "CWE-90",
        "owasp": "OWASP:A03:2021",
        "standards": ['OWASP:A03:2021', 'ISO-27001:A.8.28', 'CWE-90'],
        "regex": r"""(?i)(?:ldap\.search\s*\([^,)]*,\s*f['\"].*(?:uid|cn|mail)=|new\s+DirContext\.search\s*\([^,)]+,\s*['\"].*\+)""",
        "description": "Concatenating user input directly into LDAP search filters permits LDAP injection and unauthorized directory access (SonarQube S6363).",
        "remediation": "Sanitize LDAP filter characters (*, (, ), \\\\, NUL) using ldap.filter.escape_filter_chars() or parameterized directory APIs.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5164: Deserializing untrusted data with Java ObjectInput
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5164",
        "sonar_key": "S5164",
        "sonar_rule_id": "common:S5164",
        "name": "Deserializing untrusted data with Java ObjectInputStream or Python marshal is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ['python', 'java'],
        "cwe": "CWE-502",
        "owasp": "OWASP:A08:2021",
        "standards": ['OWASP:A08:2021', 'ISO-27001:A.8.28', 'CWE-502'],
        "regex": r"""(?i)(?:marshal\.loads\s*\(|_pickle\.loads\s*\(|new\s+ObjectInputStream\s*\([^)]*\)\.readObject\s*\(\))""",
        "description": "Deserializing unauthenticated binary streams using marshal or Java ObjectInputStream triggers arbitrary code execution gadgets (SonarQube S5164).",
        "remediation": "Use safe serialization formats like JSON, Protocol Buffers, or HMAC signatures to authenticate serialized payloads before reading.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5857: User input should be sanitized before being used i
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5857",
        "sonar_key": "S5857",
        "sonar_rule_id": "common:S5857",
        "name": "User input should be sanitized before being used in dynamic code execution",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER",
        "severity": "CRITICAL",
        "languages": ['javascript', 'typescript', 'python', 'php'],
        "cwe": "CWE-95",
        "owasp": "OWASP:A03:2021",
        "standards": ['OWASP:A03:2021', 'ISO-27001:A.8.28', 'CWE-95'],
        "regex": r"""(?i)(?:eval\s*\(\s*(?:req\.body|req\.query|request\.args)|new\s+Function\s*\(\s*['\"][^'\"]*['\"],\s*(?:req\.body|req\.query)|vm\.runInContext\s*\(\s*(?:req\.))""",
        "description": "Executing dynamic code constructed from HTTP request data allows attackers to execute arbitrary commands inside the server runtime (SonarQube S5857).",
        "remediation": "Refactor logic to eliminate eval() and dynamic Function instantiation; use safe static dispatch maps or JSON.parse().",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S3331: Cookies should have the 'SameSite' attribute speci
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S3331",
        "sonar_key": "S3331",
        "sonar_rule_id": "common:S3331",
        "name": "Cookies should have the 'SameSite' attribute specified to prevent CSRF",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MINOR",
        "severity": "MEDIUM",
        "languages": ['javascript', 'typescript', 'python', 'php', 'java'],
        "cwe": "CWE-1275",
        "owasp": "OWASP:A01:2021",
        "standards": ['OWASP:A01:2021', 'ISO-27001:A.8.28', 'CWE-1275'],
        "regex": r"""(?i)(?:res\.cookie\s*\([^,)]+,\s*[^,)]+,\s*\{(?![^}]*sameSite)|set_cookie\s*\([^,)]+,\s*[^,)]+(?![^)]*samesite=))""",
        "description": "Setting HTTP response cookies without an explicit SameSite policy defaults to Lax or None in legacy environments, increasing CSRF vulnerability (SonarQube S3331).",
        "remediation": "Explicitly set SameSite='Lax' or SameSite='Strict' on all session and state management cookies.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S2259: Null pointers should not be dereferenced without v
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2259",
        "sonar_key": "S2259",
        "sonar_rule_id": "common:S2259",
        "name": "Null pointers should not be dereferenced without validation",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "BUG",
        "sonar_severity": "MAJOR",
        "severity": "HIGH",
        "languages": ['c', 'cpp', 'java'],
        "cwe": "CWE-476",
        "owasp": "MISRA-C:Rule-1.3",
        "standards": ['MISRA-C:Rule-1.3', 'ISO-26262:ASIL-D', 'CWE-476'],
        "regex": r"""(?i)(?:\*\s*\(\s*(?:void\s*\*|char\s*\*|int\s*\*)\s*\)\s*0|ptr\s*->\s*[a-zA-Z_]\w*\s*(?:;\s*(?:if|while)\s*\(\s*ptr\s*==\s*NULL\)))""",
        "description": "Dereferencing a pointer without checking for NULL causes application crashes, segment faults, or undefined behavior in safety-critical systems (SonarQube S2259).",
        "remediation": "Perform explicit NULL checks before dereferencing pointers (e.g. if (ptr != NULL) { ptr->field; }).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S2930: System resources should be closed after use (Resou
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S2930",
        "sonar_key": "S2930",
        "sonar_rule_id": "common:S2930",
        "name": "System resources should be closed after use (Resource Leak)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "BUG",
        "sonar_severity": "MAJOR",
        "severity": "HIGH",
        "languages": ['python', 'java', 'c', 'cpp'],
        "cwe": "CWE-404",
        "owasp": "MISRA-C:Rule-22.1",
        "standards": ['MISRA-C:Rule-22.1', 'ISO-27001:A.8.28', 'CWE-404'],
        "regex": r"""(?i)(?:(?:fp|file|handle)\s*=\s*open\s*\([^)]*\)\s*(?!.*(?:with|\.close\(\)))|FileInputStream\s+\w+\s*=\s*new\s+FileInputStream\s*\([^)]*\)(?!.*try-with-resources))""",
        "description": "Opening file descriptors, sockets, or database connections without deterministic closure causes descriptor leaks and system exhaustion (SonarQube S2930).",
        "remediation": "Use language context managers: 'with open(...) as f:' in Python or try-with-resources in Java.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5655: RSA encryption should use OAEP padding instead of 
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5655",
        "sonar_key": "S5655",
        "sonar_rule_id": "common:S5655",
        "name": "RSA encryption should use OAEP padding instead of PKCS#1 v1.5",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java'],
        "cwe": "CWE-780",
        "owasp": "OWASP:A02:2021",
        "standards": ['OWASP:A02:2021', 'NIST-SSDF:PW.7', 'CWE-780'],
        "regex": r"""(?i)(?:Cipher\.getInstance\s*\(\s*['\"]RSA/ECB/PKCS1Padding['\"]\)|PKCS1_v1_5\.new\s*\(|constants\.RSA_PKCS1_PADDING)""",
        "description": "RSA PKCS#1 v1.5 padding is vulnerable to padding oracle attacks (Bleichenbacher attack), allowing ciphertext decryption without the private key (SonarQube S5655).",
        "remediation": "Use RSA with Optimal Asymmetric Encryption Padding (RSA-OAEP) with SHA-256 (e.g. OAEP.new(key, SHA256)).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S4524: Disabling Cross-Site Request Forgery (CSRF) protec
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S4524",
        "sonar_key": "S4524",
        "sonar_rule_id": "common:S4524",
        "name": "Disabling Cross-Site Request Forgery (CSRF) protection is security-sensitive",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "HIGH",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java'],
        "cwe": "CWE-352",
        "owasp": "OWASP:A01:2021",
        "standards": ['OWASP:A01:2021', 'ISO-27001:A.8.28', 'CWE-352'],
        "regex": r"""(?i)(?:@csrf_exempt|\.csrf\s*\(\s*\)\s*\.disable\s*\(\)|csrf\s*:\s*false|CSRFProtect\s*=\s*False)""",
        "description": "Explicitly disabling CSRF protection on state-changing endpoints allows malicious websites to forge unauthorized actions on behalf of authenticated users (SonarQube S4524).",
        "remediation": "Enable CSRF tokens on all state-changing HTTP methods (POST, PUT, DELETE, PATCH) or enforce SameSite=Strict cookies.",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5043: XML parsers should have entity expansion limits to
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5043",
        "sonar_key": "S5043",
        "sonar_rule_id": "common:S5043",
        "name": "XML parsers should have entity expansion limits to prevent billion laughs DoS",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'java', 'c', 'cpp'],
        "cwe": "CWE-776",
        "owasp": "OWASP:A05:2021",
        "standards": ['OWASP:A05:2021', 'ISO-27001:A.8.28', 'CWE-776'],
        "regex": r"""(?i)(?:XMLParser\s*\([^)]*resolve_entities\s*=\s*True|xml\.sax\.make_parser\s*\(\s*\)|DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*FEATURE_SECURE_PROCESSING))""",
        "description": "Parsing XML documents with entity resolution enabled allows recursive entity expansion (Billion Laughs / XML Bomb) consuming all server memory (SonarQube S5043).",
        "remediation": "Disable external DTD and entity resolution (e.g. defusedxml in Python or setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)).",
        "is_active": True
    },
    # -------------------------------------------------------------------------
    # SonarQube RSPEC S5853: Cryptographic operations should not use static ini
    # -------------------------------------------------------------------------
    {
        "id": "SONAR-S5853",
        "sonar_key": "S5853",
        "sonar_rule_id": "common:S5853",
        "name": "Cryptographic operations should not use static initialization vectors (IVs)",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL",
        "severity": "HIGH",
        "languages": ['python', 'javascript', 'typescript', 'java', 'go'],
        "cwe": "CWE-329",
        "owasp": "OWASP:A02:2021",
        "standards": ['OWASP:A02:2021', 'NIST-SSDF:PW.7', 'CWE-329'],
        "regex": r"""(?i)(?:AES\.new\s*\([^,]+,\s*(?:AES\.MODE_CBC|AES\.MODE_GCM|AES\.MODE_CTR),\s*(?:iv\s*=\s*)?b['\"](?:0{16}|1234567890123456)['\"]|createCipheriv\s*\([^,]+,\s*[^,]+,\s*Buffer\.(?:alloc\(\d+\)|from\(['\"]0{16}['\"]\)\)))""",
        "description": "Reusing static or zeroed Initialization Vectors (IV) in CBC, CTR, or GCM modes destroys confidentiality and permits replay attacks (SonarQube S5853).",
        "remediation": "Always generate fresh cryptographically random IVs per encryption operation using os.urandom() or crypto.randomBytes().",
        "is_active": True
    },
]
