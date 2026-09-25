#!/usr/bin/env python3
"""
Adds 25 additional industry-standard SonarQube SAST RSPEC rules to:
1. .sentinel/rules.yaml
2. backend/rules/sonar_rules_db.py
"""

import re
import yaml

NEW_SONAR_RULES = [
    {
        "id": "SONAR-S4507",
        "sonar_key": "S4507",
        "name": "Delivering code in production with debug mode enabled is security-sensitive",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-489",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-489"],
        "regex": r"(?i)(?:DEBUG\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True|NODE_ENV\s*[:=]\s*['\"]development['\"]|display_errors\s*=\s*(?:1|On))",
        "description": "Enabling debug mode in production exposes verbose error messages, interactive consoles, and sensitive environment variables to remote attackers (SonarQube S4507).",
        "remediation": "Disable debug mode in production configurations (e.g. DEBUG = False or set NODE_ENV='production').",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S6096",
        "sonar_key": "S6096",
        "name": "Extracting archives should not be vulnerable to directory traversal (Zip Slip)",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-22",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-22"],
        "regex": r"(?i)(?:tarfile\.open\([^)]*\)\.extractall|zipfile\.ZipFile\([^)]*\)\.extractall|unzip\s*\(\s*[^,)]+,\s*\{|admZip\.extractAllTo)",
        "description": "Extracting archive members without validating entry relative paths allows Zip Slip attacks where paths with '../../' overwrite arbitrary system files (SonarQube S6096).",
        "remediation": "Validate target file canonical paths before extracting: ensure os.path.commonpath([dest, member_path]) == dest.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    },
    {
        "id": "SONAR-S5804",
        "sonar_key": "S5804",
        "name": "Server-Side Template Injection (SSTI) is security-sensitive",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-1336",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-1336"],
        "regex": r"(?i)(?:render_template_string\s*\(\s*(?:req\.|request\.|f['\"]|.*\+)|jinja2\.Template\s*\(\s*(?:req\.|request\.)|ejs\.render\s*\(\s*(?:req\.body|req\.query))",
        "description": "Passing user input directly into template engine compilation functions permits Server-Side Template Injection (SSTI), leading to Remote Code Execution (SonarQube S5804).",
        "remediation": "Store templates in static files and pass user input strictly as template context variables instead of compiling dynamic template strings.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    },
    {
        "id": "SONAR-S5328",
        "sonar_key": "S5328",
        "name": "Disabling SSL/TLS certificate validation is security-sensitive",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-295",
        "standards": ["OWASP:A07:2021", "ISO-27001:A.8.28", "CWE-295"],
        "regex": r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureRequestWarning|TrustAllStrategy|CheckServerIdentity\s*:\s*\(\)\s*=>\s*true)",
        "description": "Disabling TLS certificate or hostname verification enables Man-in-the-Middle (MitM) attacks allowing adversaries to eavesdrop on or alter network traffic (SonarQube S5328).",
        "remediation": "Keep certificate validation enabled (verify=True, rejectUnauthorized: true) and use valid public or internal CA certificates.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S5247",
        "sonar_key": "S5247",
        "name": "Logging should not be vulnerable to log injection (CRLF Injection)",
        "type": "sast",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-117",
        "standards": ["OWASP:A09:2021", "ISO-27001:A.8.15", "CWE-117"],
        "regex": r"(?i)(?:logger\.(?:info|error|warn|debug)\s*\(\s*(?:f['\"].*(?:request\.|req\.)|['\"].*\s*\+\s*(?:request\.|req\.query|req\.headers)))",
        "description": "Writing unescaped user input containing carriage return and newline characters (\\r\\n) into server logs permits log forging and log injection attacks (SonarQube S5247).",
        "remediation": "Strip carriage returns and newlines from user input before logging, or use structured JSON logging formatters.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S5445",
        "sonar_key": "S5445",
        "name": "Creating temporary files without appropriate access permissions is security-sensitive",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "c", "cpp", "php"],
        "cwe": "CWE-377",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-377"],
        "regex": r"(?i)(?:tempfile\.mktemp\s*\(|os\.tempnam\s*\(|File\.createTempFile\s*\([^,)]+,\s*[^,)]+\)|tmpnam\s*\()",
        "description": "Using insecure temporary file functions like mktemp creates race conditions (TOCTOU) and allows local attackers to hijack or tamper with file paths (SonarQube S5445).",
        "remediation": "Use secure atomic temp file creators such as tempfile.NamedTemporaryFile() or tempfile.mkstemp() with restricted umask (0600).",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "HIGH"
    },
    {
        "id": "SONAR-S2053",
        "sonar_key": "S2053",
        "name": "Salting passwords with static or missing salt is security-sensitive",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-916",
        "standards": ["OWASP:A02:2021", "PCI-DSS:Req-8.2", "CWE-916"],
        "regex": r"(?i)(?:hashlib\.sha256\s*\(\s*password\.encode|crypto\.createHash\(['\"]sha256['\"]\)\.update\((?:password|pwd)\)|hashlib\.md5\s*\(\s*password)",
        "description": "Hashing passwords using single-iteration algorithms without unique cryptographically random salts allows precomputed rainbow table attacks (SonarQube S2053).",
        "remediation": "Use adaptive password hashing algorithms: Argon2id, bcrypt, or PBKDF2 with at least 100,000 iterations and per-user random salt.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S4426",
        "sonar_key": "S4426",
        "name": "Cryptographic keys should be robust and meet minimum key lengths",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-326",
        "standards": ["OWASP:A02:2021", "NIST-SSDF:PW.7", "CWE-326"],
        "regex": r"(?i)(?:RSA\.generate\s*\(\s*(?:512|1024)\s*\)|generateKeyPair\s*\(\s*['\"]rsa['\"],\s*\{[^}]*modulusLength\s*:\s*(?:512|1024)|KeyPairGenerator\.getInstance\(['\"]RSA['\"]\)\.initialize\s*\(\s*(?:512|1024)\))",
        "description": "Generating RSA keys with modulus lengths below 2048 bits allows factoring attacks and key compromise using modern cloud compute (SonarQube S4426).",
        "remediation": "Use RSA key lengths of at least 2048 bits (recommended 3072 or 4096 bits) or modern elliptic curves (Ed25519, NIST P-256).",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S4818",
        "sonar_key": "S4818",
        "name": "Sockets should use TLS/SSL encryption for network communication",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "c", "cpp"],
        "cwe": "CWE-319",
        "standards": ["OWASP:A02:2021", "ISO-27001:A.8.24", "CWE-319"],
        "regex": r"(?i)(?:socket\.socket\s*\(.*AF_INET.*SOCK_STREAM\)(?!.*ssl\.wrap_socket)|http\.client\.HTTPConnection\s*\(|new\s+Socket\s*\([^,)]+,\s*(?:80|21|23|25)\))",
        "description": "Opening plain TCP sockets without TLS encapsulation transmits sensitive application payloads in cleartext across network perimeters (SonarQube S4818).",
        "remediation": "Wrap TCP sockets with TLS/SSL context (e.g. ssl.create_default_context().wrap_socket(sock)) or use HTTPS/WSS protocols.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S4823",
        "sonar_key": "S4823",
        "name": "Executing processes with untrusted command line arguments is security-sensitive",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-88",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-88"],
        "regex": r"(?i)(?:subprocess\.run\s*\(\s*\[[^,\]]+,\s*(?:sys\.argv|req\.query|request\.args)|child_process\.execFile\s*\([^,]+,\s*\[\s*(?:req\.query|req\.body))",
        "description": "Passing user-controlled arguments to CLI process invocations without strict whitelist validation enables argument injection attacks (SonarQube S4823).",
        "remediation": "Validate process arguments against an explicit whitelist of allowed characters or use end-of-options delimiters ('--') before arguments.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "HIGH"
    },
    {
        "id": "SONAR-S2631",
        "sonar_key": "S2631",
        "name": "Regular expressions should not be vulnerable to exponential backtracking (ReDoS)",
        "type": "sast",
        "severity": "MEDIUM",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-1333",
        "standards": ["OWASP:A05:2021", "CWE-1333"],
        "regex": r"(?:(?:[a-zA-Z0-9_\-\.]+\+)+\+|\([a-zA-Z0-9_\|\-\.]+\+?\)\+\+|re\.compile\s*\(['\"][^'\"]*(?:\([^'\"]+\+?\)\+)[^'\"]*['\"]\))",
        "description": "Complex regular expressions with overlapping or nested repetitions lead to catastrophic exponential backtracking and CPU denial of service (SonarQube S2631).",
        "remediation": "Simplify regex patterns to avoid nested quantifiers or set execution timeouts on regex operations.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S3649",
        "sonar_key": "S3649",
        "name": "Database queries should use parameterized APIs instead of raw string formatting",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-89",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-89"],
        "regex": r"(?i)(?:\.extra\s*\(\s*where\s*=\s*\[\s*f['\"]|\.raw\s*\(\s*f['\"]|\.query\s*\(\s*`SELECT[^`]*\$\{)",
        "description": "Using raw ORM query extensions with dynamic f-strings concatenates unescaped user data directly into SQL execution contexts (SonarQube S3649).",
        "remediation": "Use ORM parameter binding: Model.objects.raw('SELECT * FROM t WHERE id = %s', [user_id]).",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    },
    {
        "id": "SONAR-S6242",
        "sonar_key": "S6242",
        "name": "Sensitive information should not be stored unencrypted in local client storage",
        "type": "sast",
        "severity": "MEDIUM",
        "languages": ["javascript", "typescript"],
        "cwe": "CWE-312",
        "standards": ["OWASP:A04:2021", "ISO-27001:A.8.12", "CWE-312"],
        "regex": r"(?i)localStorage\.setItem\s*\(\s*['\"](?:password|credit_card|cvv|api_secret|auth_token_plain)['\"]",
        "description": "Saving plaintext credentials or private encryption keys to browser LocalStorage leaves them accessible to any script via XSS (SonarQube S6242).",
        "remediation": "Store sensitive session identifiers in HttpOnly, Secure, SameSite cookies instead of accessible LocalStorage.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S6363",
        "sonar_key": "S6363",
        "name": "LDAP queries should not be vulnerable to LDAP injection",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-90",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-90"],
        "regex": r"(?i)(?:ldap\.search\s*\([^,)]*,\s*f['\"].*(?:uid|cn|mail)=|new\s+DirContext\.search\s*\([^,)]+,\s*['\"].*\+)",
        "description": "Concatenating user input directly into LDAP search filters permits LDAP injection and unauthorized directory access (SonarQube S6363).",
        "remediation": "Sanitize LDAP filter characters (*, (, ), \\, NUL) using ldap.filter.escape_filter_chars() or parameterized directory APIs.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S5164",
        "sonar_key": "S5164",
        "name": "Deserializing untrusted data with Java ObjectInputStream or Python marshal is security-sensitive",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "java"],
        "cwe": "CWE-502",
        "standards": ["OWASP:A08:2021", "ISO-27001:A.8.28", "CWE-502"],
        "regex": r"(?i)(?:marshal\.loads\s*\(|_pickle\.loads\s*\(|new\s+ObjectInputStream\s*\([^)]*\)\.readObject\s*\(\))",
        "description": "Deserializing unauthenticated binary streams using marshal or Java ObjectInputStream triggers arbitrary code execution gadgets (SonarQube S5164).",
        "remediation": "Use safe serialization formats like JSON, Protocol Buffers, or HMAC signatures to authenticate serialized payloads before reading.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    },
    {
        "id": "SONAR-S5857",
        "sonar_key": "S5857",
        "name": "User input should be sanitized before being used in dynamic code execution",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["javascript", "typescript", "python", "php"],
        "cwe": "CWE-95",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-95"],
        "regex": r"(?i)(?:eval\s*\(\s*(?:req\.body|req\.query|request\.args)|new\s+Function\s*\(\s*['\"][^'\"]*['\"],\s*(?:req\.body|req\.query)|vm\.runInContext\s*\(\s*(?:req\.))",
        "description": "Executing dynamic code constructed from HTTP request data allows attackers to execute arbitrary commands inside the server runtime (SonarQube S5857).",
        "remediation": "Refactor logic to eliminate eval() and dynamic Function instantiation; use safe static dispatch maps or JSON.parse().",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    },
    {
        "id": "SONAR-S3331",
        "sonar_key": "S3331",
        "name": "Cookies should have the 'SameSite' attribute specified to prevent CSRF",
        "type": "sast",
        "severity": "MEDIUM",
        "languages": ["javascript", "typescript", "python", "php", "java"],
        "cwe": "CWE-1275",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-1275"],
        "regex": r"(?i)(?:res\.cookie\s*\([^,)]+,\s*[^,)]+,\s*\{(?![^}]*sameSite)|set_cookie\s*\([^,)]+,\s*[^,)]+(?![^)]*samesite=))",
        "description": "Setting HTTP response cookies without an explicit SameSite policy defaults to Lax or None in legacy environments, increasing CSRF vulnerability (SonarQube S3331).",
        "remediation": "Explicitly set SameSite='Lax' or SameSite='Strict' on all session and state management cookies.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "MINOR"
    },
    {
        "id": "SONAR-S2259",
        "sonar_key": "S2259",
        "name": "Null pointers should not be dereferenced without validation",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["c", "cpp", "java"],
        "cwe": "CWE-476",
        "standards": ["MISRA-C:Rule-1.3", "ISO-26262:ASIL-D", "CWE-476"],
        "regex": r"(?i)(?:\*\s*\(\s*(?:void\s*\*|char\s*\*|int\s*\*)\s*\)\s*0|ptr\s*->\s*[a-zA-Z_]\w*\s*(?:;\s*(?:if|while)\s*\(\s*ptr\s*==\s*NULL\)))",
        "description": "Dereferencing a pointer without checking for NULL causes application crashes, segment faults, or undefined behavior in safety-critical systems (SonarQube S2259).",
        "remediation": "Perform explicit NULL checks before dereferencing pointers (e.g. if (ptr != NULL) { ptr->field; }).",
        "sonar_type": "BUG",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S2930",
        "sonar_key": "S2930",
        "name": "System resources should be closed after use (Resource Leak)",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "java", "c", "cpp"],
        "cwe": "CWE-404",
        "standards": ["MISRA-C:Rule-22.1", "ISO-27001:A.8.28", "CWE-404"],
        "regex": r"(?i)(?:(?:fp|file|handle)\s*=\s*open\s*\([^)]*\)\s*(?!.*(?:with|\.close\(\)))|FileInputStream\s+\w+\s*=\s*new\s+FileInputStream\s*\([^)]*\)(?!.*try-with-resources))",
        "description": "Opening file descriptors, sockets, or database connections without deterministic closure causes descriptor leaks and system exhaustion (SonarQube S2930).",
        "remediation": "Use language context managers: 'with open(...) as f:' in Python or try-with-resources in Java.",
        "sonar_type": "BUG",
        "sonar_severity": "MAJOR"
    },
    {
        "id": "SONAR-S5655",
        "sonar_key": "S5655",
        "name": "RSA encryption should use OAEP padding instead of PKCS#1 v1.5",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java"],
        "cwe": "CWE-780",
        "standards": ["OWASP:A02:2021", "NIST-SSDF:PW.7", "CWE-780"],
        "regex": r"(?i)(?:Cipher\.getInstance\s*\(\s*['\"]RSA/ECB/PKCS1Padding['\"]\)|PKCS1_v1_5\.new\s*\(|constants\.RSA_PKCS1_PADDING)",
        "description": "RSA PKCS#1 v1.5 padding is vulnerable to padding oracle attacks (Bleichenbacher attack), allowing ciphertext decryption without the private key (SonarQube S5655).",
        "remediation": "Use RSA with Optimal Asymmetric Encryption Padding (RSA-OAEP) with SHA-256 (e.g. OAEP.new(key, SHA256)).",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S4524",
        "sonar_key": "S4524",
        "name": "Disabling Cross-Site Request Forgery (CSRF) protection is security-sensitive",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java"],
        "cwe": "CWE-352",
        "standards": ["OWASP:A01:2021", "ISO-27001:A.8.28", "CWE-352"],
        "regex": r"(?i)(?:@csrf_exempt|\.csrf\s*\(\s*\)\s*\.disable\s*\(\)|csrf\s*:\s*false|CSRFProtect\s*=\s*False)",
        "description": "Explicitly disabling CSRF protection on state-changing endpoints allows malicious websites to forge unauthorized actions on behalf of authenticated users (SonarQube S4524).",
        "remediation": "Enable CSRF tokens on all state-changing HTTP methods (POST, PUT, DELETE, PATCH) or enforce SameSite=Strict cookies.",
        "sonar_type": "SECURITY_HOTSPOT",
        "sonar_severity": "HIGH"
    },
    {
        "id": "SONAR-S5147",
        "sonar_key": "S5147",
        "name": "Evaluating XPath expressions should not be vulnerable to XPath injection",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "php"],
        "cwe": "CWE-643",
        "standards": ["OWASP:A03:2021", "ISO-27001:A.8.28", "CWE-643"],
        "regex": r"(?i)(?:\.xpath\s*\(\s*f['\"].*(?:@name|@id|@user)=\{|xpath\.evaluate\s*\(\s*['\"].*\+\s*(?:req\.|request\.))",
        "description": "Constructing dynamic XPath queries by string concatenation allows attackers to manipulate XML query logic and extract confidential data (SonarQube S5147).",
        "remediation": "Use parameterized XPath variables (e.g. XPathVariableResolver) instead of concatenating unescaped user input into query strings.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S5043",
        "sonar_key": "S5043",
        "name": "XML parsers should have entity expansion limits to prevent billion laughs DoS",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "java", "c", "cpp"],
        "cwe": "CWE-776",
        "standards": ["OWASP:A05:2021", "ISO-27001:A.8.28", "CWE-776"],
        "regex": r"(?i)(?:XMLParser\s*\([^)]*resolve_entities\s*=\s*True|xml\.sax\.make_parser\s*\(\s*\)|DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*FEATURE_SECURE_PROCESSING))",
        "description": "Parsing XML documents with entity resolution enabled allows recursive entity expansion (Billion Laughs / XML Bomb) consuming all server memory (SonarQube S5043).",
        "remediation": "Disable external DTD and entity resolution (e.g. defusedxml in Python or setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)).",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S5853",
        "sonar_key": "S5853",
        "name": "Cryptographic operations should not use static initialization vectors (IVs)",
        "type": "sast",
        "severity": "HIGH",
        "languages": ["python", "javascript", "typescript", "java", "go"],
        "cwe": "CWE-329",
        "standards": ["OWASP:A02:2021", "NIST-SSDF:PW.7", "CWE-329"],
        "regex": r"(?i)(?:AES\.new\s*\([^,]+,\s*(?:AES\.MODE_CBC|AES\.MODE_GCM|AES\.MODE_CTR),\s*(?:iv\s*=\s*)?b['\"](?:0{16}|1234567890123456)['\"]|createCipheriv\s*\([^,]+,\s*[^,]+,\s*Buffer\.(?:alloc\(\d+\)|from\(['\"]0{16}['\"]\)\)))",
        "description": "Reusing static or zeroed Initialization Vectors (IV) in CBC, CTR, or GCM modes destroys confidentiality and permits replay attacks (SonarQube S5853).",
        "remediation": "Always generate fresh cryptographically random IVs per encryption operation using os.urandom() or crypto.randomBytes().",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "CRITICAL"
    },
    {
        "id": "SONAR-S5706",
        "sonar_key": "S5706",
        "name": "Dynamic import / code loading should not execute user-specified modules",
        "type": "sast",
        "severity": "CRITICAL",
        "languages": ["python", "javascript", "typescript"],
        "cwe": "CWE-829",
        "standards": ["OWASP:A08:2021", "ISO-27001:A.8.28", "CWE-829"],
        "regex": r"(?i)(?:__import__\s*\(\s*(?:req\.|request\.)|importlib\.import_module\s*\(\s*(?:req\.|request\.)|require\s*\(\s*(?:req\.body|req\.query))",
        "description": "Loading executable modules or plugins directly from user-controlled paths enables arbitrary code execution within the server process (SonarQube S5706).",
        "remediation": "Validate dynamic module names against a strict internal whitelist of approved plugin identifiers.",
        "sonar_type": "VULNERABILITY",
        "sonar_severity": "BLOCKER"
    }
]

def main():
    # 1. Update .sentinel/rules.yaml
    rules_yaml_path = ".sentinel/rules.yaml"
    with open(rules_yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    existing_ids = {r["id"] for r in data.get("rules", [])}
    added_to_yaml = 0
    for r in NEW_SONAR_RULES:
        if r["id"] not in existing_ids:
            rule_entry = {
                "id": r["id"],
                "sonar_key": r["sonar_key"],
                "name": r["name"],
                "type": r["type"],
                "severity": r["severity"],
                "languages": r["languages"],
                "cwe": r["cwe"],
                "standards": r["standards"],
                "regex": r["regex"],
                "description": r["description"],
                "remediation": r["remediation"]
            }
            data["rules"].append(rule_entry)
            existing_ids.add(r["id"])
            added_to_yaml += 1

    with open(rules_yaml_path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, sort_keys=False, default_flow_style=False, allow_unicode=True)

    print(f"Added {added_to_yaml} rules to {rules_yaml_path}. Total rules: {len(data['rules'])}")

    # 2. Update backend/rules/sonar_rules_db.py
    sonar_db_path = "backend/rules/sonar_rules_db.py"
    with open(sonar_db_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Read existing IDs in sonar_rules_db
    import ast
    tree = ast.parse(content)
    existing_sonar_keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if isinstance(k, ast.Constant) and k.value == "id" and isinstance(v, ast.Constant):
                    existing_sonar_keys.add(v.value)

    # Format new rules to append to SONARQUBE_SAST_RULES list in sonar_rules_db.py
    new_entries_str = ""
    added_to_db = 0
    for r in NEW_SONAR_RULES:
        if r["id"] not in existing_sonar_keys:
            raw_regex = r["regex"].replace('\\', '\\\\')
            entry = f"""
    # -------------------------------------------------------------------------
    # SonarQube RSPEC {r['sonar_key']}: {r['name'][:50]}
    # -------------------------------------------------------------------------
    {{
        "id": "{r['id']}",
        "sonar_key": "{r['sonar_key']}",
        "sonar_rule_id": "common:{r['sonar_key']}",
        "name": "{r['name']}",
        "type": "sast",
        "rule_category": "sast",
        "rule_source": "sonarqube_rspec",
        "sonar_type": "{r.get('sonar_type', 'VULNERABILITY')}",
        "sonar_severity": "{r.get('sonar_severity', 'CRITICAL')}",
        "severity": "{r['severity']}",
        "languages": {r['languages']},
        "cwe": "{r['cwe']}",
        "owasp": "{r['standards'][0] if r['standards'] else 'OWASP:A03:2021'}",
        "standards": {r['standards']},
        "regex": r\"\"\"{r['regex']}\"\"\",
        "description": "{r['description']}",
        "remediation": "{r['remediation']}",
        "is_active": True
    }},"""
            new_entries_str += entry
            added_to_db += 1

    if added_to_db > 0:
        # Find closing bracket of SONARQUBE_SAST_RULES
        idx = content.rfind("]")
        if idx != -1:
            updated_content = content[:idx] + new_entries_str + "\n" + content[idx:]
            with open(sonar_db_path, "w", encoding="utf-8") as f:
                f.write(updated_content)
            print(f"Added {added_to_db} rules to {sonar_db_path}.")

if __name__ == "__main__":
    main()
