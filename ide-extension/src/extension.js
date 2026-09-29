/**
 * Sentinel AppSec - Visual Studio Code / Antigravity IDE Extension
 * Real-time AST security scanning, vulnerability diagnostics, hover tooltips,
 * and project custom rules reflection (.sentinel/rules.yaml).
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

// --- In-Memory Rule Store ---
let activeRules = [];
let projectCustomRules = [];
let diagnosticCollection = null;
let rulesTreeProvider = null;
let statusBarItem = null;
let serverFindingsByFile = new Map(); // normalizedFilePath -> Array<vscode.Diagnostic>
let serverFindingsRaw = []; // raw array of findings


// --- Built-in Default Security Rules ---
const DEFAULT_RULES = [
    // Project Custom Fallback Benchmark
    {
        id: "PROJ-SAST-001",
        name: "Unsafe Insecure YAML Deserialization via yaml.load",
        type: "sast",
        severity: "CRITICAL",
        languages: ["python"],
        cwe: "CWE-502",
        standards: ["OWASP:A08:2021", "ISO-27001:A.8.28"],
        regex: "yaml\\.load\\s*\\([^,)]*\\)(?!.*Loader=)",
        description: "Calling yaml.load without specifying a safe Loader permits arbitrary object deserialization and remote code execution.",
        remediation: "Always use yaml.safe_load(data) or specify Loader=yaml.SafeLoader.",
        is_project_custom: true
    },
    {
        id: "PROJ-SAST-002",
        name: "Unbounded Global Dictionary Cache",
        type: "sast",
        severity: "HIGH",
        languages: ["python"],
        cwe: "CWE-400",
        standards: ["OWASP:A04:2021", "ISO-27001:A.8.28"],
        regex: "GLOBAL_CACHE\\[[^\\]]+\\]\\s*=",
        description: "Direct unbounded assignment to an in-memory global dictionary can cause memory exhaustion under high load.",
        remediation: "Use a bounded cache implementation such as functools.lru_cache or an external cache with TTL (Redis/Memcached).",
        is_project_custom: true
    },
    {
        id: "PROJ-IAC-001",
        name: "Enforce Non-Root Application Container User",
        type: "iac",
        severity: "HIGH",
        languages: ["dockerfile"],
        cwe: "CWE-250",
        standards: ["CIS:Docker:4.1", "NIST-SSDF:PW.1.1"],
        regex: "^USER\\s+(?:root|0)(?:\\s|$)",
        description: "Container explicitly declares execution as root user, increasing the attack surface if a container escape occurs.",
        remediation: "Create and switch to an unprivileged dedicated service account: RUN useradd -u 10001 appuser && USER appuser",
        is_project_custom: true
    },
    {
        id: "PROJ-SEC-001",
        name: "Sentinel Internal Service Mesh Token Pattern",
        type: "secret",
        severity: "CRITICAL",
        languages: ["python", "javascript", "yaml", "json", "shell"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2"],
        regex: "SENTINEL_TOKEN_[0-9a-zA-Z_-]{24,}",
        description: "Found hardcoded internal Sentinel cluster authentication token embedded directly in source code.",
        remediation: "Store cluster mesh tokens in an environment secret or Vault and inject at runtime.",
        is_project_custom: true
    },

    // Built-in Secret Detection Rules (High-Entropy & Cloud Signatures)
    {
        id: "SEC-AWS-001",
        name: "AWS Access Key ID",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2", "NIST-800-53:IA-5"],
        regex: "\\b(AKIA[0-9A-Z]{16})\\b",
        min_entropy: 3.0,
        description: "Hardcoded AWS Access Key ID detected.",
        remediation: "Remove credentials and use AWS IAM roles, instance profiles, or AWS Secrets Manager."
    },
    {
        id: "SEC-AWS-002",
        name: "AWS Secret Access Key",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2", "NIST-800-53:IA-5"],
        regex: "aws_secret_access_key\\s*[:=]\\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        min_entropy: 4.0,
        description: "Hardcoded AWS Secret Access Key detected.",
        remediation: "Rotate secret immediately and use AWS Secrets Manager or environment variables."
    },
    {
        id: "SEC-GH-001",
        name: "GitHub Personal Access Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2"],
        regex: "\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\\b",
        min_entropy: 3.5,
        description: "GitHub Personal Access Token found in source code.",
        remediation: "Revoke token on GitHub and inject via GitHub Actions secrets or environment variables."
    },
    {
        id: "SEC-GH-002",
        name: "GitHub Fine-Grained Personal Access Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2"],
        regex: "\\b(github_pat_[0-9a-zA-Z_]{82})\\b",
        min_entropy: 4.0,
        description: "GitHub fine-grained PAT found in source code.",
        remediation: "Revoke token immediately in GitHub settings and store in secure vault."
    },
    {
        id: "SEC-GL-001",
        name: "GitLab Personal Access Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "CIS:SupplyChain:1.2"],
        regex: "\\b(glpat-[0-9a-zA-Z_\\-]{20,})\\b",
        min_entropy: 3.5,
        description: "GitLab Personal Access Token discovered.",
        remediation: "Revoke token in GitLab and configure CI/CD masked variables."
    },
    {
        id: "SEC-SLACK-001",
        name: "Slack Bot or User Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)",
        min_entropy: 3.0,
        description: "Slack API token embedded in plaintext.",
        remediation: "Regenerate token in Slack Developer Portal and store securely."
    },
    {
        id: "SEC-SLACK-002",
        name: "Slack Incoming Webhook",
        type: "secret",
        severity: "HIGH",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)",
        min_entropy: 3.0,
        description: "Slack webhook URL with embedded authentication tokens exposed.",
        remediation: "Inject webhook URLs through environment variables."
    },
    {
        id: "SEC-AI-001",
        name: "OpenAI API Secret Key",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "OWASP:A07:2021"],
        regex: "\\b(sk-[a-zA-Z0-9]{20,})\\b",
        min_entropy: 3.5,
        description: "OpenAI API Key detected in code.",
        remediation: "Rotate key in OpenAI Dashboard and set OPENAI_API_KEY environment variable."
    },
    {
        id: "SEC-AI-002",
        name: "Anthropic Claude API Key",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b(sk-ant-[a-zA-Z0-9_\\-]{32,})\\b",
        min_entropy: 3.5,
        description: "Anthropic API Key discovered.",
        remediation: "Rotate API key and configure via ANTHROPIC_API_KEY environment variable."
    },
    {
        id: "SEC-AI-003",
        name: "Hugging Face Access Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b(hf_[a-zA-Z0-9]{34,})\\b",
        min_entropy: 3.5,
        description: "Hugging Face authentication token found in source code.",
        remediation: "Revoke token and store in HF_TOKEN secret."
    },
    {
        id: "SEC-GOOGLE-001",
        name: "Google Cloud / Firebase API Key",
        type: "secret",
        severity: "HIGH",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b(AIza[0-9A-Za-z\\-_]{35})\\b",
        min_entropy: 3.5,
        description: "Google Cloud API Key exposed in source code.",
        remediation: "Restrict API key in GCP Console and inject at runtime."
    },
    {
        id: "SEC-STRIPE-001",
        name: "Stripe Live Secret Key",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "PCI-DSS:Req-3"],
        regex: "\\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\\b",
        min_entropy: 3.5,
        description: "Stripe Live Secret Key detected. Allows unauthorized charge processing and refund actions.",
        remediation: "Roll key immediately in Stripe Dashboard and store in KMS/Vault."
    },
    {
        id: "SEC-TWILIO-001",
        name: "Twilio API Key or Auth Token",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b((?:AC|SK)[0-9a-fA-F]{32})\\b",
        min_entropy: 3.0,
        description: "Twilio Account SID or API Key found.",
        remediation: "Store in TWILIO_AUTH_TOKEN environment variable."
    },
    {
        id: "SEC-SENDGRID-001",
        name: "SendGrid API Key",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12"],
        regex: "\\b(SG\\.[a-zA-Z0-9_\\-\\.]+\\.[a-zA-Z0-9_\\-]+)\\b",
        min_entropy: 3.8,
        description: "SendGrid API Key exposed.",
        remediation: "Revoke key on SendGrid and provide via SENDGRID_API_KEY environment variable."
    },
    {
        id: "SEC-PK-001",
        name: "Private Cryptographic Key Block",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-312",
        standards: ["ISO-27001:A.8.12", "FIPS-140-3"],
        regex: "(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
        min_entropy: 0.0,
        description: "Private cryptographic key block directly committed to repository.",
        remediation: "Remove private key immediately, rotate keypair, and mount from secure secret store."
    },
    {
        id: "SEC-DB-001",
        name: "Database Connection URI with Credentials",
        type: "secret",
        severity: "CRITICAL",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "OWASP:A07:2021"],
        regex: "((?:postgres|postgresql|mysql|mongodb|redis):\\/\\/[a-zA-Z0-9_]+:[a-zA-Z0-9_!@#$%^&*()+\\-=\\[\\]{}]+@[a-zA-Z0-9_.\\-]+)",
        min_entropy: 2.5,
        description: "Database connection string containing plaintext username and password.",
        remediation: "Construct connection string dynamically from environment variables DATABASE_URL."
    },
    {
        id: "SEC-GEN-001",
        name: "Generic High-Entropy Credential Assignment",
        type: "secret",
        severity: "HIGH",
        languages: ["*"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "OWASP:A07:2021"],
        regex: "(?:api_key|apikey|secret|token|password|passwd|auth_token)\\s*[:=]\\s*['\"]([a-zA-Z0-9_\\-\\.]{20,})['\"]",
        min_entropy: 3.8,
        description: "Hardcoded API keys, tokens, or credentials embedded directly into source code.",
        remediation: "Extract secrets into environment variables or secrets manager (AWS Secrets Manager, HashiCorp Vault)."
    },
    {
        id: "INJ-001",
        name: "SQL Injection via String Concatenation or Formatting",
        type: "sast",
        severity: "CRITICAL",
        languages: ["python", "javascript", "typescript", "java"],
        cwe: "CWE-89",
        standards: ["OWASP:A03:2021", "ISO-27001:A.8.28"],
        regex: "(?:execute|query|raw|cursor\\.execute)\\s*\\(\\s*(?:f['\"].*SELECT.*\\{|['\"].*SELECT.*['\"]\\s*\\+|`.*SELECT.*\\${)",
        description: "SQL query dynamically constructed using raw string interpolation instead of parameterized queries.",
        remediation: "Use parameterized query binds: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    },
    {
        id: "RCE-001",
        name: "OS Command Injection via Shell Execution",
        type: "sast",
        severity: "CRITICAL",
        languages: ["python", "javascript", "typescript"],
        cwe: "CWE-78",
        standards: ["OWASP:A03:2021", "ISO-27001:A.8.28"],
        regex: "(?:os\\.system|subprocess\\.call|subprocess\\.Popen|exec|shell_exec|system|popen)\\s*\\(\\s*(?:f['\"]|[^\\)]*shell\\s*=\\s*True|[^\\)]*\\+)",
        description: "Executing system shell commands with concatenated unsanitized input leads to Remote Code Execution.",
        remediation: "Pass arguments as an immutable array with shell=False, or invoke safe standard library APIs."
    },
    {
        id: "DES-001",
        name: "Insecure Deserialization via Python pickle or marshal",
        type: "sast",
        severity: "CRITICAL",
        languages: ["python"],
        cwe: "CWE-502",
        standards: ["OWASP:A08:2021", "ISO-27001:A.8.28"],
        regex: "(?:pickle\\.loads|marshal\\.loads|_pickle\\.loads)\\s*\\(",
        description: "Deserializing untrusted pickle streams allows arbitrary code execution via __reduce__ hooks.",
        remediation: "Use secure serialization formats like JSON, Protocol Buffers, or HMAC-signed tokens."
    },
    {
        id: "XSS-001",
        name: "DOM-Based Cross-Site Scripting via innerHTML",
        type: "sast",
        severity: "HIGH",
        languages: ["javascript", "typescript"],
        cwe: "CWE-79",
        standards: ["OWASP:A03:2021", "ISO-27001:A.8.28"],
        regex: "(?:\\.innerHTML|\\.outerHTML|document\\.write)\\s*=",
        description: "Writing untrusted input directly into innerHTML or document.write creates DOM XSS vulnerabilities.",
        remediation: "Use textContent, innerText, or parameterized framework templates to safely encode browser output."
    },
    {
        id: "CRY-001",
        name: "Use of Broken Cryptographic Hash Algorithm (MD5/SHA1)",
        type: "sast",
        severity: "MEDIUM",
        languages: ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        cwe: "CWE-327",
        standards: ["OWASP:A02:2021", "NIST-SP-800-131A"],
        regex: "(?:hashlib\\.md5|hashlib\\.sha1|crypto\\.createHash\\(['\"](?:md5|sha1)['\"]\\)|MD5_Init|SHA1_Init)",
        description: "MD5 and SHA1 suffer from practical collision attacks and must not be used for security purposes.",
        remediation: "Upgrade to SHA-256, SHA-3, or use Argon2id/bcrypt for password hashing."
    },
    {
        id: "MISRA-001",
        name: "MISRA C:2012 Rule 21.3 - Dynamic Memory Allocation in Safety-Critical Code",
        type: "sast",
        severity: "HIGH",
        languages: ["c", "cpp"],
        cwe: "CWE-401",
        standards: ["MISRA-C:2012:Rule-21.3", "ISO-26262-6"],
        regex: "\\b(?:malloc|calloc|realloc|free)\\s*\\(",
        description: "Dynamic heap allocation introduces fragmentation and non-deterministic latency in safety-critical systems.",
        remediation: "Allocate static memory buffers or pre-initialized object pools at boot."
    },
    {
        id: "MISRA-002",
        name: "MISRA C:2012 Rule 21.6 - Unbounded String Buffer Operation",
        type: "sast",
        severity: "HIGH",
        languages: ["c", "cpp"],
        cwe: "CWE-120",
        standards: ["MISRA-C:2012:Rule-21.6", "ISO-27001:A.8.28"],
        regex: "\\b(?:strcpy|strcat|sprintf|vsprintf|gets)\\s*\\(",
        description: "Unbounded string operations do not check target buffer capacity, causing stack buffer overflows.",
        remediation: "Use bounded string functions with explicit destination size limits: strncpy, snprintf, or strlcpy."
    },
    {
        id: "OPEN-COMM-001",
        name: "OWASP A01: Broken Access Control - Direct Insecure Object Reference (IDOR)",
        type: "sast",
        severity: "HIGH",
        languages: ["python", "javascript", "typescript"],
        cwe: "CWE-639",
        standards: ["OWASP:A01:2021", "ISO-27001:A.8.28"],
        regex: "(?:SELECT.*FROM.*WHERE\\s+id\\s*=\\s*(?:req\\.params|request\\.args)|find(?:ById)?\\s*\\(\\s*(?:req\\.params\\.id|request\\.args\\.get\\(['\"]id['\"]\\))\\s*\\)(?!.*user_id))",
        description: "Fetching resources by client-supplied ID without verifying ownership allows unauthorized tenant access.",
        remediation: "Scope queries to authenticated session identifiers: WHERE id = %s AND user_id = %s."
    },
    {
        id: "SONAR-S2068",
        name: "Hard-coded credentials are security-sensitive",
        type: "sast",
        severity: "HIGH",
        languages: ["python", "javascript", "typescript", "java", "c", "cpp", "go"],
        cwe: "CWE-798",
        standards: ["OWASP:A07:2021", "ISO-27001:A.8.12", "SonarQube:S2068"],
        regex: "(?:password|passwd|pwd|secret)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
        description: "Hard-coding sensitive credentials directly in source code allows anyone with repo access to impersonate identities.",
        remediation: "Extract secrets into environment variables or cloud secret managers."
    },
    {
        id: "DEP-SPRING4SHELL",
        name: "Spring4Shell - Remote Code Execution via Insecure Data Binding",
        type: "sca",
        severity: "CRITICAL",
        languages: ["xml", "json", "yaml"],
        cwe: "CWE-94",
        standards: ["CVE-2022-22965", "CISA-KEV", "OWASP:A06:2021"],
        regex: "(?:spring-boot-starter-parent|spring-boot)[\"'>\\s]*[:<]?(?:2\\.[567]\\.[0-8]|5\\.[34]\\.[0-9])",
        description: "Spring Framework vulnerable to class loader data binding RCE (CVE-2022-22965 / Spring4Shell).",
        remediation: "Upgrade Spring Boot to >= 2.6.9, 2.7.1, or 3.0+ immediately."
    },

    // Built-in IaC
    {
        id: "IAC-DOCKER-001",
        name: "Container Process Running as Root User",
        type: "iac",
        severity: "HIGH",
        languages: ["dockerfile"],
        cwe: "CWE-250",
        standards: ["CIS:Docker:4.1", "NIST-800-53:AC-6"],
        regex: "^USER\\s+root\\b",
        description: "Dockerfile runs container process as root without a non-privileged user switch.",
        remediation: "Declare an unprivileged user before entrypoint: USER appuser"
    },
    {
        id: "IAC-DOCKER-002",
        name: "Insecure Pipe to Shell (curl/wget | sh)",
        type: "iac",
        severity: "HIGH",
        languages: ["dockerfile", "yaml"],
        cwe: "CWE-78",
        standards: ["OWASP:A03:2021", "ISO-27001:A.8.25"],
        regex: "(?:curl|wget)\\s+[^\\n\\|]+\\|\\s*(?:ba)?sh",
        description: "Piping untrusted remote scripts directly into bash executes unverified code without checksum verification.",
        remediation: "Download script first, verify SHA-256 checksum, then execute."
    },
    {
        id: "IAC-DOCKER-003",
        name: "Unpinned or Mutable Base Image Tag (:latest)",
        type: "iac",
        severity: "MEDIUM",
        languages: ["dockerfile"],
        cwe: "CWE-1104",
        standards: ["CIS:Docker:4.3", "NIST-SSDF:PW.8"],
        regex: "^FROM\\s+[a-zA-Z0-9_\\-\\.\\/]+:(?:latest)\\b|^FROM\\s+[a-zA-Z0-9_\\-\\.\\/]+(?:\\s+AS\\s+\\w+)?$",
        description: "Base image uses mutable ':latest' tag or omits tag, breaking build reproducibility.",
        remediation: "Pin base image to explicit immutable SHA digest or specific semantic tag: FROM alpine:3.19.1@sha256:..."
    }
];

/**
 * Activates the Sentinel IDE extension
 */
function activate(context) {
    console.log('🛡️ Sentinel AppSec IDE Extension activated.');

    // 1. Initialize Diagnostic Collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('sentinel');
    context.subscriptions.push(diagnosticCollection);

    // 2. Initialize Status Bar
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'sentinel.scanWorkspace';
    context.subscriptions.push(statusBarItem);
    updateStatusBar();

    // 3. Register Custom Rules Explorer Tree View
    rulesTreeProvider = new SentinelRulesTreeProvider();
    vscode.window.registerTreeDataProvider('sentinel.rulesExplorer', rulesTreeProvider);

    // 4. Load Project Custom Rules from workspace and scan open editors
    loadAllRules().then(() => {
        if (vscode.window.visibleTextEditors) {
            for (const editor of vscode.window.visibleTextEditors) {
                if (editor.document && editor.document.uri && editor.document.uri.scheme === 'file') {
                    scanDocument(editor.document);
                }
            }
        }
    });

    // 4b. Optional background sync with server (disabled by default so local Problems reflect only actual code)
    const initialConfig = vscode.workspace.getConfiguration('sentinel');
    if (initialConfig.get('autoSyncServerFindings') === true) {
        const serverSyncInterval = setInterval(() => {
            syncWorkspaceFindingsFromServer().catch(() => {});
        }, 30000);
        context.subscriptions.push({ dispose: () => clearInterval(serverSyncInterval) });
    }

    // 5. Register Extension Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.scanCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                const config = vscode.workspace.getConfiguration('sentinel');
                if (config.get('clearStoredResultsOnScan') !== false) {
                    const docPathNorm = path.normalize(editor.document.fileName);
                    serverFindingsByFile.delete(docPathNorm);
                    if (diagnosticCollection) {
                        diagnosticCollection.delete(editor.document.uri);
                    }
                }
                scanDocument(editor.document);
                vscode.window.showInformationMessage(`🛡️ Sentinel: Scanned ${path.basename(editor.document.fileName)}`);
            }
        }),

        vscode.commands.registerCommand('sentinel.scanWorkspace', () => {
            scanWorkspace();
        }),

        vscode.commands.registerCommand('sentinel.clearStoredResults', () => {
            clearStoredResults();
            vscode.window.showInformationMessage('🛡️ Sentinel: Cleared all stored findings and diagnostics.');
        }),

        vscode.commands.registerCommand('sentinel.refreshRules', async () => {
            await loadAllRules();
            await syncWorkspaceFindingsFromServer();
            vscode.window.showInformationMessage('🛡️ Sentinel: Refreshed security rules and synchronized IDE Problems findings.');
        }),

        vscode.commands.registerCommand('sentinel.syncWorkspaceFindings', async () => {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: '🛡️ Sentinel AppSec: Syncing server findings into IDE Problems...',
                cancellable: false
            }, async () => {
                const count = await syncWorkspaceFindingsFromServer();
                vscode.window.showInformationMessage(`🛡️ Sentinel: Loaded ${count} project vulnerability findings into IDE Problems tab.`);
            });
        }),

        vscode.commands.registerCommand('sentinel.inspectRule', (rule) => {
            if (rule) {
                showRuleInspectorWebview(context, rule);
            }
        }),

        vscode.commands.registerCommand('sentinel.openDashboard', () => {
            const config = vscode.workspace.getConfiguration('sentinel');
            const serverUrl = config.get('serverUrl') || 'http://127.0.0.1:8000';
            vscode.env.openExternal(vscode.Uri.parse(serverUrl));
        }),

        vscode.commands.registerCommand('sentinel.configureCloud', async () => {
            const config = vscode.workspace.getConfiguration('sentinel');
            const currentUrl = config.get('serverUrl') || 'http://127.0.0.1:8000';
            const inputUrl = await vscode.window.showInputBox({
                prompt: 'Enter Sentinel Cloud Server URL (e.g. https://sentinel.company.internal or http://<ip>:8000)',
                value: currentUrl,
                placeHolder: 'https://sentinel.mycloud.com',
                ignoreFocusOut: true
            });
            if (!inputUrl) return;

            const authChoice = await vscode.window.showQuickPick([
                { label: '$(key) Login with Username & Password', description: 'Authenticate to cloud server and retrieve API token automatically', id: 'login' },
                { label: '$(passkey) Enter API Bearer Token / PAT', description: 'Paste an existing JWT or Personal Access Token', id: 'token' },
                { label: '$(globe) Connect without Token (Public / Dev Mode)', description: 'Connect using unauthenticated dev access', id: 'none' }
            ], {
                placeHolder: 'Select Authentication Method for Cloud Server'
            });
            if (!authChoice) return;

            let finalToken = '';

            if (authChoice.id === 'login') {
                const username = await vscode.window.showInputBox({
                    prompt: 'Enter Sentinel Cloud Username',
                    value: 'admin',
                    ignoreFocusOut: true
                });
                if (!username) return;

                const password = await vscode.window.showInputBox({
                    prompt: 'Enter Sentinel Cloud Password',
                    password: true,
                    ignoreFocusOut: true
                });
                if (password === undefined) return;

                try {
                    vscode.window.setStatusBarMessage('Connecting to Sentinel Cloud...', 3000);
                    finalToken = await loginToCloudServer(inputUrl.trim(), username.trim(), password);
                    vscode.window.showInformationMessage(`🛡️ Successfully authenticated as "${username}"!`);
                } catch (err) {
                    vscode.window.showErrorMessage(`❌ Login to ${inputUrl.trim()} failed: ${err.message}`);
                    return;
                }
            } else if (authChoice.id === 'token') {
                const tokenInput = await vscode.window.showInputBox({
                    prompt: 'Paste API Bearer Token or Personal Access Token (PAT)',
                    password: true,
                    ignoreFocusOut: true
                });
                if (tokenInput === undefined) return;
                finalToken = tokenInput.trim();
            }

            await config.update('serverUrl', inputUrl.trim(), vscode.ConfigurationTarget.Global);
            await config.update('apiToken', finalToken, vscode.ConfigurationTarget.Global);

            vscode.window.showInformationMessage(`🛡️ Sentinel: Connected to cloud server (${inputUrl.trim()}). Synchronizing security rules...`);
            await loadAllRules();
        }),

        vscode.commands.registerCommand('sentinel.autoDetectServer', async () => {
            let discovered = null;
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (workspaceFolders && workspaceFolders.length > 0) {
                const rootPath = workspaceFolders[0].uri.fsPath;
                const candidates = [
                    path.join(rootPath, '.sentinel', 'config.json'),
                    path.join(rootPath, '.sentinel', 'connection.json'),
                    path.join(rootPath, '.vscode', 'settings.json')
                ];
                for (const c of candidates) {
                    if (fs.existsSync(c)) {
                        try {
                            const raw = fs.readFileSync(c, 'utf-8');
                            const data = JSON.parse(raw);
                            const url = data.lanUrl || data.serverUrl || data['sentinel.serverUrl'];
                            if (url && !url.includes('103.79.222.59')) {
                                discovered = url;
                                break;
                            }
                        } catch (_) {}
                    }
                }
            }
            if (!discovered || discovered.includes('103.79.222.59')) {
                discovered = 'http://192.168.0.101:8000';
            }
            const config = vscode.workspace.getConfiguration('sentinel');
            await config.update('serverUrl', discovered, vscode.ConfigurationTarget.Global);
            vscode.window.showInformationMessage(`🛡️ Sentinel AppSec: Auto-configured to server at ${discovered}`);
            await loadAllRules();
        }),

        vscode.commands.registerCommand('sentinel.applyQuickFix', (documentUri, range, ruleId) => {
            applySuppressionComment(documentUri, range, ruleId);
        }),

        vscode.commands.registerCommand('sentinel.openRulesYaml', async () => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders || workspaceFolders.length === 0) {
                vscode.window.showWarningMessage('🛡️ Sentinel: No active workspace folder open.');
                return;
            }
            const rootPath = workspaceFolders[0].uri.fsPath;
            const config = vscode.workspace.getConfiguration('sentinel');
            const rulesRelPath = config.get('rulesFile') || '.sentinel/rules.yaml';
            const rulesPath = path.join(rootPath, rulesRelPath);

            if (!fs.existsSync(rulesPath)) {
                const choice = await vscode.window.showInformationMessage(
                    `Sentinel rules file not found at ${rulesRelPath}. Would you like to create it?`,
                    'Create rules.yaml', 'Cancel'
                );
                if (choice === 'Create rules.yaml') {
                    const dir = path.dirname(rulesPath);
                    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
                    const starter = `# Sentinel Enterprise Project-Specific Custom Security Rules\nversion: "1.0"\nproject: "custom"\n\nrules:\n  # Add your custom rules here\n`;
                    fs.writeFileSync(rulesPath, starter, 'utf-8');
                } else {
                    return;
                }
            }

            try {
                const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(rulesPath));
                await vscode.window.showTextDocument(doc);
            } catch (err) {
                vscode.window.showErrorMessage(`Failed to open rules file: ${err.message}`);
            }
        })
    );

    // 6. Register Hover Provider
    context.subscriptions.push(
        vscode.languages.registerHoverProvider({ scheme: 'file' }, {
            provideHover(document, position) {
                const diagnostics = diagnosticCollection.get(document.uri);
                if (!diagnostics || diagnostics.length === 0) return null;

                const match = diagnostics.find(d => d.range.contains(position));
                if (!match) return null;

                const ruleId = typeof match.code === 'object' ? match.code.value : match.code;
                const rule = activeRules.find(r => r.id === ruleId) || { id: ruleId, name: match.message };

                const md = new vscode.MarkdownString();
                md.isTrusted = true;
                md.appendMarkdown(`### 🛡️ Sentinel AppSec: ${escapeMarkdown(rule.name || match.message)}\n\n`);
                md.appendMarkdown(`- **Rule ID:** \`${rule.id}\`\n`);
                md.appendMarkdown(`- **Severity:** \`${rule.severity || 'HIGH'}\`\n`);
                md.appendMarkdown(`- **Origin:** ${rule.is_project_custom ? '⚙️ **Project Custom Rule** (`.sentinel/rules.yaml`)' : '🛡️ Built-in Scanner Rule'}\n`);
                if (rule.cwe) md.appendMarkdown(`- **CWE:** \`${rule.cwe}\`\n`);
                if (rule.standards && rule.standards.length > 0) {
                    md.appendMarkdown(`- **Compliance:** \`${rule.standards.join(', ')}\`\n`);
                }
                md.appendMarkdown(`\n**Remediation:**\n> ${rule.remediation || 'Review and refactor code according to secure coding guidelines.'}\n\n`);
                md.appendMarkdown(`[⚡ Suppress Rule](command:sentinel.applyQuickFix?${encodeURIComponent(JSON.stringify([document.uri.toString(), match.range, rule.id]))}) | [🌐 Open Dashboard](command:sentinel.openDashboard)`);

                return new vscode.Hover(md, match.range);
            }
        })
    );

    // 7. Register CodeAction / QuickFix Provider
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, {
            provideCodeActions(document, range, context) {
                const actions = [];
                for (const diag of context.diagnostics) {
                    if (diag.source && diag.source.includes('Sentinel')) {
                        const ruleId = typeof diag.code === 'object' ? diag.code.value : diag.code;
                        const action = new vscode.CodeAction(`Sentinel: Suppress ${ruleId} for this line`, vscode.CodeActionKind.QuickFix);
                        action.command = {
                            command: 'sentinel.applyQuickFix',
                            title: 'Suppress Rule',
                            arguments: [document.uri.toString(), diag.range, ruleId]
                        };
                        action.diagnostics = [diag];
                        action.isPreferred = true;
                        actions.push(action);
                    }
                }
                return actions;
            }
        })
    );

    // 8. Auto-scan on Document Open, Save, and Active Tab Switch
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document && editor.document.uri.scheme === 'file') {
                scanDocument(editor.document);
            }
        }),

        vscode.workspace.onDidOpenTextDocument(doc => {
            if (doc.uri.scheme === 'file') scanDocument(doc);
        }),

        vscode.workspace.onDidSaveTextDocument(async doc => {
            const config = vscode.workspace.getConfiguration('sentinel');
            if (config.get('scanOnSave') && doc.uri.scheme === 'file') {
                scanDocument(doc);
            }
        }),

        vscode.workspace.onDidCloseTextDocument(doc => {
            diagnosticCollection.delete(doc.uri);
        })
    );

    // 8b. Real-time file system watcher on source code modifications across workspace
    const sourceWatcher = vscode.workspace.createFileSystemWatcher('**/*.{py,js,jsx,ts,tsx,java,go,c,cpp,h,hpp,php,rb,sh,tf,yaml,yml}');
    sourceWatcher.onDidChange(async uri => {
        try {
            const doc = await vscode.workspace.openTextDocument(uri);
            scanDocument(doc);
        } catch (_) {}
    });
    sourceWatcher.onDidDelete(uri => {
        if (diagnosticCollection) {
            diagnosticCollection.delete(uri);
        }
    });
    context.subscriptions.push(sourceWatcher);

    // 9. Real-time File System Watcher on project rules (.sentinel/rules.yaml)
    const rulesWatcher = vscode.workspace.createFileSystemWatcher('**/.sentinel/rules.*');
    rulesWatcher.onDidChange(() => {
        console.log('[Sentinel IDE] Detected modification to .sentinel/rules.*, reloading rules and updating diagnostics...');
        loadAllRules();
    });
    rulesWatcher.onDidCreate(() => {
        console.log('[Sentinel IDE] Detected creation of .sentinel/rules.*, reloading...');
        loadAllRules();
    });
    rulesWatcher.onDidDelete(() => {
        console.log('[Sentinel IDE] Detected deletion of .sentinel/rules.*, resetting and purging stale diagnostics...');
        loadAllRules();
    });
    context.subscriptions.push(rulesWatcher);

    // 10. Live buffer scanning on edit (debounced 400ms)
    let liveScanTimer = null;
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(e => {
            if (e.document.uri.scheme === 'file') {
                if (liveScanTimer) clearTimeout(liveScanTimer);
                liveScanTimer = setTimeout(() => {
                    scanDocument(e.document);
                }, 400);
            }
        })
    );

    // 11. Auto-sync rules whenever editor window gains focus (e.g. switching back from browser)
    context.subscriptions.push(
        vscode.window.onDidChangeWindowState(state => {
            if (state.focused) {
                loadAllRules();
            }
        })
    );

    // 12. Periodic background rule synchronization every 30 seconds
    const syncInterval = setInterval(() => {
        loadAllRules();
    }, 30000);
    context.subscriptions.push({
        dispose: () => clearInterval(syncInterval)
    });

    // 13. Register URI Handler for 1-click browser auto-configuration
    // e.g. vscode://sentinel-security.sentinel-appsec-ide/connect?serverUrl=http://<IP>:8000
    context.subscriptions.push(
        vscode.window.registerUriHandler({
            async handleUri(uri) {
                try {
                    const query = new URLSearchParams(uri.query);
                    const newServerUrl = query.get('serverUrl');
                    const newToken = query.get('token');
                    if (newServerUrl) {
                        const config = vscode.workspace.getConfiguration('sentinel');
                        await config.update('serverUrl', newServerUrl, vscode.ConfigurationTarget.Global);
                        if (newToken) {
                            await config.update('apiToken', newToken, vscode.ConfigurationTarget.Global);
                        }
                        vscode.window.showInformationMessage(`🛡️ Sentinel AppSec: Automatically configured server URL to ${newServerUrl}`);
                        await loadAllRules();
                    }
                } catch (err) {
                    vscode.window.showErrorMessage(`Failed to auto-configure Sentinel: ${err.message}`);
                }
            }
        })
    );

    // Initial scan of active editor
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}

/**
 * Builds fully qualified API endpoint URL preserving any base subpaths (e.g. reverse proxy /sentinel/)
 * and automatically normalizes scheme (http/https)
 */
function buildApiUrl(baseUrl, endpointPath) {
    if (!baseUrl) return '';
    let base = baseUrl.trim();
    if (!/^https?:\/\//i.test(base)) {
        base = 'http://' + base;
    }
    const cleanBase = base.replace(/\/+$/, '');
    const cleanEndpoint = (endpointPath || '').replace(/^\/+/, '');
    return cleanEndpoint ? `${cleanBase}/${cleanEndpoint}` : cleanBase;
}

/**
 * Helper to perform HTTP or HTTPS requests for cloud sync & authentication.
 * Hardened for Docker, remote cloud environments, and self-signed TLS proxies.
 */
function makeApiRequest(urlStr, options = {}, postData = null) {
    return new Promise((resolve, reject) => {
        try {
            let targetUrl = urlStr;
            if (!/^https?:\/\//i.test(targetUrl)) {
                targetUrl = 'http://' + targetUrl;
            }
            const urlObj = new URL(targetUrl);
            const isHttps = urlObj.protocol === 'https:';
            const client = isHttps ? https : http;

            let allowInsecureTLS = false;
            try {
                const config = vscode.workspace.getConfiguration('sentinel');
                allowInsecureTLS = config.get('allowInsecureTLS', false);
            } catch (_) {}

            const reqOptions = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: options.method || 'GET',
                headers: {
                    'Accept': 'application/json',
                    'User-Agent': 'Sentinel-IDE-Plugin/1.0.0',
                    ...(options.headers || {})
                },
                timeout: options.timeout || 4000
            };

            // Support self-signed certificates for Docker or private cloud clusters
            if (isHttps && allowInsecureTLS) {
                reqOptions.rejectUnauthorized = false;
            }

            if (postData) {
                reqOptions.headers['Content-Type'] = 'application/json';
                reqOptions.headers['Content-Length'] = Buffer.byteLength(postData);
            }

            const req = client.request(reqOptions, (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => {
                    resolve({ statusCode: res.statusCode, headers: res.headers, body });
                });
            });

            req.on('error', (err) => {
                let friendlyMsg = err.message;
                if (err.code === 'ECONNREFUSED') {
                    friendlyMsg = `Connection refused at ${urlObj.hostname}:${reqOptions.port}. Ensure Sentinel Docker container is running and port ${reqOptions.port} is published (-p ${reqOptions.port}:${reqOptions.port}).`;
                } else if (err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
                    friendlyMsg = `Connection timed out connecting to ${urlObj.hostname}:${reqOptions.port}. Check firewall or cloud security group rules.`;
                } else if (err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
                    friendlyMsg = `Self-signed TLS certificate detected for ${urlObj.hostname}. Enable "sentinel.allowInsecureTLS" in VS Code settings to connect anyway.`;
                }
                const error = new Error(friendlyMsg);
                error.code = err.code;
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error(`Connection to ${urlObj.hostname}:${reqOptions.port} timed out after 10 seconds. Check network and cloud firewall.`));
            });

            if (postData) {
                req.write(postData);
            }
            req.end();
        } catch (e) {
            reject(e);
        }
    });
}

/**
 * Authenticates against remote Sentinel cloud server to retrieve JWT Bearer token
 */
async function loginToCloudServer(serverUrl, username, password) {
    const postBody = JSON.stringify({ username, password });
    const candidateUrls = [serverUrl];
    if (!candidateUrls.includes('http://192.168.0.101:8000')) candidateUrls.push('http://192.168.0.101:8000');
    if (!candidateUrls.includes('http://127.0.0.1:8000')) candidateUrls.push('http://127.0.0.1:8000');

    let lastErr = null;
    for (const curUrl of candidateUrls) {
        try {
            const url = buildApiUrl(curUrl, '/api/auth/login');
            const res = await makeApiRequest(url, { method: 'POST', timeout: 3500 }, postBody);
            if (res.statusCode >= 200 && res.statusCode < 300) {
                const json = JSON.parse(res.body);
                return json.access_token;
            } else {
                let msg = `HTTP ${res.statusCode}`;
                try {
                    const err = JSON.parse(res.body);
                    if (err.detail) msg = err.detail;
                } catch (_) {}
                lastErr = new Error(msg);
            }
        } catch (e) {
            lastErr = e;
        }
    }
    throw lastErr || new Error('Connection failed to all server endpoints');
}

/**
 * Fetches latest security rules and platform custom rules from remote Sentinel server
 */
async function fetchCloudRules(serverUrl, apiToken) {
    if (!serverUrl) return [];

    const candidateUrls = [serverUrl];
    if (!candidateUrls.includes('http://192.168.0.101:8000')) candidateUrls.push('http://192.168.0.101:8000');
    if (!candidateUrls.includes('http://127.0.0.1:8000')) candidateUrls.push('http://127.0.0.1:8000');

    for (const targetUrl of candidateUrls) {
        try {
            const headers = {};
            if (apiToken) {
                headers['Authorization'] = `Bearer ${apiToken.trim()}`;
            }
            const url = buildApiUrl(targetUrl, '/api/rules/catalog');
            const res = await makeApiRequest(url, { method: 'GET', headers, timeout: 3500 });
            if (res.statusCode >= 200 && res.statusCode < 300) {
                const catalog = JSON.parse(res.body);
                const cloudRules = [];
                if (catalog && catalog.rules) {
                    for (const cat of Object.keys(catalog.rules)) {
                        const rulesArr = catalog.rules[cat];
                        if (Array.isArray(rulesArr)) {
                            for (const r of rulesArr) {
                                if (cat === 'platform_custom') {
                                    r.is_platform_custom = true;
                                }
                                cloudRules.push(r);
                            }
                        }
                    }
                }
                if (targetUrl !== serverUrl) {
                    console.log(`[Sentinel IDE] Connected via fallback server URL: ${targetUrl}`);
                }
                return cloudRules;
            }
        } catch (err) {
            // Try next candidate URL
        }
    }
    console.warn('[Sentinel IDE] All candidate cloud server endpoints unreachable');
    return [];
}

/**
 * Compiles regex safely, stripping Python-specific inline flags like (?i), (?m)
 */
function compileRegex(rawRegex) {
    if (!rawRegex) return null;
    let clean = rawRegex.trim();
    // Strip Python inline flags (?i), (?m), (?s) at the start
    clean = clean.replace(/^\(\?[imsx]+\)/, '');
    try {
        return new RegExp(clean, 'i');
    } catch (e) {
        return null;
    }
}

/**
 * Loads project custom rules from .sentinel/rules.yaml, syncs with remote cloud server if configured,
 * and merges with built-in rules
 */
async function loadAllRules() {
    activeRules = [...DEFAULT_RULES];
    projectCustomRules = [];

    const config = vscode.workspace.getConfiguration('sentinel');
    let serverUrl = config.get('serverUrl');
    const apiToken = config.get('apiToken');

    // Automatic server IP discovery:
    // If serverUrl is default (http://127.0.0.1:8000) or unset, check if workspace has auto-detected server config (.sentinel/config.json)
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if ((!serverUrl || serverUrl === 'http://127.0.0.1:8000' || serverUrl.includes('103.79.222.59')) && workspaceFolders && workspaceFolders.length > 0) {
        const rootPath = workspaceFolders[0].uri.fsPath;
        const autoConfigPaths = [
            path.join(rootPath, '.sentinel', 'config.json'),
            path.join(rootPath, '.sentinel', 'connection.json'),
            path.join(rootPath, '.vscode', 'settings.json')
        ];
        for (const p of autoConfigPaths) {
            if (fs.existsSync(p)) {
                try {
                    const raw = fs.readFileSync(p, 'utf-8');
                    const parsed = JSON.parse(raw);
                    const discovered = parsed.lanUrl || parsed.serverUrl || parsed['sentinel.serverUrl'];
                    if (discovered && !discovered.includes('103.79.222.59')) {
                        serverUrl = discovered;
                        console.log(`[Sentinel IDE] Automatically discovered server IP from workspace configuration: ${serverUrl}`);
                        break;
                    }
                } catch (_) {}
            }
        }
        if (!serverUrl || serverUrl.includes('103.79.222.59')) {
            serverUrl = 'http://192.168.0.101:8000';
        }
    }

    // 1. Fetch remote rules from cloud server if configured
    if (serverUrl) {
        try {
            const cloudRules = await fetchCloudRules(serverUrl, apiToken);
            if (cloudRules && cloudRules.length > 0) {
                for (const cr of cloudRules) {
                    const existingIdx = activeRules.findIndex(x => x.id === cr.id);
                    if (existingIdx >= 0) {
                        activeRules[existingIdx] = cr;
                    } else {
                        activeRules.push(cr);
                    }
                }
                console.log(`[Sentinel IDE] Synchronized ${cloudRules.length} rules from cloud server: ${serverUrl}`);
            }
        } catch (err) {
            console.warn('[Sentinel IDE] Failed fetching cloud rules:', err.message);
        }
    }

    // 2. Load local project custom rules from workspace (.sentinel/rules.yaml)
    if (workspaceFolders && workspaceFolders.length > 0) {
        const rootPath = workspaceFolders[0].uri.fsPath;
        const customRulesFile = config.get('rulesFile') || '.sentinel/rules.yaml';

        const possiblePaths = [
            path.join(rootPath, customRulesFile),
            path.join(rootPath, '.sentinel', 'rules.yaml'),
            path.join(rootPath, '.sentinel', 'rules.json'),
            path.join(rootPath, '.aegissec', 'rules.yaml')
        ];

        for (const filePath of possiblePaths) {
            if (fs.existsSync(filePath)) {
                try {
                    const content = fs.readFileSync(filePath, 'utf-8');
                    let parsedRules = [];
                    if (filePath.endsWith('.json')) {
                        const json = JSON.parse(content);
                        parsedRules = json.rules || [];
                    } else {
                        parsedRules = parseSimpleYamlRules(content);
                    }

                    if (parsedRules.length > 0) {
                        for (const r of parsedRules) {
                            r.is_project_custom = true;
                            r.source_file = path.relative(rootPath, filePath);
                            projectCustomRules.push(r);

                            const existingIdx = activeRules.findIndex(x => x.id === r.id);
                            if (existingIdx >= 0) {
                                activeRules[existingIdx] = r;
                            } else {
                                activeRules.unshift(r);
                            }
                        }
                    }
                    console.log(`[Sentinel IDE] Loaded ${parsedRules.length} custom rules from ${filePath}`);
                    break;
                } catch (err) {
                    console.error(`[Sentinel IDE] Failed parsing custom rules at ${filePath}:`, err);
                }
            }
        }
    }

    // Optionally synchronize server findings if configured
    if (config.get('autoSyncServerFindings') === true) {
        try {
            await syncWorkspaceFindingsFromServer();
        } catch (err) {
            console.warn('[Sentinel IDE] Error syncing server findings in loadAllRules:', err.message);
        }
    }

    // Re-evaluate all currently open/visible documents with updated rules
    try {
        if (vscode.window.visibleTextEditors) {
            for (const editor of vscode.window.visibleTextEditors) {
                if (editor.document && editor.document.uri && editor.document.uri.scheme === 'file') {
                    scanDocument(editor.document);
                }
            }
        }
    } catch (_) {}

    if (rulesTreeProvider) {
        rulesTreeProvider.refresh();
    }
    updateStatusBar();
}

/**
 * Resolves candidate backend URLs for auto-discovery (host loopback, docker network, LAN, config)
 */
function getServerCandidateUrls() {
    const urls = [];
    const config = vscode.workspace.getConfiguration('sentinel');
    const confUrl = config.get('serverUrl');
    if (confUrl) urls.push(confUrl);

    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (workspaceFolders && workspaceFolders.length > 0) {
        const rootPath = workspaceFolders[0].uri.fsPath;
        const autoConfigPaths = [
            path.join(rootPath, '.sentinel', 'config.json'),
            path.join(rootPath, '.sentinel', 'connection.json'),
            path.join(rootPath, '.vscode', 'settings.json')
        ];
        for (const p of autoConfigPaths) {
            if (fs.existsSync(p)) {
                try {
                    const raw = fs.readFileSync(p, 'utf-8');
                    const parsed = JSON.parse(raw);
                    const discovered = parsed.lanUrl || parsed.serverUrl || parsed['sentinel.serverUrl'];
                    if (discovered) urls.push(discovered);
                } catch (_) {}
            }
        }
    }

    urls.push('http://127.0.0.1:8000');
    urls.push('http://localhost:8000');
    urls.push('http://172.19.0.2:8000');
    urls.push('http://192.168.0.101:8000');

    // Deduplicate and filter out dead public WAN IPs
    const deduped = [];
    for (const u of urls) {
        if (!u) continue;
        const trimmed = u.trim().replace(/\/+$/, '');
        if (!deduped.includes(trimmed) && !trimmed.includes('103.79.222.59')) {
            deduped.push(trimmed);
        }
    }
    return deduped;
}

/**
 * Synchronizes scan findings directly from Sentinel backend server into VS Code / IDE Problems panel
 */
async function syncWorkspaceFindingsFromServer() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders || workspaceFolders.length === 0) {
        return 0;
    }
    const rootPath = workspaceFolders[0].uri.fsPath;
    const config = vscode.workspace.getConfiguration('sentinel');
    const apiToken = config.get('apiToken');
    const headers = {};
    if (apiToken) {
        headers['Authorization'] = `Bearer ${apiToken.trim()}`;
    }

    const candidateUrls = getServerCandidateUrls();
    let findings = [];
    let connectedServerUrl = null;

    for (const targetUrl of candidateUrls) {
        try {
            // First check if there is an active matching project
            let targetProjectId = null;
            try {
                const projUrl = buildApiUrl(targetUrl, '/api/projects');
                const projRes = await makeApiRequest(projUrl, { method: 'GET', headers, timeout: 2500 });
                if (projRes.statusCode >= 200 && projRes.statusCode < 300) {
                    const projects = JSON.parse(projRes.body);
                    if (Array.isArray(projects) && projects.length > 0) {
                        const folderName = path.basename(rootPath).toLowerCase();
                        let matched = projects.find(p => {
                            const gitUrl = (p.git_url || '').toLowerCase();
                            const pName = (p.name || '').toLowerCase();
                            return gitUrl.includes('sentinal-scanner') || gitUrl.includes('appsec') ||
                                   gitUrl.includes(folderName) || pName.includes(folderName);
                        });
                        if (!matched && projects.length > 0) {
                            matched = [...projects].sort((a, b) => (b.total_findings || 0) - (a.total_findings || 0))[0];
                        }
                        if (matched) {
                            targetProjectId = matched.id;
                        }
                    }
                }
            } catch (_) {}

            // Try dedicated workspace findings endpoint first if present
            try {
                const wsUrl = buildApiUrl(targetUrl, '/api/ide/workspace-findings');
                const wsRes = await makeApiRequest(wsUrl, { method: 'GET', headers, timeout: 2500 });
                if (wsRes.statusCode >= 200 && wsRes.statusCode < 300) {
                    const wsData = JSON.parse(wsRes.body);
                    if (wsData && Array.isArray(wsData.findings) && wsData.findings.length > 0) {
                        findings = wsData.findings;
                        connectedServerUrl = targetUrl;
                        break;
                    }
                }
            } catch (_) {}

            // Fetch from /api/findings
            const queryParam = targetProjectId ? `?project_id=${targetProjectId}&status=open` : '?status=open';
            const findingsUrl = buildApiUrl(targetUrl, `/api/findings${queryParam}`);
            const res = await makeApiRequest(findingsUrl, { method: 'GET', headers, timeout: 3500 });
            if (res.statusCode >= 200 && res.statusCode < 300) {
                const data = JSON.parse(res.body);
                if (Array.isArray(data)) {
                    findings = data;
                    connectedServerUrl = targetUrl;
                    break;
                }
            }
        } catch (err) {
            // try next candidate
        }
    }

    const previousFiles = new Set(serverFindingsByFile.keys());
    if (!findings || findings.length === 0) {
        serverFindingsRaw = [];
        serverFindingsByFile.clear();
        for (const prevFile of previousFiles) {
            try {
                diagnosticCollection.delete(vscode.Uri.file(prevFile));
            } catch (_) {}
        }
        return 0;
    }

    serverFindingsRaw = findings;
    serverFindingsByFile.clear();

    let totalMapped = 0;
    const fileDiagnosticsMap = new Map();

    for (const f of findings) {
        if (!f.file_path) continue;
        if (f.status && f.status.toLowerCase() !== 'open' && f.status.toLowerCase() !== 'in_triage') {
            continue;
        }
        const cleanRelPath = f.file_path.replace(/^\/+/, '');
        const candidateAbs = path.isAbsolute(f.file_path) ? f.file_path : path.join(rootPath, cleanRelPath);
        if (!fs.existsSync(candidateAbs)) {
            continue;
        }

        const sevStr = (f.severity || 'HIGH').toUpperCase();
        let severity = vscode.DiagnosticSeverity.Warning;
        if (sevStr === 'CRITICAL' || sevStr === 'HIGH') {
            severity = vscode.DiagnosticSeverity.Error;
        } else if (sevStr === 'LOW' || sevStr === 'INFO') {
            severity = vscode.DiagnosticSeverity.Information;
        }

        const rawLine = f.line_start || f.line_number || 1;
        const lineIdx = Math.max(0, parseInt(rawLine, 10) - 1);
        const endLineIdx = Math.max(lineIdx, (parseInt(f.line_end || rawLine, 10) - 1));
        const colIdx = Math.max(0, parseInt(f.column_number || f.column_start || 0, 10));
        const range = new vscode.Range(lineIdx, colIdx, endLineIdx, 999);

        const typeLabel = (f.type || f.scanner_type || 'VULN').toUpperCase();
        const codeId = f.cve_id || f.cwe_id || f.rule_id || typeLabel;
        const fixHint = f.remediation ? ` - Fix: ${f.remediation}` : (f.description ? ` - ${f.description}` : '');
        const msg = `[${typeLabel}:${codeId}] ${f.title || 'Security flaw detected'}${fixHint}`;

        const diag = new vscode.Diagnostic(range, msg, severity);
        diag.source = `Sentinel Server (${typeLabel})`;
        diag.code = codeId;

        const normKey = path.normalize(candidateAbs);
        if (!fileDiagnosticsMap.has(normKey)) {
            fileDiagnosticsMap.set(normKey, []);
        }
        fileDiagnosticsMap.get(normKey).push(diag);
        totalMapped++;
    }

    // Purge diagnostics for files that no longer have server findings
    for (const prevFile of previousFiles) {
        if (!fileDiagnosticsMap.has(prevFile)) {
            try {
                diagnosticCollection.delete(vscode.Uri.file(prevFile));
            } catch (_) {}
        }
    }

    for (const [filePath, diags] of fileDiagnosticsMap.entries()) {
        serverFindingsByFile.set(filePath, diags);
        const fileUri = vscode.Uri.file(filePath);
        diagnosticCollection.set(fileUri, diags);
    }

    console.log(`[Sentinel IDE] Synchronized ${totalMapped} findings across ${fileDiagnosticsMap.size} files into IDE Problems tab from ${connectedServerUrl}.`);
    updateStatusBar();
    return totalMapped;
}

/**
 * Lightweight YAML parser specifically extracting rules list from .sentinel/rules.yaml
 */
function parseSimpleYamlRules(yamlText) {
    const rules = [];
    const lines = yamlText.split('\n');
    let currentRule = null;
    let inRulesSection = false;

    for (let line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        if (trimmed === 'rules:') {
            inRulesSection = true;
            continue;
        }

        if (inRulesSection) {
            if (trimmed.startsWith('- id:')) {
                if (currentRule) rules.push(currentRule);
                const idVal = trimmed.replace('- id:', '').trim().replace(/['"]/g, '');
                currentRule = { id: idVal, standards: [], languages: [] };
            } else if (currentRule) {
                const kvMatch = trimmed.match(/^([a-zA-Z0-9_]+):\s*(.*)$/);
                if (kvMatch) {
                    const key = kvMatch[1];
                    let val = kvMatch[2].trim().replace(/^['"]|['"]$/g, '');
                    if (key === 'languages' || key === 'standards') {
                        currentRule[key] = [];
                    } else if (key === 'cvss') {
                        currentRule[key] = parseFloat(val) || 7.0;
                    } else {
                        currentRule[key] = val;
                    }
                } else if (trimmed.startsWith('-') && currentRule) {
                    const item = trimmed.replace(/^[-\s]+/, '').replace(/['"]/g, '');
                    if (currentRule.standards && (!currentRule.languages || currentRule.languages.length === 0)) {
                        currentRule.standards.push(item);
                    } else if (currentRule.languages) {
                        currentRule.languages.push(item);
                    }
                }
            }
        }
    }
    if (currentRule) rules.push(currentRule);
    return rules;
}

/**
 * Calculates Shannon entropy (bits per character) of a string to distinguish high-randomness secrets from words
 */
function calculateShannonEntropy(data) {
    if (!data || data.length === 0) return 0.0;
    const freqs = {};
    for (let i = 0; i < data.length; i++) {
        const c = data[i];
        freqs[c] = (freqs[c] || 0) + 1;
    }
    let entropy = 0.0;
    const len = data.length;
    for (const char in freqs) {
        const p = freqs[char] / len;
        entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
}

const DUMMY_SUBSTRINGS = [
    "example", "placeholder", "your_api_key", "your_secret",
    "insert_here", "dummy", "test_key", "sample_key", "change_me",
    "replace_me", "mysecretkey", "xxxxxx", "000000", "123456"
];

function isDummySecret(val) {
    if (!val) return true;
    const lower = val.toLowerCase();
    for (const d of DUMMY_SUBSTRINGS) {
        if (lower.includes(d)) return true;
    }
    if (new Set(val).size <= 2 && val.length > 8) return true;
    return false;
}

/**
 * Scans an individual text document against active rules
 */
function scanDocument(document) {
    const fsPath = (document.fileName || (document.uri && document.uri.fsPath) || (document.uri && document.uri.path) || '').replace(/\\/g, '/');
    const uriStr = document.uri ? document.uri.toString() : '';

    // Strictly ignore virtual environments, third-party libraries, build output, rule definitions, and test code
    if (/(?:^|\/)(?:\.venv|venv|site-packages|dist-packages|node_modules|vendor|dist|build|\.pytest_cache|tests?|__tests__|fixtures?|mocks?|backend\/rules|\.sentinel|\.vscode)(?:\/|$)/i.test(fsPath) ||
        /(?:\.venv|venv|site-packages|node_modules|\.sentinel|backend\/rules)/i.test(uriStr) ||
        /(?:^|\/)(?:test_[^/]+\.py|[^/]+_test\.(?:py|js|ts|go)|sonar_rules_db\.py|nl_rule_generator\.py|rules\.ya?ml|rules\.json|open_rules_db\.json)$/i.test(fsPath)) {
        if (diagnosticCollection && document.uri) {
            diagnosticCollection.delete(document.uri);
            diagnosticCollection.set(document.uri, []);
        }
        return;
    }

    const text = document.getText();
    const fileName = document.fileName.toLowerCase();
    const diagnostics = [];

    // Language resolution
    let docLang = 'text';
    if (fileName.endsWith('.py')) docLang = 'python';
    else if (fileName.endsWith('.js') || fileName.endsWith('.jsx')) docLang = 'javascript';
    else if (fileName.endsWith('.ts') || fileName.endsWith('.tsx')) docLang = 'typescript';
    else if (fileName.endsWith('.java')) docLang = 'java';
    else if (fileName.endsWith('.go')) docLang = 'go';
    else if (fileName.endsWith('.c') || fileName.endsWith('.h')) docLang = 'c';
    else if (fileName.endsWith('.cpp') || fileName.endsWith('.hpp') || fileName.endsWith('.cc') || fileName.endsWith('.cxx')) docLang = 'cpp';
    else if (fileName.endsWith('.php')) docLang = 'php';
    else if (fileName.endsWith('.rb')) docLang = 'ruby';
    else if (fileName.endsWith('.sh') || fileName.endsWith('.bash')) docLang = 'shell';
    else if (fileName.endsWith('.tf')) docLang = 'terraform';
    else if (fileName.endsWith('.json')) docLang = 'json';
    else if (fileName.endsWith('.yaml') || fileName.endsWith('.yml')) docLang = 'yaml';
    else if (fileName.includes('dockerfile')) docLang = 'dockerfile';

    const lines = text.split(/\r?\n/);

    for (const rule of activeRules) {
        if (rule.languages && rule.languages.length > 0) {
            const applies = rule.languages.some(l => {
                const low = l.toLowerCase();
                return low === '*' || low === 'all' || low === docLang ||
                    (low === 'c' && (docLang === 'c' || docLang === 'cpp')) ||
                    (low === 'cpp' && docLang === 'cpp') ||
                    (low === 'javascript' && (docLang === 'javascript' || docLang === 'typescript')) ||
                    fileName.includes(low);
            });
            if (!applies) {
                continue;
            }
        }

        if (!rule.regex) continue;

        const regex = compileRegex(rule.regex);
        if (!regex) continue;

        try {
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.includes('sentinel-ignore') || line.includes('pragma: allowlist secret')) continue;

                const match = regex.exec(line);
                if (match) {
                    let secretEntropy = null;
                    if (rule.type === 'secret') {
                        const candidate = match[1] || match[0];
                        if (isDummySecret(candidate)) continue;
                        secretEntropy = calculateShannonEntropy(candidate);
                        const minEntropy = rule.min_entropy !== undefined ? rule.min_entropy : 3.0;
                        if (secretEntropy < minEntropy) continue;
                    }

                    const startCol = match.index;
                    const endCol = match.index + match[0].length;
                    const range = new vscode.Range(i, startCol, i, endCol > startCol ? endCol : line.length);

                    const severity = (rule.severity === 'CRITICAL' || rule.severity === 'HIGH')
                        ? vscode.DiagnosticSeverity.Error
                        : vscode.DiagnosticSeverity.Warning;

                    let originLabel = '';
                    if (rule.is_project_custom) {
                        originLabel = ' [Project Custom: .sentinel/rules.yaml]';
                    } else if (rule.is_platform_custom) {
                        originLabel = ' [Cloud Platform Custom]';
                    }

                    const entropyLabel = secretEntropy !== null ? ` [Entropy: ${secretEntropy} bits/char]` : '';

                    const diag = new vscode.Diagnostic(
                        range,
                        `[${rule.id}] ${rule.name}${originLabel}${entropyLabel}: ${rule.description}`,
                        severity
                    );
                    diag.code = rule.id;
                    diag.source = 'Sentinel AppSec';
                    diagnostics.push(diag);
                }
            }
        } catch (e) {
            // Ignore regex runtime errors
        }
    }

    // If clearStoredResultsOnScan is enabled, purge stored/cached findings for this file
    const config = vscode.workspace.getConfiguration('sentinel');
    const clearStored = config.get('clearStoredResultsOnScan') !== false;
    const mergeServer = config.get('mergeServerFindings') === true;

    const docPathNorm = path.normalize(document.fileName);
    if (clearStored) {
        serverFindingsByFile.delete(docPathNorm);
        const baseName = path.basename(docPathNorm);
        for (const keyPath of Array.from(serverFindingsByFile.keys())) {
            if (path.basename(keyPath) === baseName) {
                serverFindingsByFile.delete(keyPath);
            }
        }
    }

    const merged = [...diagnostics];

    // Only merge historical server findings if explicitly configured and clearStored is disabled
    if (mergeServer && !clearStored) {
        let serverDiagsForFile = serverFindingsByFile.get(docPathNorm);
        if (!serverDiagsForFile) {
            // Try fuzzy relative match (match filename and relative path suffix)
            const baseName = path.basename(docPathNorm);
            for (const [keyPath, diags] of serverFindingsByFile.entries()) {
                if (path.basename(keyPath) === baseName) {
                    if (docPathNorm.endsWith(keyPath) || keyPath.endsWith(docPathNorm) || 
                        docPathNorm.includes(path.normalize(keyPath).replace(/^.*?([/\\](?:frontend|backend|src|tests|scripts|config)[/\\])/, '$1'))) {
                        serverDiagsForFile = diags;
                        break;
                    }
                }
            }
        }

        if (serverDiagsForFile && serverDiagsForFile.length > 0) {
            for (const sd of serverDiagsForFile) {
                const targetLineIdx = sd.range.start.line;
                const lineText = lines[targetLineIdx] || '';

                // 1. Skip if suppressed via inline comment
                if (lineText.includes('sentinel-ignore') || lineText.includes('pragma: allowlist secret')) {
                    continue;
                }

                // 2. If matching rule is known and its regex no longer matches the line, the flaw was remediated
                const matchingRule = activeRules.find(r =>
                    r.id === sd.code ||
                    r.sonar_key === sd.code ||
                    r.cwe === sd.code ||
                    (sd.code && String(sd.code).includes(r.id))
                );
                if (matchingRule && matchingRule.regex) {
                    const rx = compileRegex(matchingRule.regex);
                    if (rx && !rx.test(lineText)) {
                        // Remediated in code
                        continue;
                    }
                }

                // 3. Avoid duplicates if local rule hit on the exact line with same code
                const duplicate = diagnostics.some(ld =>
                    ld.range.start.line === targetLineIdx &&
                    (ld.code === sd.code || (typeof ld.code === 'string' && typeof sd.code === 'string' && (ld.code.includes(sd.code) || sd.code.includes(ld.code))))
                );
                if (!duplicate) {
                    merged.push(sd);
                }
            }
        }
    }

    diagnosticCollection.set(document.uri, merged);
    updateStatusBar();
}

/**
 * Completely clears all stored diagnostics and cached server findings
 */
function clearStoredResults() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
    }
    serverFindingsByFile.clear();
    serverFindingsRaw = [];
    updateStatusBar();
}

/**
 * Scans all documents in the active workspace
 */
function scanWorkspace() {
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: '🛡️ Sentinel AppSec: Auditing Workspace...',
        cancellable: false
    }, async () => {
        const config = vscode.workspace.getConfiguration('sentinel');
        const clearStored = config.get('clearStoredResultsOnScan') !== false;
        if (clearStored) {
            clearStoredResults();
        }

        const files = await vscode.workspace.findFiles('**/*', '{**/node_modules/**,**/tests/**,**/test/**,**/__tests__/**,**/.venv/**,**/dist/**,**/build/**,**/.sentinel/**,**/backend/rules/**,**/.vscode/**}', 300);
        for (const file of files) {
            try {
                const doc = await vscode.workspace.openTextDocument(file);
                scanDocument(doc);
            } catch (e) {
                // Ignore binary files
            }
        }
        vscode.window.showInformationMessage(`🛡️ Sentinel: Finished scanning ${files.length} workspace files.`);
    });
}

/**
 * QuickFix: inserts inline comment suppressing finding
 */
function applySuppressionComment(documentUri, range, ruleId) {
    const edit = new vscode.WorkspaceEdit();
    const uri = vscode.Uri.parse(documentUri);
    const lineEnd = new vscode.Position(range.start.line, 9999);
    edit.insert(uri, lineEnd, `  # sentinel-ignore: ${ruleId}`);
    vscode.workspace.applyEdit(edit).then(() => {
        const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === documentUri);
        if (doc) scanDocument(doc);
    });
}

/**
 * Updates status bar with current flaw count & loaded rules
 */
function updateStatusBar() {
    if (!statusBarItem) return;
    let totalFlaws = 0;
    diagnosticCollection.forEach((uri, diags) => {
        totalFlaws += diags.length;
    });

    const projCount = projectCustomRules.length;
    const totalRules = activeRules.length;

    if (totalFlaws > 0) {
        statusBarItem.text = `$(alert) Sentinel: ${totalFlaws} Flaw${totalFlaws > 1 ? 's' : ''} (${projCount} Custom Rules)`;
        statusBarItem.color = '#ef4444';
        statusBarItem.tooltip = `${totalFlaws} security violations detected. Click to run full workspace audit.`;
    } else {
        statusBarItem.text = `$(shield) Sentinel: Clean (${totalRules} Rules Active)`;
        statusBarItem.color = '#38bdf8';
        statusBarItem.tooltip = `All clear! ${totalRules} rules loaded (${projCount} project custom). Click to audit.`;
    }
    statusBarItem.show();
}

/**
 * TreeDataProvider for the Security & Custom Rules Explorer View
 */
class SentinelRulesTreeProvider {
    constructor() {
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    }

    refresh() {
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element) {
        return element;
    }

    getChildren(element) {
        if (!element) {
            // Root Categories
            const categories = [];

            // 1. Project Custom Rules
            const projRules = activeRules.filter(r => r.is_project_custom);
            categories.push(new RuleCategoryItem(
                `⚙️ Project Custom Rules (.sentinel/rules.yaml)`,
                projRules,
                vscode.TreeItemCollapsibleState.Expanded,
                'project_custom'
            ));

            // 2. Cloud Platform Custom Rules (if any)
            const platformRules = activeRules.filter(r => r.is_platform_custom || (r.is_custom && !r.is_project_custom));
            if (platformRules.length > 0) {
                categories.push(new RuleCategoryItem(
                    `☁️ Cloud Platform Custom Rules`,
                    platformRules,
                    vscode.TreeItemCollapsibleState.Expanded,
                    'platform_custom'
                ));
            }

            // 3. Built-in SAST
            const sastRules = activeRules.filter(r => !r.is_project_custom && !r.is_platform_custom && r.type === 'sast');
            categories.push(new RuleCategoryItem(
                `🛡️ Built-in SAST Rules`,
                sastRules,
                vscode.TreeItemCollapsibleState.Collapsed,
                'sast'
            ));

            // 4. Built-in IaC & Containers
            const iacRules = activeRules.filter(r => !r.is_project_custom && !r.is_platform_custom && r.type === 'iac');
            categories.push(new RuleCategoryItem(
                `🏗️ IaC & Container Hardening`,
                iacRules,
                vscode.TreeItemCollapsibleState.Collapsed,
                'iac'
            ));

            // 5. Built-in Secrets
            const secretRules = activeRules.filter(r => !r.is_project_custom && !r.is_platform_custom && r.type === 'secret');
            categories.push(new RuleCategoryItem(
                `🔑 Secret & Key Detection`,
                secretRules,
                vscode.TreeItemCollapsibleState.Collapsed,
                'secret'
            ));

            return Promise.resolve(categories);
        } else if (element instanceof RuleCategoryItem) {
            const items = [];
            if (element.categoryType === 'project_custom') {
                const openItem = new vscode.TreeItem('📄 Open .sentinel/rules.yaml', vscode.TreeItemCollapsibleState.None);
                openItem.description = 'Edit / View';
                openItem.tooltip = 'Click to open and edit workspace .sentinel/rules.yaml';
                openItem.iconPath = new vscode.ThemeIcon('file-code', new vscode.ThemeColor('charts.blue'));
                openItem.command = {
                    command: 'sentinel.openRulesYaml',
                    title: 'Open rules.yaml'
                };
                items.push(openItem);
            }
            items.push(...element.rules.map(r => new RuleItem(r)));
            return Promise.resolve(items);
        }
        return Promise.resolve([]);
    }
}

class RuleCategoryItem extends vscode.TreeItem {
    constructor(label, rules, collapsibleState, categoryType) {
        super(`${label} (${rules.length})`, collapsibleState);
        this.rules = rules;
        this.categoryType = categoryType;
        this.contextValue = 'ruleCategory';
    }
}

class RuleItem extends vscode.TreeItem {
    constructor(rule) {
        super(`[${rule.id}] ${rule.name}`, vscode.TreeItemCollapsibleState.None);
        this.rule = rule;
        this.description = rule.severity;
        this.tooltip = `${rule.name}\nCWE: ${rule.cwe || 'N/A'}\n${rule.description}`;
        this.contextValue = 'ruleItem';

        if (rule.is_project_custom) {
            this.iconPath = new vscode.ThemeIcon('tools', new vscode.ThemeColor('charts.green'));
        } else if (rule.is_platform_custom) {
            this.iconPath = new vscode.ThemeIcon('cloud', new vscode.ThemeColor('charts.purple'));
        } else if (rule.severity === 'CRITICAL') {
            this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
        } else {
            this.iconPath = new vscode.ThemeIcon('shield', new vscode.ThemeColor('charts.blue'));
        }

        this.command = {
            command: 'sentinel.inspectRule',
            title: 'Inspect Rule',
            arguments: [rule]
        };
    }
}

/**
 * Renders rule inspection webview
 */
function showRuleInspectorWebview(context, rule) {
    const panel = vscode.window.createWebviewPanel(
        'sentinelRuleInspector',
        `Rule: ${rule.id}`,
        vscode.ViewColumn.Beside,
        { enableScripts: true }
    );

    const standardsHtml = (rule.standards || []).map(s => `<span class="badge badge-std">${escapeHtml(s)}</span>`).join(' ');
    const isCustom = rule.is_project_custom;
    const isPlatform = rule.is_platform_custom;

    let originLabel = '🛡️ Built-in Scanner Rule';
    if (isCustom) {
        originLabel = '<span class="badge badge-custom">⚙️ Project Custom Rule</span> &bull; <code>.sentinel/rules.yaml</code>';
    } else if (isPlatform) {
        originLabel = '<span class="badge badge-cloud">☁️ Cloud Platform Custom Rule</span> &bull; Remote Catalog';
    }

    panel.webview.html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; color: #f8fafc; background: #0b0f19; line-height: 1.6; }
            .header { display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 20px; }
            .badge { padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
            .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
            .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
            .badge-custom { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
            .badge-cloud { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #a855f7; }
            .badge-std { background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); }
            .box { background: rgba(15, 23, 42, 0.7); border: 1px solid #1e293b; border-radius: 8px; padding: 14px 18px; margin-bottom: 16px; }
            pre { background: #020617; padding: 12px; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #38bdf8; overflow-x: auto; border: 1px solid #1e293b; }
            h2 { font-size: 18px; margin: 0; color: #fff; }
            h4 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin: 0 0 8px 0; }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h2>[${escapeHtml(rule.id)}] ${escapeHtml(rule.name)}</h2>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
                    ${originLabel}
                </div>
            </div>
            <div>
                <span class="badge ${rule.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${escapeHtml(rule.severity || 'HIGH')}</span>
            </div>
        </div>

        <div class="box">
            <h4>Description &amp; Impact</h4>
            <p style="margin: 0; color: #cbd5e1;">${escapeHtml(rule.description || 'No description provided.')}</p>
        </div>

        <div class="box">
            <h4>Detection Pattern (Regex / AST)</h4>
            <pre>${escapeHtml(rule.regex || 'AST Structural Check')}</pre>
        </div>

        <div class="box">
            <h4>Recommended Secure Remediation</h4>
            <p style="margin: 0; color: #34d399; font-weight: 500;">${escapeHtml(rule.remediation || 'Follow project secure coding policies.')}</p>
        </div>

        <div class="box">
            <h4>Regulatory Compliance &amp; Standards Mapping</h4>
            <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px;">
                ${standardsHtml || '<span style="color: #64748b; font-size: 12px;">No specific standard tagged</span>'}
            </div>
        </div>
    </body>
    </html>
    `;
}

function escapeHtml(str) {
    return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeMarkdown(str) {
    return (str || '').replace(/([\\`*_{}[\]()#+\-.!])/g, '\\$1');
}

function deactivate() {
    if (diagnosticCollection) diagnosticCollection.clear();
}

module.exports = {
    activate,
    deactivate,
    buildApiUrl,
    makeApiRequest,
    parseSimpleYamlRules,
    fetchCloudRules,
    loginToCloudServer,
    compileRegex,
    syncWorkspaceFindingsFromServer,
    getServerCandidateUrls
};
