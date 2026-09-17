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

    // Built-in SAST
    {
        id: "SEC-001",
        name: "Hardcoded API Key or Secret Token",
        type: "secret",
        severity: "HIGH",
        languages: ["python", "javascript", "typescript", "java", "go"],
        cwe: "CWE-798",
        standards: ["ISO-27001:A.8.12", "OWASP:A07:2021"],
        regex: "(?:api_key|apikey|secret|token|password|passwd|private_key|aws_secret_access_key)\\s*[:=]\\s*['\"][a-zA-Z0-9_\\-\\.]{16,}['\"]",
        description: "Hardcoded API keys or credentials embedded directly into source code.",
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

    // 4. Load Project Custom Rules from workspace
    loadAllRules();

    // 5. Register Extension Commands
    context.subscriptions.push(
        vscode.commands.registerCommand('sentinel.scanCurrentFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanDocument(editor.document);
                vscode.window.showInformationMessage(`🛡️ Sentinel: Scanned ${path.basename(editor.document.fileName)}`);
            }
        }),

        vscode.commands.registerCommand('sentinel.scanWorkspace', () => {
            scanWorkspace();
        }),

        vscode.commands.registerCommand('sentinel.refreshRules', () => {
            loadAllRules();
            vscode.window.showInformationMessage('🛡️ Sentinel: Refreshed security rules and project custom rules (.sentinel/rules.yaml).');
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

        vscode.commands.registerCommand('sentinel.applyQuickFix', (documentUri, range, ruleId) => {
            applySuppressionComment(documentUri, range, ruleId);
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

    // 8. Auto-scan on Document Open and Save
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => {
            if (doc.uri.scheme === 'file') scanDocument(doc);
        }),

        vscode.workspace.onDidSaveTextDocument(doc => {
            const config = vscode.workspace.getConfiguration('sentinel');
            if (config.get('scanOnSave') && doc.uri.scheme === 'file') {
                scanDocument(doc);
            }
        }),

        vscode.workspace.onDidCloseTextDocument(doc => {
            diagnosticCollection.delete(doc.uri);
        })
    );

    // Initial scan of active editor
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}

/**
 * Helper to perform HTTP or HTTPS requests for cloud sync & authentication
 */
function makeApiRequest(urlStr, options = {}, postData = null) {
    return new Promise((resolve, reject) => {
        try {
            const urlObj = new URL(urlStr);
            const isHttps = urlObj.protocol === 'https:';
            const client = isHttps ? https : http;

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
                timeout: 5000
            };

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

            req.on('error', (err) => reject(err));
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Connection timed out'));
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
    const url = new URL('/api/auth/login', serverUrl).toString();
    const res = await makeApiRequest(url, { method: 'POST' }, postBody);
    if (res.statusCode >= 200 && res.statusCode < 300) {
        const json = JSON.parse(res.body);
        return json.access_token;
    } else {
        let msg = `HTTP ${res.statusCode}`;
        try {
            const err = JSON.parse(res.body);
            if (err.detail) msg = err.detail;
        } catch (_) {}
        throw new Error(msg);
    }
}

/**
 * Fetches latest security rules and platform custom rules from remote Sentinel server
 */
async function fetchCloudRules(serverUrl, apiToken) {
    if (!serverUrl) return [];
    try {
        const headers = {};
        if (apiToken) {
            headers['Authorization'] = `Bearer ${apiToken.trim()}`;
        }
        const url = new URL('/api/rules/catalog', serverUrl).toString();
        const res = await makeApiRequest(url, { method: 'GET', headers });
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
            return cloudRules;
        } else {
            console.warn(`[Sentinel IDE] Cloud server returned status ${res.statusCode}`);
            return [];
        }
    } catch (err) {
        console.warn('[Sentinel IDE] Cloud server unreachable:', err.message);
        return [];
    }
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
    const serverUrl = config.get('serverUrl');
    const apiToken = config.get('apiToken');

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
    const workspaceFolders = vscode.workspace.workspaceFolders;
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

    if (rulesTreeProvider) {
        rulesTreeProvider.refresh();
    }
    updateStatusBar();
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
 * Scans an individual text document against active rules
 */
function scanDocument(document) {
    if (!document || !document.getText) return;
    const text = document.getText();
    const fileName = document.fileName.toLowerCase();
    const diagnostics = [];

    // Language resolution
    let docLang = 'python';
    if (fileName.endsWith('.js') || fileName.endsWith('.ts')) docLang = 'javascript';
    if (fileName.endsWith('.json')) docLang = 'json';
    if (fileName.endsWith('.yaml') || fileName.endsWith('.yml')) docLang = 'yaml';
    if (fileName.includes('dockerfile')) docLang = 'dockerfile';

    const lines = text.split(/\r?\n/);

    for (const rule of activeRules) {
        if (rule.languages && rule.languages.length > 0) {
            const applies = rule.languages.some(l => docLang.includes(l.toLowerCase()) || fileName.includes(l.toLowerCase()));
            if (!applies && !rule.languages.includes('*') && !rule.languages.includes('all')) {
                continue;
            }
        }

        if (!rule.regex) continue;

        const regex = compileRegex(rule.regex);
        if (!regex) continue;

        try {
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if (line.includes('sentinel-ignore')) continue;

                const match = regex.exec(line);
                if (match) {
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

                    const diag = new vscode.Diagnostic(
                        range,
                        `[${rule.id}] ${rule.name}${originLabel}: ${rule.description}`,
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

    diagnosticCollection.set(document.uri, diagnostics);
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
        const files = await vscode.workspace.findFiles('**/*', '**/node_modules/**', 200);
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
            const items = element.rules.map(r => new RuleItem(r));
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
    parseSimpleYamlRules,
    fetchCloudRules,
    loginToCloudServer,
    compileRegex
};
