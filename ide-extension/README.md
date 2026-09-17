# Sentinel AppSec IDE Plugin & Project Custom Rules Engine

The **Sentinel AppSec IDE Extension** delivers developer shift-left security directly into your code editor (compatible with Visual Studio Code, Cursor, Windsurf, and Antigravity IDE).

It reflects all built-in security engines (SAST, Secrets, IaC/Containers, OpenAPI specs) and **dynamically discovers and enforces project custom rules** written in `.sentinel/rules.yaml` directly in your workspace.

---

## Key Features

1. **Real-Time In-Editor Squiggly Diagnostics**:
   - As you type or save code, the plugin scans the active buffer against all active security rules.
   - Highlights code flaws with red (Critical/High) or yellow (Medium) squiggly underlines.
   - Distinct source tags distinguishing **`[Project Custom: .sentinel/rules.yaml]`** from built-in engine checks.

2. **Interactive Hover Tooltips**:
   - Hover over any flagged line to see:
     - Rule Name and ID (`PROJ-SAST-001`, `INJ-001`, `IAC-DOCKER-001`)
     - Severity & Rule Origin (Project Custom vs Built-in)
     - CWE / CVE identifier
     - Regulatory Standards (`ISO 27001`, `MISRA`, `OWASP Top 10`, `CIS`)
     - Exact remediation steps and safe code pattern
     - 1-click **Suppress Rule** action

3. **Project Custom Rules Reflection (`.sentinel/rules.yaml`)**:
   - Write custom security rules directly in your repository:
     ```yaml
     version: "1.0"
     rules:
       - id: "PROJ-SAST-001"
         name: "Unsafe Insecure YAML Deserialization via yaml.load"
         type: "sast"
         severity: "CRITICAL"
         languages: ["python"]
         cwe: "CWE-502"
         standards: ["OWASP:A08:2021", "ISO-27001:A.8.28"]
         regex: "(?i)yaml\\.load\\s*\\([^,)]*\\)(?!.*Loader=)"
         description: "Calling yaml.load without specifying a safe Loader permits arbitrary object deserialization."
         remediation: "Always use yaml.safe_load(data) or specify Loader=yaml.SafeLoader."
     ```
   - Any rule added to `.sentinel/rules.yaml` is instantly reflected in the editor without restarting!

4. **Security & Custom Rules Explorer Sidebar**:
   - Dedicated Activity Bar container (`Sentinel AppSec`) with a hierarchical tree view:
     - ⚙️ **Project Custom Rules (`.sentinel/rules.yaml`)**
     - 🛡️ **Built-in SAST Rules**
     - 🏗️ **IaC & Container Hardening**
     - 🌐 **API Security (OWASP Top 10)**
     - 🔑 **High-Entropy Secrets**
   - Click on any rule to open the rich **Rule Inspector Webview** showing its regex pattern, impact, and compliance mappings.

5. **1-Click Quick Fixes**:
   - Click the lightbulb on any diagnostic line to automatically insert `# sentinel-ignore: <RULE-ID>`.

---

## Installation

### Method 1: Local Workspace Installation (Zero-Config)
Symlink or copy the `ide-extension` folder into your VS Code / Cursor extensions directory:
```bash
ln -s /home/zeek/appsec/ide-extension ~/.vscode/extensions/sentinel-appsec-ide
```
Or for Cursor:
```bash
ln -s /home/zeek/appsec/ide-extension ~/.cursor/extensions/sentinel-appsec-ide
```

### Method 2: Package VSIX
If `vsce` is installed:
```bash
cd ide-extension
npx @vscode/vsce package
code --install-extension sentinel-appsec-ide-1.0.0.vsix
```

---

## Configuration Settings

In your editor `settings.json`:
```json
{
  "sentinel.serverUrl": "http://127.0.0.1:8000",
  "sentinel.rulesFile": ".sentinel/rules.yaml",
  "sentinel.scanOnSave": true,
  "sentinel.failOnSeverity": "HIGH"
}
```
