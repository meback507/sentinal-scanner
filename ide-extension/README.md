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

---

## Cloud Server Setup & Remote Connection

When Sentinel is hosted on a remote or cloud server (e.g. AWS EC2, GCP Compute Engine, Kubernetes cluster, or private VPS), developers can seamlessly connect their IDE extension to sync organization-wide security policies, platform custom rules, and audit results in real time.

### Step 1: Deploy Sentinel on Your Cloud Server

On your cloud VM or container cluster:

```bash
# Clone the repository on your cloud server
git clone https://github.com/meback507/sentinal-scanner.git appsec
cd appsec

# Start Sentinel backend & web dashboard
./run.sh
# Or with Docker:
docker compose up -d
```
Ensure your security group / firewall allows inbound traffic to port `8000` (or `443` if behind an Nginx / Cloudflare reverse proxy with SSL).

---

### Step 2: Configure the IDE Extension

There are **two easy ways** to connect the extension to your cloud server:

#### Option A: Interactive 1-Click Wizard (Recommended)
1. Open the Command Palette in your editor:
   - **Linux / Windows:** `Ctrl + Shift + P`
   - **macOS:** `Cmd + Shift + P`
2. Type and select: **`Sentinel: Connect to Cloud Server & API Token`**
3. Enter your remote cloud server URL:
   ```text
   https://sentinel.company.internal
   # or
   http://<YOUR_CLOUD_SERVER_IP>:8000
   ```
4. Choose your preferred authentication method:
   - **🔑 Login with Username & Password:** Enter your Sentinel account username and password (e.g., `admin` / `Admin@123!`). The plugin will authenticate to `POST /api/auth/login`, acquire your JWT bearer token, and save it automatically!
   - **🪪 Enter API Bearer Token / PAT:** If you already have a Personal Access Token or CI token, simply paste it in.
   - **🌐 Connect without Token:** Connect using anonymous / development mode.
5. The extension immediately connects to the cloud server, downloads the full security catalog (`GET /api/rules/catalog`), and displays a confirmation notification!

---

#### Option B: Configure via Editor Settings (`settings.json`)

You can also configure the server URL and token directly in your User or Workspace settings:

1. Open Settings (`Ctrl + ,` or `Cmd + ,`).
2. Search for **`Sentinel`**.
3. Set the following options:

```json
{
  "sentinel.serverUrl": "https://sentinel.your-company.com",
  "sentinel.apiToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "sentinel.allowInsecureTLS": false,
  "sentinel.rulesFile": ".sentinel/rules.yaml",
  "sentinel.scanOnSave": true,
  "sentinel.failOnSeverity": "HIGH"
}
```

> **🐳 Hosting in Docker Checklist:**
> 1. **Port Publishing**: Ensure port 8000 is published (`docker run -p 8000:8000 ...` or `docker compose up -d`).
> 2. **Interface Binding**: The container binds to `0.0.0.0:8000` by default, making it accessible from both `localhost` (local Docker) and your server's public/private IP (remote Docker).
> 3. **Firewall / Security Group**: In AWS/GCP/Azure/VPS, permit inbound TCP traffic on port `8000` (or `443` if using HTTPS).
> 4. **Self-Signed SSL/TLS**: If using self-signed HTTPS certificates, set `"sentinel.allowInsecureTLS": true` in your editor settings.
> 5. **Subpaths & Proxies**: Works seamlessly behind reverse proxies (Nginx, Caddy, Traefik), whether at root domain or subpath (e.g., `https://domain.com/sentinel/`).


---

### Step 3: How Cloud Rules & Local Rules Synchronize

Once connected to your cloud instance:
1. **Remote Cloud Catalog Synchronization:**
   The plugin queries `GET /api/rules/catalog` on the remote cloud instance. All centralized rules (SAST, IaC, Secrets, API security, and platform-wide custom rules) are retrieved and displayed under:
   - `☁️ Cloud Platform Custom Rules`
   - `🛡️ SAST Security Rules`
   - `🏗️ IaC & Container Hardening`
   - `🔑 Secret & Key Detection`
2. **Local Project Custom Rules Layering (`.sentinel/rules.yaml`):**
   If the active project has its own `.sentinel/rules.yaml`, local project rules are automatically merged and take precedence, showing under:
   - `⚙️ Project Custom Rules (.sentinel/rules.yaml)`
3. **Real-Time In-Editor Enforcement:**
   Every open document is evaluated against both remote cloud rules and local project rules as you type or save.
4. **Offline Resilience:**
   If the cloud server is temporarily unreachable or the developer goes offline, the plugin gracefully falls back to local cached rules and `.sentinel/rules.yaml` without breaking editor workflows.

---

## Quick Command Reference

| Command | Action |
| :--- | :--- |
| `Sentinel: Connect to Cloud Server & API Token` | Launch cloud server connection & login wizard |
| `Sentinel: Scan Active Document` | Run immediate AST audit on current file |
| `Sentinel: Scan Entire Workspace` | Audit all repository files and update status bar |
| `Sentinel: Refresh & Sync Custom Rules` | Re-fetch rules from cloud server & reload `.sentinel/rules.yaml` |
| `Sentinel: Open Web Dashboard` | Open the cloud server dashboard in default browser |

