# Sentinel AppSec: Enterprise SAST & SCA Security Platform

**Sentinel AppSec** (formerly AegisSec) is a next-generation Application Security Testing (AST) platform unifying **Static Application Security Testing (SAST)**, **Software Composition Analysis (SCA)**, **SonarQube RSpec Rule Compatibility**, **Infrastructure-as-Code (IaC) Auditing**, and **High-Entropy Secret Detection** into a centralized, modern web dashboard and developer IDE extension.

---

## Key Capabilities

1. **Intelligent Vulnerability Prioritization (CVSS + EPSS)**:
   - Evaluates **CVSS v3.1 / v4.0** impact severity alongside live/cached **EPSS** (Exploit Prediction Scoring System) data from FIRST.org and public vulnerability databases (NVD, OSV).
   - Dynamic **Action Quadrants**:
     - 🚨 **Act Now** (*High CVSS $\ge$ 7.0 & High EPSS $\ge$ 0.20*): Immediate active threat hazard. SLA: 24–48 hours.
     - ⚠️ **Critical Patch** (*High CVSS $\ge$ 7.0 & Low EPSS < 0.20*): Severe impact with low current weaponization. SLA: 14 days.
     - ⚡ **Opportunistic** (*Low CVSS < 7.0 & High EPSS $\ge$ 0.20*): Low severity flaws actively targeted by botnets. SLA: 30 days.
     - 🟢 **Routine Backlog** (*Low CVSS < 7.0 & Low EPSS < 0.20*): Maintenance SLA: 90 days.

2. **Unified Compliance & Regulatory Standards**:
   - **General & AppSec**: ISO/IEC 27001:2022 (A.8.28 Secure Coding, A.8.25 Dev Lifecycle, A.8.12 Data Leakage), ISO/IEC 27034 (Application Security Controls), OWASP Top 10:2021, CWE/SANS Top 25.
   - **Automotive & Embedded**: ISO 26262-6 (Functional Safety ASIL A–D), ISO/SAE 21434 (Road vehicles cybersecurity), MISRA C:2012, MISRA C++:2023, and AUTOSAR C++14.
   - **Cloud & Software Supply Chain**: NIST SP 800-53 Rev. 5, NIST SSDF (SP 800-218), CIS Software Supply Chain Security, PCI-DSS v4.0, and ISO/IEC 5230 (OpenChain Open Source License Compliance).

3. **SonarQube RSpec Compatibility & Open Community Rule Catalog**:
   - Built-in engine supporting **25+ SonarQube standard rules** across Python, JavaScript, TypeScript, Java, and C/C++ (S2068 Hardcoded Credentials, S5131 Reflected XSS, S2077 SQL Injection, S4524 CSRF Disabled, S5043 XML Billion Laughs DoS, S5853 Static IV Cryptography, etc.).
   - Curated **Open Community Rules** covering OWASP Top 10 (OPEN-COMM-001 IDOR, OPEN-COMM-002 Unsalted Hashes, OPEN-COMM-003 Stack Trace Disclosure, OPEN-COMM-004 Unpinned Dependencies).
   - Native SonarQube external issue report exporter (`--sonar-export sonar-issues.json` or `GET /api/projects/{id}/export/sonarqube`) with 1-click `sonar-project.properties` and GitHub Action configuration generator (`sentinel-cli init-sonar`).

4. **Natural-Language Custom Rule Studio & Project-Oriented Scoping**:
   - Translates human English instructions into concrete SAST AST/pattern rules or SCA dependency policies.
   - **Project-Specific or Global Scope**: Custom rules can be configured globally or targeted specifically to an individual project (`project_id`). This ensures that specialized rules (e.g. automotive MISRA C:2012 / ISO 26262 memory allocation restrictions) only run against their intended codebases without creating false positives in unrelated web or microservice projects.
   - Example prompts:
     - *"Disallow dynamic memory allocation malloc or free in C/C++ for MISRA compliance"*
     - *"Detect hardcoded API keys or JWT tokens in Python and JavaScript"*
     - *"Flag SQL injection via string concatenation in Python"*
     - *"Ban dependency package lodash below version 4.17.21 or any library with license AGPL-3.0"*
   - Built-in **Live Code Test Bench** to test synthesized rules against custom code snippets before activation.

5. **Live `rules.yaml` Editor & Bi-Directional Synchronization**:
   - View, edit, sync, and purge custom rules in real-time through an in-browser YAML editor (`GET /api/rules/file` and `PUT /api/rules/file`).
   - Supports project-scoped filtering (`?project_id=...`) to view active rules for a designated project.
   - Seamless two-way persistence: rule updates created in the UI sync instantly to `.sentinel/rules.yaml` on disk, and manual edits to the YAML file sync automatically into the database.

6. **Git Repository Management with Personal Access Tokens (PAT)**:
   - Configurable remote Git repositories (GitHub, GitLab, Bitbucket, Azure DevOps, private Git servers).
   - Automated token encryption and credential masking in logs and output.
   - Shallow clone optimization (`--depth 1 --single-branch`) with workspace isolation.

7. **Ticketing Platform Connectors & Automatic Author Assignment**:
   - **Automatic Assignment to Code Author**: Dispatched tickets (Jira or Zammad) are **automatically assigned directly to the author of that code** (`author_name`, `author_email`) via Git blame attribution.
   - **Atlassian Jira Cloud / Server**: Direct issue creation with automatic `assignee` set to the code author, vulnerability reproduction details, CVSS/EPSS priority mapping, and code context.
   - **Zammad Helpdesk**: Native REST API ticket creation with customer/owner set directly to the code author.
   - **1-Click Project Auto-Dispatch (`POST /api/projects/{id}/auto-ticket`)**: Batch dispatches and assigns tickets directly to each respective code author for all detected vulnerabilities across the codebase.

8. **Multi-Format Security Exporters**:
   - **Executive HTML / PDF Report**: Comprehensive executive summaries, compliance impact, and remediation plan.
   - **SARIF v2.1.0 JSON**: OASIS standard format for GitHub Code Scanning, GitLab SAST, SonarQube, and IDE integration.
   - **SonarQube Generic Issue Format**: Full compatibility with SonarScanner and SonarCloud external issue imports.
   - **CycloneDX v1.5 JSON**: Software Bill of Materials (SBOM) for component inventory and supply chain audits.
   - **CSV Tabular Export**: Direct export for spreadsheet analysis and tracker sync.

9. **Role-Based Access Control (RBAC), Project Assignments & Dedicated Login Portal**:
   - Dedicated glassmorphic login interface at `/login` with 1-click persona switchboard.
   - **Strict Project Assignment Isolation**: Users and developers can be assigned to one or more specific projects (`project_members`). Any non-admin user (`role != "admin"`, including developers, security engineers, and auditors) is **strictly restricted to their assigned projects**.
   - **Project Team Management**: Administrators can assign, view, and unassign team members via the **`👥 Team`** modal in the Projects view or configure project scopes when creating/editing user accounts.
   - Roles:
     - `admin`: Enterprise-wide global access across all projects, system settings, RBAC, integrations, and custom rules.
     - `security_engineer`: Scoped strictly to assigned projects. Trigger scans, project custom rule generation, reports, and ticket dispatch.
     - `developer`: Scoped strictly to assigned projects AND authored code. Inspect code flaws, review fixes, triage status.
     - `auditor`: Scoped strictly to assigned projects. Read-only compliance matrices, standards reports, and audit logs.

10. **Dual-Layer Isolation: Project Assignments & Git Blame Attribution**:
    - **Layer 1: Project-Level Membership Isolation**: Non-admin users are strictly isolated to their assigned projects. Project listings (`/api/projects`), findings (`/api/findings`), scans (`/api/projects/{id}/scan`), rules, and reports only return data for authorized projects.
    - **Layer 2: Per-Line Git Blame Attribution**: Within an assigned project, developer views are further scoped to code authored by that specific developer (`author_name`, `author_email`).
    - **Cross-Project & Cross-Developer Tamper Guards**: Direct API requests to inspect, triage, patch, or export unassigned projects or foreign code flaws are rejected with `403 Forbidden`.

11. **Large Language Model (LLM) Integration & AI-Powered Security Engine**:
    - **Multi-Provider Support**: Supports OpenAI (GPT-4o, GPT-4 Turbo), Anthropic Claude (Claude 3.5 Sonnet), Google Gemini (Gemini 1.5 Pro), Ollama (Local/Self-Hosted `llama3.2`), and custom OpenAI-compatible gateways.
    - **AI Contextual Remediation & Code Diffs**: In the Vulnerability Triage inspector, engineers can generate AI root-cause analysis, refactored secure replacement code diffs (parameterized queries, bounded buffers, safe deserialization), and unit test verification guidance.
    - **Developer-Scoped AI Access**: Developers can only trigger AI remediation on code they authored; cross-developer inspection requests are strictly blocked.
    - **100% Offline / Air-Gapped Resiliency**: Built-in deterministic AST synthesis engine ensures continuous operation with expert code diffs even when external LLM APIs are offline or unconfigured.

12. **Compliance, Audit & Governance Hub (`#view-audit`)**:
    - **Audited Findings Ledger**: Complete inventory of vulnerabilities with regulatory controls (ISO 26262 ASIL-D, ISO 27001, NIST SSDF), SCA reachability, and developer blame.
    - **Signed Audit Attestation Certificates**: Generates downloadable, cryptographically signed compliance certificates with 64-character SHA-256 digital seals.
    - **Immutable Audit Trail Log**: Append-only security log tracking scans, PR creations, CI evaluations, and attestation events.

13. **Time-Series Trend Line Graphs & RBAC Contributor Scoping**:
    - **Default Landing Page Trajectory (`#view-dashboard`)**: Visualizes 6-sprint historical security progress across Critical flaws, High severity, Remediated fixes, and Posture rating (%).
    - **Strict Contributor Scoping**: When a Developer logs in, the graph renders **strictly their contributed code trajectory**; when an Admin logs in, shows Global Enterprise trends with an interactive Contributor Scope dropdown.
    - **Audit Compliance Velocity Curve**: Dedicated trend chart in the Audit Hub showing ISO 27001, ISO 26262, and NIST SSDF adherence velocity over time.

14. **1-Click Autonomous AI Remediation PR & Patch Generator**:
    - Directly branches (`fix/aegissec-{id[:8]}-{cwe}`), patches code with verified AI diffs, attributes original authors, and opens pull requests with automated compliance and test verification suites.
    - Enforces developer isolation: developers cannot generate PRs on foreign code (`403 Forbidden`).

15. **CI/CD Quality Gates & Differential PR Webhooks**:
    - Threat-informed gate checking (`POST /api/ci/gate-check`) that fails on active weaponized hazards (🚨 Act Now) or automotive safety violations (ASIL-D / MISRA Rule 21.3) while preserving routine velocity.
    - GitHub/GitLab webhook integration (`POST /api/webhooks/github`) with automated Markdown review comments and remediation links.

16. **True-Positive SCA Reachability & High-Entropy Secret Scanner**:
    - Static call-graph symbol reachability analysis distinguishing `REACHABLE` from `IMPORTED` and `DORMANT` dependencies.
    - Shannon Entropy detection ($H(X) \ge 4.0$ bits/char) with regex pattern matching for 50+ API and cloud token formats.

17. **Threat Intelligence & CISA KEV Catalog**:
    - Automatic enrichment of CVE findings against the **CISA Known Exploited Vulnerabilities (KEV)** catalog.
    - Escalates weaponized in-the-wild vulnerabilities to `ACT_NOW` urgency with strict 24–48 hour remediation deadlines and prominent badges across triage and audit ledgers.

18. **Infrastructure as Code (IaC) & Container Hardening**:
    - Dedicated scanner (`IaCEngine`) evaluating Dockerfiles, docker-compose, Kubernetes manifests, Terraform (`.tf`), and GitHub Actions workflows.
    - Enforces least-privilege containers, non-root execution, pinned immutable tags, secret mask checks, and secure cloud storage configurations.

19. **OpenAPI / Swagger API Security Engine (OWASP API Top 10)**:
    - Spec auditor (`APISecEngine`) detecting Broken Object Level Authorization (BOLA), unauthenticated administrative routes, mass assignment hazards, unbounded pagination DoS, and cleartext HTTP transport.

20. **Developer Shift-Left Tooling & Sentinel CLI**:
    - Standalone pre-commit shield (`scripts/sentinel_cli.py`) enabling developers to run instant local AST/secrets/IaC audits before committing.
    - Supports 1-command git pre-commit hook installation (`sentinel-cli install-hook`) and configurable exit gates (`--fail-on HIGH`).
    - SonarQube setup automation (`sentinel-cli init-sonar`).

21. **IDE Extension (VS Code / Antigravity / Cursor / VSCodium)**:
    - Pre-packaged `.vsix` extension downloadable directly from the web interface or via `GET /api/extension/download`.
    - Live in-editor squiggly diagnostics as you code, interactive hover tooltips with compliance references, rules sidebar explorer, and `allowInsecureTLS` configuration for custom/self-signed deployments.

22. **Cloud-Native & Containerized Architecture**:
    - Docker container optimized for AWS ECS/EKS, GCP Cloud Run/GKE, Azure Container Apps, and standalone VPS.
    - Non-root `sentinel` execution user + root-enabled `admin` user with sudo privileges.
    - Automated `docker-entrypoint.sh` with interactive initial admin setup, dynamic port allocation (`$PORT`), and container healthcheck probe (`GET /api/health`).

23. **CycloneDX 1.5, SPDX 2.3 & OpenVEX SBOM Generator**:
    - Enterprise Software Bill of Materials (SBOM) compliant with CycloneDX 1.5 and SPDX 2.3 specifications.
    - Reachability-aware VEX (Vulnerability Exploitability eXchange) array with machine-readable justification states (`not_affected`, `exploitable`, `in_triage`).
    - Dedicated interactive SBOM Center modal (`#modal-sbom-center`) with live JSON preview, format toggle, copy-to-clipboard, and direct file downloads.

24. **Interactive Custom Rule Builder & Live Regex Sandbox**:
    - Visual rule creation studio with real-time regex compilation, execution latency benchmarking (μs), and match offset highlighting.
    - Direct test sandbox against user-supplied code snippets prior to committing rules into `.sentinel/rules.yaml` and the persistent rule registry.
    - Accessible via header button `🛠️ Rule Builder` and modal `#modal-rule-builder`.

25. **Two-Way Jira & Linear Issue Tracker Integration**:
    - Native bidirectional issue tracking with Atlassian Jira and Linear.
    - 1-click export of security findings with full CVSS/EPSS vectors, CWEs, and code context into Jira issues or Linear tickets.
    - Automated bidirectional synchronization (`/api/trackers/sync`) syncing ticket status transitions (e.g. Done/Resolved in Jira/Linear auto-resolving vulnerabilities in Sentinel).

26. **Runtime Application Self-Protection (RASP) & Simulated Live Exploit Defense Monitor**:
    - Real-time application-layer inspection engine detecting SQL injection, command execution, path traversal, SSRF, XXE, and reflected XSS.
    - Dual operating modes: `BLOCK` (HTTP 403 Forbidden with security telemetry alerts) and `MONITOR` (passive detection with audit logging).
    - Built-in Live Attack Simulation Workbench (`#modal-rasp-defense`) with real-time telemetry radar, payload testing, and incident feeds.

27. **AI Threat Modeling & Attack Surface Diagrammer (STRIDE & DFD)**:
    - Automated STRIDE hazard analysis (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) mapped directly from source code AST and routes.
    - Interactive architecture Data-Flow Diagram (Level-1 DFD) showing trust boundaries between untrusted client traffic, DMZ API controllers, and protected data stores.
    - DREAD risk scoring matrix (Damage, Reproducibility, Exploitability, Affected Users, Discoverability).
    - Dedicated view in sidebar: `Threat Model (STRIDE)`.

28. **Automated Secret Rotation & Cloud Vault Integration**:
    - Enterprise integration with **HashiCorp Vault**, **AWS Secrets Manager**, and **Azure Key Vault**.
    - 1-click automated rotation of leaked credentials directly from the vulnerability inspector.
    - Automatically injects secure environment retrieval code diffs (`os.getenv(...)`) and records rotation audit logs.

29. **Container Image & Base OS Vulnerability Scanner**:
    - Deep layer inspection of Dockerfiles, container configurations, and base OS packages (Alpine apk, Debian dpkg, RPM).
    - Curated Base OS CVE intelligence database detecting critical vulnerabilities in `curl`, `glibc`, `openssl`, `busybox`, `zlib`, and `libxml2`.
    - Detects root container execution, deprecated EOL base images, mutable `:latest` tags, and layer bloat.

30. **Visual Policy-as-Code & Quality Gate Studio**:
    - Declarative security gate policies enforcing zero critical findings, CISA KEV blocking, secret leakage gates, and EPSS exploit probability ceilings.
    - Interactive **PR Quality Gate Simulator (Dry-Run Workbench)** allowing engineering teams to test simulated PR metrics against active policies before merging.
    - Dedicated view in sidebar: `Policy-as-Code Studio`.

31. **Attack Path & Blast Radius Analyzer**:
    - Graph-based multi-stage vulnerability chaining across SAST, DAST, Secrets, and SCA into adversary kill chains.
    - Automated **Chokepoint Identification**: isolates single strategic vulnerabilities whose remediation severs entire attack paths.
    - Interactive **Kill-Chain Chokepoint Simulator**: visualizes live adversary reachability and threat exposure reduction percentages.
    - Dedicated view in sidebar: `Attack Path & Blast Radius`.

32. **Regulatory Compliance & Control Matrix Engine**:
    - Automated, real-time mapping of technical code findings to **SOC 2 Type II**, **PCI-DSS v4.0**, **ISO/IEC 27001:2022**, **HIPAA Security Rule**, and **NIST CSF v2.0**.
    - Audit-readiness scorecards, automated control evaluation tables, and 1-click auditor export packages (JSON).
    - Integrated directly into the `Standards & ISO Matrix` view (`#view-compliance`).

33. **OWASP API Security Top 10 Dynamic Fuzzer**:
    - Automated dynamic behavioral fuzzing engine targeting **API1:2023 (BOLA)**, **API2:2023 (Broken Auth)**, **API3:2023 (Mass Assignment)**, **API5:2023 (BFLA)**, and **API7:2023 (SSRF)**.
    - Automatic OpenAPI/Swagger 3.0 schema parsing with built-in parameter tampering and fuzz probes.
    - Generates 1-click reproducible `curl` commands and detailed exploit proof-of-concept evidence.
    - Dedicated view in sidebar: `API Sec Fuzzer (OWASP)`.

34. **OWASP Top 10 for LLMs & AI Agent Security Guard**:
    - Static analysis scanner detecting hardcoded AI provider keys, direct prompt concatenation, and excessive agent agency (dangerous shell execution).
    - Interactive **Adversarial Prompt & Jailbreak Prober**: tests prompt templates against Direct Overrides, Base64 bypasses, DAN personas, and RAG context poisoning with a real-time **Guardrail Health Score**.
    - Dedicated view in sidebar: `AI & LLM Guard`.

35. **Continuous SBOM Drift & SLSA Level 3 Attestation**:
    - Compares Software Bill of Materials (SBOM) snapshots across builds to detect dependency drift and unauthorized transitive bumps.
    - Automated **Copyleft License Alerting** flagging GPL/AGPL viral contamination in commercial codebases.
    - Cryptographically verifiable **in-toto SLSA Level 3 build provenance attestation** with Sigstore Cosign-compatible signing metadata.
    - Dedicated view in sidebar: `SBOM Drift & SLSA`.

36. **AppSec Developer Playground & Vulnerability Sandbox**:
    - Hands-on interactive security lab featuring curated challenges: SQLi Parameterization, JWT `"alg": "none"` bypass, SSRF Metadata protection, Path Traversal canonicalization, and LLM Prompt Boundary enforcement.
    - In-browser interactive code editor, adversarial exploit test harness, real-time terminal output, and security points scoring.
    - Dedicated view in sidebar: `AppSec Playground`.

37. **Interactive Dependency Tree & Transitive Blast Radius Visualizer (Supply Chain & SCA)**:
    - Hierarchical nested dependency tree navigation (`root -> direct -> transitive`) with instant search, type filters (`All`, `Vulnerable`, `Direct`, `Transitive`), and CVE severity badges.
    - Quantitative **Blast Radius Analytics**: computes downstream blast radius scores quantifying how many direct modules and application services are compromised if a given transitive library is weaponized.
    - Visual **Root-to-Leaf Exposure Tracing**: traces exact parent chains (e.g. `express -> body-parser -> qs@6.5.2`) and provides 1-click CycloneDX SBOM downloads.
    - Dedicated view in sidebar: `Dependency Tree & Blast Radius` (`#view-deptree`).

38. **Conversational Security Copilot Chatbot (AI & Analytics)**:
    - Context-aware conversational security assistant accessible platform-wide via floating widget (`#copilot-floating-btn` / `#copilot-chat-window`).
    - Ingests real-time project security telemetry, findings inventory, composite risk scores, SCA reachability, and regulatory compliance gaps.
    - Dual-engine architecture: connects to external LLM providers (OpenAI, Claude, Gemini, Ollama) with seamless fallback to an expert Domain-Specific Heuristic Engine for 100% offline, air-gapped security.
    - Features syntax-highlighted remediation code blocks, quick-prompt chips, and actionable workflow shortcuts (navigate to triage, trigger auto-patches, export compliance dossiers).
    - Fully strictly scoped to user RBAC and project access permissions.

39. **Executive Compliance Crosswalk Matrix & Printable Auditor Dossier Exporter**:
    - Real-time mapping of code-level findings and architectural controls across **SOC 2 Type II**, **ISO/IEC 27001:2022**, **PCI-DSS v4.0**, **HIPAA Security Rule**, and **NIST CSF v2.0**.
    - Generates a polished, C-level executive audit dossier (`GET /api/projects/{id}/compliance/export/html`) formatted specifically for board presentations and external audit submissions.
    - Features cryptographic 64-character SHA-256 digital attestation seals, compliance scorecards, vulnerability breakdown matrices, and regulatory control crosswalk tables.
    - Integrated directly into the `Standards & ISO Matrix` view (`#view-compliance`).

---

## Quick Start

### Option 1: Run Locally with Python Virtualenv (Instant Start)
Execute the automated run script:
```bash
./run.sh
```
The server will boot at **`http://127.0.0.1:8000`**.

---

### Option 2: Run with Docker Compose (Recommended for Production)
Build and start the containerized service:
```bash
docker compose up -d --build
```
Check container logs:
```bash
docker compose logs -f sentinel
```
Restart or rebuild:
```bash
docker compose restart
# or rebuild after updates:
docker compose up -d --build
```
The platform will be accessible at **`http://localhost:8000`** with persistent SQLite database storage and audit reports.

---

### Option 3: Run with Standalone Docker CLI
Build the Docker image:
```bash
docker build -t sentinel-appsec:latest .
```
Run the container:
```bash
docker run -d \
  --name sentinel-platform \
  -p 8000:8000 \
  -e ADMIN_PASSWORD=admin \
  -v sentinel_data:/app/data \
  -v sentinel_reports:/app/reports \
  sentinel-appsec:latest
```

---

## Environment Variables & Configuration

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `PORT` | `8000` | Port for the HTTP server to bind (supports dynamic Cloud Run/ECS `$PORT`) |
| `WORKERS` | `2` | Number of Uvicorn worker processes |
| `ADMIN_USERNAME` | `admin` | Initial super-administrator username |
| `ADMIN_PASSWORD` | `admin` | Initial super-administrator password |
| `SENTINEL_DB_PATH` | `/app/data/sentinel.db` | Path to persistent SQLite database |
| `APP_ENV` | `production` | Runtime environment mode (`development` / `production`) |
| `PYTHONUNBUFFERED` | `1` | Stream console logs without buffering |

---

## Default RBAC & Developer Demo Credentials

The platform includes pre-seeded accounts demonstrating dual-layer isolation (Project Assignments + Developer Git Blame):

| Role | Username | Password | Project Access Scope | Authored Code Scope | Permissions |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Super Admin** | `admin` | `admin` *(or `Admin@123!`)* | **Global** (All projects) | Global (All developers) | Full enterprise administration, RBAC, project assignments, LLM config |
| **Security Lead** | `sec_lead` | `SecLead@123!` | Assigned Projects | Global within assigned projects | Trigger scans, project custom rules, ticket dispatch, AI analysis |
| **Developer** | `marcus` | `Marcus@123!` | Assigned Projects | Marcus Vance (`app.py`) | **Double Scoped**: Assigned projects only & Python flaws authored by Marcus |
| **Developer** | `elena` | `Elena@123!` | Assigned Projects | Dr. Elena Rostova (`ecu_controller.cpp`) | **Double Scoped**: Assigned projects only & MISRA C flaws authored by Elena |
| **Developer** | `sarah` | `Sarah@123!` | Assigned Projects | Sarah Lin (`dashboard.js`) | **Double Scoped**: Assigned projects only & JS flaws authored by Sarah |
| **Auditor** | `auditor` | `Auditor@123!` | Assigned Projects | Read-only | Read-only compliance inspection, certificates & audit exports |

*Note: Non-admin users are strictly isolated to their assigned projects. Admins can assign users to projects via the **`👥 Team`** modal in the Projects view or the project checklist in User Management (`/login`).*

---

## Installing the IDE Extension (VS Code / Antigravity IDE)

1. Download the extension `.vsix` directly from the running web interface by clicking the **"Download IDE Extension"** button or via API:
   ```bash
   curl -O http://localhost:8000/api/extension/download
   ```
2. Install in Visual Studio Code, Cursor, or Antigravity IDE:
   ```bash
   code --install-extension sentinel-appsec-ide-1.0.0.vsix
   ```
3. Configure your server URL in settings:
   - `sentinel.serverUrl`: `http://localhost:8000` (or your cloud endpoint)
   - `sentinel.allowInsecureTLS`: `true` (if using custom/self-signed certificates)

---

## Running Automated Tests

Run the full verification test suite (100+ tests covering SAST, SCA, RBAC, SonarQube rules, IDE resilience, and Auto-Patch):
```bash
./.venv/bin/python3 -m unittest discover -s tests -v
```

---

## REST API Overview

### Authentication & Health
- `POST /api/auth/login`: Authenticate and receive JWT access token.
- `GET /api/health`: Healthcheck probe for load balancers and container orchestrators.

### Projects & Scans
- `GET /api/projects`: List configured projects (automatically filtered strictly to assigned projects for non-admin users).
- `POST /api/projects`: Create project with Git repository, PAT credentials, and optional initial assigned members (`assigned_users`).
- `GET /api/projects/{id}`: Get project details (enforces project assignment; returns `403 Forbidden` if unassigned).
- `DELETE /api/projects/{id}`: Permanently delete project with cascading data cleanup (`admin` only).
- `POST /api/projects/{id}/scan`: Trigger on-demand SAST & SCA scan (enforces project assignment).
- `GET /api/projects/{id}/members`: List all team members assigned to project with their roles and assignment timestamps.
- `POST /api/projects/{id}/members`: Assign users to project with specified role (`admin` only).
- `DELETE /api/projects/{id}/members/{user_id}`: Remove user from project membership (`admin` only).

### Findings & Triage
- `GET /api/findings`: List findings (strictly scoped to assigned projects for non-admins, and further scoped to authored code for developers).
- `GET /api/findings/{id}`: Get finding details (returns `403 Forbidden` if finding belongs to an unassigned project).
- `PATCH /api/findings/{id}/status`: Update triage status (enforces project and author access).
- `POST /api/findings/{id}/ticket`: Create Jira or Zammad ticket assigned directly to the author of the code.
- `POST /api/projects/{id}/auto-ticket`: Batch create and assign tickets directly to code authors for all vulnerabilities.
- `POST /api/findings/{id}/ai-remediation`: Generate AI root-cause analysis, secure code diff, and verification steps (enforces project and author access).
- `POST /api/findings/{id}/patch`: Auto-patch vulnerable source files with secure replacement code.
- `POST /api/findings/batch-patch`: Batch auto-patch multiple findings and files simultaneously with row-level security.
- `POST /api/findings/batch-pr`: Open a single coordinated Pull Request addressing multiple selected vulnerabilities.

### Custom Rules & SonarQube Catalog
- `GET /api/rules`: List custom rules (supports `?project_id={id}` to return project-specific rules plus global enterprise rules).
- `POST /api/rules`: Create custom rule with optional `project_id` scope.
- `GET /api/rules/file`: Retrieve `.sentinel/rules.yaml` content.
- `PUT /api/rules/file`: Update `.sentinel/rules.yaml` content with bidirectional DB synchronization.
- `GET /api/rules/open-community`: Query SonarQube RSpec rules and curated community rules.
- `POST /api/rules/generate`: Convert natural language into SAST/SCA rule YAML using LLM or semantic engine (supports optional `project_id`).
- `POST /api/rules/test`: Sandbox test bench for custom rules against code.

### User Management & RBAC (`admin` only)
- `GET /api/users`: List registered users with assigned roles and `assigned_projects` scope list.
- `POST /api/users`: Create user account with username, email, password, role, and assigned projects list.
- `GET /api/users/{id}`: Fetch user profile and project assignment memberships.
- `PUT /api/users/{id}`: Update user profile, password, role, and synchronize `assigned_projects`.
- `DELETE /api/users/{id}`: Permanently delete user and cascade-remove all project memberships.

### Supply Chain Topology & Dynamic Testing
- `POST /api/dast/audit`: Run dynamic security audit on live HTTP/HTTPS endpoints (HSTS, CSP, Clickjacking, Cookies, TLS).
- `GET /api/projects/{id}/dependencies/graph`: Interactive DAG representing topological dependency hierarchy and reachability.
- `GET /api/projects/{id}/dependencies/tree`: Hierarchical nested dependency tree with transitive blast radius metrics.
- `GET /api/projects/{id}/dependencies/blast-radius`: Quantitative downstream blast radius analysis and exposure paths.
- `GET /api/integrations/webhooks`: Retrieve Slack, Microsoft Teams, Discord, and Generic webhook configuration.
- `POST /api/integrations/webhooks`: Save webhook notification settings.
- `POST /api/integrations/webhooks/test`: Test live alert delivery to configured webhook channels.
- `GET /api/schedules`: List configured periodic automated repository scans and threat intel sync jobs.
- `POST /api/schedules`: Create or update automated scan schedules.
- `POST /api/threat-intel/sync`: On-demand synchronization of CISA Known Exploited Vulnerabilities and EPSS feeds.
- `GET /api/threat-intel/status`: Check current CISA KEV count and EPSS feed version.

### Conversational Security Copilot
- `POST /api/copilot/chat`: Context-aware conversational AI security copilot with real-time project telemetry, remediation diffs, and RBAC isolation.
- `GET /api/copilot/prompts`: Curated role-based and task-oriented prompt starters for rapid security posture assessment.

### Compliance Crosswalk & Governance
- `GET /api/compliance/matrix`: Enterprise regulatory compliance crosswalk matrix across SOC 2, ISO 27001, PCI-DSS, HIPAA, and NIST CSF.
- `GET /api/projects/{id}/compliance/matrix`: Project-specific regulatory compliance crosswalk matrix with control evaluations.
- `GET /api/projects/{id}/compliance/export/html`: Executive Compliance Crosswalk Dossier (print-ready HTML with cryptographic SHA-256 seal).
- `GET /api/standards`: Query compliance taxonomies and violation counts.
- `POST /api/ci/gate-check`: CI/CD Quality Gate evaluation (threat-informed pass/fail).

### Integrations & LLM Service
- `GET /api/integrations/llm`: Retrieve LLM integration configuration with secret masking.
- `POST /api/integrations/llm`: Save LLM provider, model, API keys, temperature, and feature toggles.
- `POST /api/integrations/llm/test`: Test live connectivity to configured LLM provider.

### Exporters & Downloads
- `GET /api/projects/{id}/export/{html|sarif|cyclonedx|csv|sonarqube|vex}`: Download multi-format security reports (enforces project assignment; `403 Forbidden` if unassigned).
- `GET /api/projects/{id}/compliance/export/html`: Download executive compliance crosswalk audit dossier.
- `GET /api/extension/download`: Download packaged VS Code / Antigravity IDE `.vsix` extension.
- `GET /api/benchmark`: Retrieve full head-to-head comparative benchmark report and operational KPIs.

---

## Industry Benchmark: Sentinel AppSec vs. SonarQube, Semgrep & OWASP Dependency-Check

> 📄 **Dedicated Comprehensive Benchmark Report**: For the complete empirical benchmark analysis, ASCII performance trajectories, and strategic migration matrices, see [BENCHMARK.md](file:///home/zeek/appsec/BENCHMARK.md).

### Executive Scorecard Summary

| Tool | Overall Score | Category & Primary Focus | Key Differentiator |
| :--- | :---: | :--- | :--- |
| **Sentinel AppSec** | **96 / 100** | **Unified SAST, SCA, Threat Prioritization, SonarQube Rules & AI Engine** | **EPSS Threat Prioritization, ISO 26262/MISRA Compliance, NL Rule Studio, Developer Isolation & AI Code Diffs** |
| **Semgrep (OSS / Pro)** | **78 / 100** | Semantic AST Pattern-Matching SAST & Supply Chain | Fast code-like semantic search; lacks native EPSS, developer isolation, or NL rule generation |
| **SonarQube** | **71 / 100** | Code Quality, Maintainability & Traditional SAST | Established code quality gates; heavy footprint, zero native SCA/SBOM, no EPSS, complex Java plugins |
| **OWASP Dependency-Check** | **52 / 100** | Open-Source Software Composition Analysis (SCA) | Free NVD CVE checker; zero SAST capability, high false positive CPE matching, no code remediation |

---

### Head-to-Head Capability Matrix

| Capability / Evaluation Criteria | Sentinel AppSec | Semgrep (OSS/Pro) | SonarQube | OWASP DepCheck |
| :--- | :--- | :--- | :--- | :--- |
| **Vulnerability Prioritization** | **EPSS + CVSS Matrix (72% Noise Reduction)** | CVSS Base Severity only | Static Severity / Quality Gate | CVSS Base Score only |
| **Action Quadrants & SLAs** | **4 Quadrants (Act Now, Critical Patch, Opportunistic, Routine)** | ❌ Static High/Med/Low | ❌ Blocker/Critical flags | ❌ Build threshold only |
| **SonarQube RSpec Compatibility** | **Native S2068, S5131, S2077, S4524, S5043, S5853** | ❌ None | ✔ Native standard | ❌ None |
| **Automotive Safety (ISO 26262 ASIL A-D)** | **Native ASIL-D rules & taxonomy tagger** | ❌ None | ⚠️ Commercial C/C++ partial | ❌ None (SCA only) |
| **Automotive Guidelines (MISRA C:2012 / AUTOSAR)** | **Native Rule 21.3 & determinism checks** | ❌ Community only | ⚠️ Commercial C/C++ edition | ❌ None (SCA only) |
| **Enterprise Standards (ISO 27001, ISO 27034, NIST)** | **12 Standards mapped automatically** | ⚠️ OWASP/CWE tags only | ⚠️ OWASP/CWE tags only | ⚠️ CWE tags only |
| **OpenChain (ISO/IEC 5230) License Auditing** | **Native license parser & compliance checks** | ⚠️ Paid Supply Chain only | ❌ Requires 3rd party plugin | ⚠️ Basic license parser |
| **Custom Rule Authoring Mode** | **Natural Language Prompts (LLM + AST Engine)** | Manual YAML patterns | Java AST plugins (Compile JAR) | Manual XML suppression |
| **Rule Creation Latency** | **< 10 Seconds (Prompt $\rightarrow$ YAML)** | 15 – 45 Minutes | 2 – 8 Hours | N/A (Cannot author code rules) |
| **In-Browser Rule Test Bench Sandbox** | **Built-in live code sandbox with highlights** | ⚠️ External web playground | ❌ Requires restart & rescan | ❌ None |
| **Live rules.yaml View & Editor** | **Real-time bidirectional DB & YAML sync** | ❌ File editing only | ❌ Server reboot needed | ❌ None |
| **Developer-Scoped Data Isolation (RBAC)** | **Strict Row-Level Isolation (Author-only)** | ❌ Global repo view / PR bot | ❌ Project-wide permissions | ❌ None |
| **Cross-Developer Tamper Guards** | **HTTP 403 Forbidden enforced at API level** | ❌ None | ❌ None | ❌ None |
| **Git Blame Line Attribution** | **Author, email, commit hash & date per finding** | ❌ Line numbers only | ⚠️ Author line gutter | ❌ None |
| **AI Root Cause & Exploit Mechanics** | **Multi-Provider LLM (OpenAI, Claude, Gemini, Ollama)** | ❌ Static rule description | ❌ Generic rule description | ❌ NVD advisory link |
| **Refactored Secure Code Diffs (Before/After)** | **Syntax-highlighted diff + 1-click Copy Fix** | ⚠️ Static regex autofix only | ❌ Vulnerable line snippet | ❌ None |
| **Automated Unit Test Suggestions** | **Negative edge-case assertions per finding** | ❌ None | ❌ None | ❌ None |
| **Unified Single-Pass SAST + SCA** | **Unified AST + Manifest scanner in single pass** | ❌ Separate products | ❌ SAST only | ❌ SCA only |
| **CycloneDX v1.5 SBOM Generation** | **Native JSON export with license disclosures** | ⚠️ Paid Supply Chain only | ❌ None | ❌ XML/CSV only |
| **SARIF v2.1.0 Standard Export** | **Native 1-click SARIF export** | ✔ Supported (`--sarif`) | ❌ Import only | ⚠️ Experimental |
| **SonarQube Generic Issue Export** | **Native export format for SonarScanner & CI** | ❌ None | ✔ Internal native | ❌ None |
| **Ticketing Connectors** | **Atlassian Jira + Zammad Helpdesk native API** | ⚠️ Paid Cloud Platform only | ⚠️ Community plugin needed | ❌ None |
| **Runtime Footprint & Startup** | **Lightweight (< 150MB RAM, boots in <1s)** | Lightweight (< 200MB RAM) | Heavy (> 2GB–4GB RAM, boots ~60s) | Heavy JVM + NVD download |

---

### Key Differentiators Deep-Dive

#### 1. EPSS Prioritization vs. Raw CVSS Alert Fatigue
- **The Industry Problem**: Legacy tools (SonarQube, DepCheck) alert on every CVE with a high CVSS score (e.g. CVSS 9.0+), creating hundreds of unmanageable tickets. Real-world threat research proves that **only 4% to 7% of published CVEs are ever weaponized or exploited in the wild**.
- **The Sentinel Advantage**: Ingests live EPSS (Exploit Prediction Scoring System) data from FIRST.org. Flaws with low exploit probability (< 0.20) are routed into **Critical Patch (14-day SLA)** or **Routine Backlog (90-day SLA)**, reducing active triage alert fatigue by **~72%**, while high-EPSS flaws are immediately escalated to **🚨 Act Now (24-48h SLA)**.

#### 2. Multi-Standard Compliance & Automotive Functional Safety
- **The Industry Problem**: SonarQube and Semgrep cater almost exclusively to general web development (OWASP Top 10), leaving automotive, avionics, and safety-critical embedded systems unaddressed unless expensive proprietary licenses are purchased.
- **The Sentinel Advantage**: Natively tags and audits against **ISO 26262-6 (ASIL A–D)**, **MISRA C:2012 / C++:2023**, **AUTOSAR C++14**, **ISO/SAE 21434**, and **ISO/IEC 27001:2022 (A.8.28)** out of the box, bridging software safety and enterprise cybersecurity.

#### 3. Natural Language Rule Studio vs. Complex Custom Authoring
- **SonarQube**: Requires developers to learn internal Java AST APIs, set up Maven/Gradle build chains, compile a `.jar`, restart the SonarQube server, and debug runtime exceptions (2–8 hours per rule).
- **Semgrep**: Requires mastering proprietary YAML syntax (`pattern-inside`, `pattern-either`, `metavariable-regex`).
- **Sentinel AppSec**: Security leads write plain human English (*"Disallow dynamic memory allocation malloc and calloc in safety-critical C code per MISRA C:2012 Rule 21.3"*). The LLM/AST engine synthesizes valid regex, extracts language targets, associates standards, and outputs ready-to-test YAML rules in **less than 10 seconds**.

#### 4. Dual-Layer Project Assignment & Developer-Scoped Isolation vs. Global Overexposure
- **Legacy Approach**: In SonarQube or Semgrep, permissions are typically coarse: any user added to a workspace can view all projects or every finding in a repository, leading to alert chaos, lack of accountability, and security boundary leaks.
- **The Sentinel Advantage**: Implements a defense-in-depth **Dual-Layer Isolation Model**:
  1. **Project Assignment Isolation**: Non-admin users (developers, security engineers, auditors) are strictly locked to their assigned projects. Unassigned projects, scans, findings, quality gates, custom rules, and export reports are completely inaccessible and return an enforced HTTP `403 Forbidden`.
  2. **Per-Line Git Blame Attribution**: Within an assigned project, developer views are further scoped to code authored by that specific engineer (`author_name`, `author_email`). A developer working on Project A only sees Project A, and within Project A only their own authored flaws.

#### 5. AI-Powered Refactoring Diffs vs. Static Advisory Links
- **Legacy Tools**: Point developers to generic CVE descriptions or external CWE definitions, leaving the engineer to research how to safely refactor the code.
- **Sentinel AppSec**: Injects the flagged code snippet, language, and standards violations into the LLM engine to generate **exact refactored code diffs** (parameterized queries, bounded buffers, safe deserialization), root-cause analysis, and specific unit test verification steps with a 1-click **"Copy Fix"** workflow.

---

> 📊 **Explore More**: Read the full empirical study and technical scorecard in [BENCHMARK.md](file:///home/zeek/appsec/BENCHMARK.md).
