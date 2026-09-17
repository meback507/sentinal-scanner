# AegisSec: Enterprise SAST & SCA Security Platform

**AegisSec** is a next-generation Application Security Testing (AST) platform unifying **Static Application Security Testing (SAST)** and **Software Composition Analysis (SCA)** into a centralized, modern web dashboard.

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

3. **Natural-Language Custom Rule Studio**:
   - Translates human English instructions into concrete SAST AST/pattern rules or SCA dependency policies.
   - Example prompts:
     - *"Disallow dynamic memory allocation malloc or free in C/C++ for MISRA compliance"*
     - *"Detect hardcoded API keys or JWT tokens in Python and JavaScript"*
     - *"Flag SQL injection via string concatenation in Python"*
     - *"Ban dependency package lodash below version 4.17.21 or any library with license AGPL-3.0"*
   - Built-in **Live Code Test Bench** to test synthesized rules against custom code snippets before activation.

4. **Git Repository Management with Personal Access Tokens (PAT)**:
   - Configurable remote Git repositories (GitHub, GitLab, Bitbucket, Azure DevOps, private Git servers).
   - Automated token encryption and credential masking in logs and output.
   - Shallow clone optimization (`--depth 1 --single-branch`) with workspace isolation.

5. **Ticketing Platform Connectors**:
   - **Atlassian Jira Cloud / Server**: Direct issue creation with vulnerability details, reproduction, priority mapping, code snippet context, and remediation guidance.
   - **Zammad Helpdesk**: Native REST API ticket creation and customer/group assignment.

6. **Multi-Format Security Exporters**:
   - **Executive HTML / PDF Report**: Comprehensive executive summaries, compliance impact, and remediation plan.
   - **SARIF v2.1.0 JSON**: OASIS standard format for GitHub Code Scanning, GitLab SAST, SonarQube, and IDE integration.
   - **CycloneDX v1.5 JSON**: Software Bill of Materials (SBOM) for component inventory and supply chain audits.
   - **CSV Tabular Export**: Direct export for spreadsheet analysis and tracker sync.

7. **Role-Based Access Control (RBAC)**:
   - `admin`: Full system control, integrations, custom rules, user management, and projects.
   - `security_engineer`: Project management, scans, custom rule generation, reports, and ticket dispatch.
   - `developer`: View projects, inspect vulnerability lines, mark false positives, review fixes.
   - `auditor`: Read-only compliance matrices, standards reports, and audit logs.

---

## Quick Start

### Option 1: Run Locally (Instant Start)
Execute the automated run script:
```bash
./run.sh
```
The server will boot at **`http://127.0.0.1:8000`**.

### Option 2: Run with Docker & Docker Compose
```bash
docker compose up --build
```
The containerized platform will be accessible on port 8000 with persistent data storage.

---

## Default RBAC Demo Credentials

| Role | Username | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Super Admin** | `admin` | `Admin@123!` | Full administrative & system access |
| **Security Lead** | `sec_lead` | `SecLead@123!` | Scans, custom rules, ticket dispatch, projects |
| **Developer** | `developer` | `Dev@123!` | Triage, false-positive flagging, code inspection |
| **Auditor** | `auditor` | `Auditor@123!` | Read-only compliance inspection & report exports |

*Note: You can instantly switch active roles using the top/sidebar role switcher in the UI.*

---

## Running Automated Tests

Run the full verification test suite:
```bash
.venv/bin/python3 -m unittest discover -s tests -v
```

---

## REST API Overview

- `POST /api/auth/login`: Authenticate and receive JWT token.
- `GET /api/projects`: List all configured projects and security posture.
- `POST /api/projects`: Create project with Git repository and PAT credentials.
- `DELETE /api/projects/{id}`: Permanently delete project with cascading data cleanup.
- `POST /api/projects/{id}/scan`: Trigger on-demand SAST & SCA scan.
- `GET /api/findings`: List findings with multi-dimensional filtering.
- `PATCH /api/findings/{id}/status`: Update triage status.
- `POST /api/findings/{id}/ticket`: Create Jira or Zammad ticket.
- `POST /api/rules/generate`: Convert natural language into SAST/SCA rule YAML.
- `POST /api/rules/test`: Sandbox test bench for custom rules against code.
- `GET /api/standards`: Query compliance taxonomies and violation counts.
- `GET /api/projects/{id}/export/{html|sarif|cyclonedx|csv}`: Download reports.
