# 🛡️ ThreatGate: System Architecture Specification
**Document Version:** `1.0.0-RELEASE`  
**Classification:** `Core System Architecture & Component Design`  
**Status:** `Approved for Implementation`  
**Target Lifecycle:** `Developer ➔ Code ➔ Threat Model Tool ➔ Status Artifact ➔ Git ➔ PR (Code + Status) ➔ PR Approved`

---

## 1. Executive Summary & Core Paradigm

**ThreatGate** is an automated, code-first threat modeling and continuous governance engine. It solves the historic disconnect in Application Security (AppSec) between high-level architectural threat modeling (STRIDE) and low-level source code pull requests.

### Core Value Propositions
* **Shift-Left Upfront:** Architectural STRIDE analysis is performed on the developer's workstation *before* or *at the point of* git commit.
* **Actionable Remediation:** The tool does not simply flag threats; it outputs syntactically valid, drop-in replacement code fixes.
* **Component-Scoped Scoping:** Threat models are co-located with source code (`<name>.threat.md`), eliminating Git merge conflicts across concurrent feature branches.
* **Cryptographic Non-Repudiation:** Status artifacts are sealed using asymmetric **Ed25519** digital signatures, preventing local tampering or forgery.
* **Two-Speed CI/CD Pipeline:** CI/CD pipelines validate signatures in $< 5\text{ seconds}$ using public keys, reserving LLM compute strictly for developer workflows or unverified fallbacks.

---

## 2. Master System Architecture Diagram

```mermaid
flowchart TD
    %% Subgraphs
    subgraph Layer1["1. Developer Workspace (Local Desktop)"]
        Dev["Developer"]
        Code["Source Code / Feature Branch<br/>(e.g., src/payments/refund.py)"]
        PreCommitHook["Git Pre-Commit Hook / CLI<br/>(threatgate scan)"]
    end

    subgraph Layer2["2. Hybrid Threat Modeling Engine (The Brain)"]
        ASTTriage["AST Triage & Cache Layer<br/>(Skips non-code & checks AST cache)"]
        ProviderSwitch{"LLM Provider Switch"}
        CloudLLM["Cloud Engine (Gemini 2.5 Flash)<br/>High Reasoning / Low Latency"]
        LocalLLM["Local Engine (Ollama / vLLM)<br/>Air-Gapped / Zero Data Egress"]
        DualAgent["Dual-Agent Consensus Logic<br/>• Threat Hunter: Finds STRIDE vectors<br/>• Security Critic: Prunes false positives (Semgrep)"]
        FixGenerator["In-Line Code Fix Generator<br/>(Generates Before/After secure diffs)"]
    end

    subgraph Layer3["3. Cryptographic Stamping Engine"]
        Ed25519Signer["Asymmetric Signer (Ed25519)<br/>Uses Private Key"]
        ScopedArtifact["Status Artifact Generated:<br/>src/payments/refund.threat.md (Status: APPROVED ✅)"]
        AutoTestGen["Threat-to-Test Generator<br/>tests/security/test_threat_01.py"]
    end

    subgraph Layer4["4. Git Remote & Pull Request (Co-Versioning)"]
        GitCommit["git commit & push<br/>Files: [Code + refund.threat.md + test.py]"]
        PR["Pull Request Raised"]
        FastCI["CI Fast-Path Gatekeeper<br/>• Verifies Ed25519 Public Key (< 2s)<br/>• Executes Threat Regression Tests"]
        DeltaBot["Threat Delta PR Commenter<br/>(Posts concise &Delta; summary)"]
    end

    subgraph Layer5["5. Reviewer Verification & Governance Gate"]
        Reviewer["Peer Reviewer / Security Champion<br/>(30-Second Delta Review)"]
        SlashCmd["ChatOps / Slash Commands<br/>(/threat-accept for approved edge cases)"]
        BranchGate["Branch Protection Rules<br/>(Enforces Status Check: APPROVED)"]
    end

    subgraph Layer6["6. Post-Merge Living Threat Model"]
        MergeToMain["PR Merged into Main ✅"]
        LivingReconciler["Post-Merge Reconciler<br/>(Updates root SYSTEM_THREAT_MODEL.md)"]
        AuditLedger[("Immutable Audit Ledger<br/>(SOC2 / ISO 27001 / PCI-DSS 4.0)")]
    end

    %% Data Flows
    Dev -->|"Writes"| Code
    Code -->|"Triggers git commit"| PreCommitHook
    PreCommitHook --> ASTTriage
    ASTTriage --> ProviderSwitch
    ProviderSwitch -->|"Cloud Route"| CloudLLM
    ProviderSwitch -->|"Air-Gapped Route"| LocalLLM
    CloudLLM --> DualAgent
    LocalLLM --> DualAgent

    DualAgent -->|"If flaws exist: Halts commit"| FixGenerator
    FixGenerator -->|"Returns actionable code fix"| Dev

    DualAgent -->|"If clean / mitigated"| Ed25519Signer
    DualAgent -->|"Auto-Generates"| AutoTestGen
    Ed25519Signer --> ScopedArtifact

    ScopedArtifact --> GitCommit
    AutoTestGen --> GitCommit
    Code --> GitCommit

    GitCommit -->|"git push"| PR
    PR --> FastCI
    PR --> DeltaBot

    FastCI -->|"Seal Valid"| BranchGate
    DeltaBot --> Reviewer
    Reviewer -.->|"Optional override"| SlashCmd
    SlashCmd --> BranchGate
    Reviewer -->|"Approves PR"| BranchGate

    BranchGate --> MergeToMain
    MergeToMain --> LivingReconciler
    LivingReconciler --> AuditLedger
```

---

## 3. End-to-End Sequence Map

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant Tool as ThreatGate CLI
    participant Git as Local Git (.git)
    participant PR as Remote PR (GitHub/GitLab)
    participant CI as CI Fast-Path Verifier (< 5s)
    actor Reviewer as Security Champion

    Dev->>Git: 1. git commit -m "feat: payment refund"
    Git->>Tool: 2. Pre-commit hook triggers scan
    activate Tool
    
    Tool->>Tool: Evaluates STRIDE threats & trust boundaries
    alt Flaws Detected (e.g., IDOR/BOLA found)
        Tool-->>Dev: ❌ STATUS: ACTION REQUIRED<br/>Prints Before/After code replacement
        Note over Dev: Dev applies recommended fix<br/>and re-commits
    end

    Tool->>Tool: Verifies all threats mitigated
    Tool->>Tool: Signs code + report with Ed25519 Private Key
    Tool->>Git: 3. Writes refund.threat.md & test_threat_*.py
    Tool-->>Git: Stages files into current commit
    deactivate Tool

    Dev->>PR: 4. git push & open PR (Code + refund.threat.md + test.py)

    activate CI
    PR->>CI: 5. Runs verify-pr CI Job
    CI->>CI: Confirms Ed25519 Seal with Public Key (< 2s)
    CI->>CI: Runs pytest tests/security/
    CI-->>PR: Status Check: "ThreatGate: APPROVED ✅"
    deactivate CI

    PR->>PR: 6. Posts Threat Delta summary comment
    Reviewer->>PR: 7. Inspects code diff + Threat Delta (30s)
    Reviewer->>PR: 8. Clicks "Approve PR"
    PR->>PR: 9. Merges into main branch
```

---

## 4. Layer-by-Layer Architectural Specifications

### Layer 1: Developer Workspace (Client Tier)
* **Trigger Mechanism:** Runs automatically via `.git/hooks/pre-commit` or on-demand via `threatgate scan -p <file>`.
* **Zero Disruption:** Executes on staged files in the developer's local shell. If code is clean, it auto-stages the generated `.threat.md` without requiring manual secondary commits.

### Layer 2: Hybrid Reasoning Engine (Inference Tier)
* **AST Pre-Filter:** Parses file syntax trees using Tree-sitter or Python `ast` to strip comments and whitespaces. If the AST hash matches an existing cached verdict, it returns an approval in $< 20\text{ ms}$.
* **Dual-Agent Architecture:**
  * **Threat Hunter Agent:** Dissects entry points, privilege transitions, and persistence sinks to formulate STRIDE threats.
  * **Security Critic Agent:** Uses deterministic Semgrep taint-flow analysis to prune false positives caused by upstream framework middleware.
* **Provider Routing:** Abstracted client supporting both commercial cloud APIs (`gemini-2.5-flash`) and local air-gapped endpoints (`ollama/qwen2.5-coder`).

### Layer 3: Cryptographic Stamping Engine
* **Algorithm:** Pure Ed25519 (RFC 8032) asymmetric digital signatures.
* **Key Architecture:**
  * **Private Key:** Stored strictly in developer `.env` or internal KMS. Never committed.
  * **Public Key:** Committed to the repository at `.threatmodel/public_key.pem`.
* **Mathematical Binding:**
  $$\text{CodeDigest} = \text{SHA256}(\text{CodeContent}_{\text{normalized}})$$
  $$\text{DigitalSeal} = \text{Sign}_{\text{Ed25519PrivKey}}(\text{CodeDigest} \parallel \text{ReportContent}_{\text{normalized}})$$

### Layer 4: Git Co-Versioning Tier
* **Component-Scoped Paths:** Threat models are named `<filename>.threat.md` and live in the same directory as the source code.
  * *Benefit:* Eliminates Git merge conflicts between parallel feature branches.
* **Threat-to-Test Durability:** The tool auto-generates a companion regression unit test in `tests/security/test_threat_<id>.py`. If a future developer removes the security check, standard unit testing immediately fails.

### Layer 5: Reviewer Verification & Governance Gate
* **Threat Delta ($\Delta$):** The PR bot calculates what changed between `main` and the branch, posting a high-contrast 4-line summary showing neutralized threats, new trust boundaries, and open risks.
* **Reviewer Efficiency:** Peer reviewers and Security Champions can verify security intent in under 30 seconds.
* **Break-Glass Overrides:** Reviewers can accept edge-case risks via PR slash commands:
  `/threat-accept TH-01 reason="Protected by upstream Cloudflare WAF"`

### Layer 6: Post-Merge Living Threat Model & Audit Ledger
* **Continuous Synchronization:** A GitHub Action running on `push: [main]` parses merged `.threat.md` files and updates the root `SYSTEM_THREAT_MODEL.md`.
* **Audit Trail:** Appends an entry to `.threatmodel/audit_ledger.jsonl`, providing permanent evidence for compliance audits.

---

## 5. Two-Speed CI/CD Pipeline Architecture

```mermaid
flowchart TD
    PRPush["Developer Pushes to PR"] 
    --> CheckSeal{"Is Ed25519 Seal present & valid?<br/>(Checks .threatmodel/public_key.pem)"}

    %% FAST PATH (Normal Operation)
    CheckSeal -->|"YES (Seal Valid)"| FastPath["⚡ FAST PATH (< 5 seconds)<br/>• Verifies Ed25519 public key signature<br/>• Runs pytest tests/security/<br/>• ZERO LLM calls, $0 token cost"]
    FastPath --> PassStatus["PR Status Check: PASSED ✅<br/>(Merge button unlocks)"]

    %% FALLBACK PATH (Edge Case)
    CheckSeal -->|"NO (Missing / Tampered / --no-verify)"| FallbackPath["🔄 FALLBACK PATH (~25 seconds)<br/>• CI invokes Threat Engine on PR Diff<br/>• Evaluates threats & signs fallback report<br/>• Flags manual AppSec review"]
    FallbackPath --> FailStatus["PR Status Check: ACTION REQUIRED ⚠️<br/>(Merge button locked)"]
```

---

## 6. Comparison with Existing Industry Tools

| Dimension | Traditional Tools (IriusRisk, MS TMT) | SAST Scanners (Snyk, Semgrep, CodeQL) | **ThreatGate Architecture** |
| :--- | :--- | :--- | :--- |
| **Input** | Manual architecture diagrams & forms | Source code syntax & regex | **Source code & Git diffs** |
| **Scope** | High-level system design (disconnected from code) | Low-level syntax bugs / CVEs | **Architectural STRIDE flaws & trust boundaries** |
| **Timing** | Design phase (months before release) | CI/CD build or IDE typing | **Upfront at commit + Verified on PR** |
| **Remediation** | Text recommendations only | Basic quick-fixes for syntax bugs | **Full Before/After secure code replacements** |
| **Git Coupling** | Disconnected (stored in external DBs) | PR inline comments | **Co-committed `<name>.threat.md` in Git** |
| **Merge Safety** | N/A (Central tool) | N/A (Stateless) | **Component-scoped (Zero merge conflicts)** |
| **Integrity** | Unenforced | Fails build | **Cryptographic Ed25519 Digital Seal** |
| **Reviewer Gate** | Manual Jira tickets | Static alerts | **PR-native review of Code + Status together** |

---

## 7. Compliance Crosswalk (SOC2, PCI-DSS 4.0, ISO 27001)

| Standard | Control Reference | Requirement | How ThreatGate Satisfies It |
| :--- | :--- | :--- | :--- |
| **PCI-DSS v4.0** | **Req 6.2.3** | Threat modeling required for significant architectural changes. | Every PR touching business logic co-commits a verified `.threat.md`. |
| **PCI-DSS v4.0** | **Req 6.3.2** | Software vulnerabilities must be verified prior to release. | CI fails build if Ed25519 signature is missing, invalid, or tampered. |
| **SOC 2 Type II** | **CC7.1 / CC7.2** | System changes are authorized, designed, and tested prior to production. | PR history proves peer sign-off of code + threat models side-by-side. |
| **ISO/IEC 27001** | **Control A.8.25** | Secure system development lifecycle rules must be enforced. | Pre-commit hook enforces automated STRIDE evaluations by default. |

