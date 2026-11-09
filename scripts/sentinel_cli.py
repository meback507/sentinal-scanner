#!/usr/bin/env python3
"""
Sentinel Scanner CLI - Developer Shift-Left Security Tool
Enforces pre-commit security gates and executes local SAST, Secrets, IaC, and API security audits.
"""

import os
import sys
import argparse

# Add repo root to path so backend scanners can be imported cleanly
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Auto-detect local virtualenv site-packages if running with system python
venv_base = os.path.join(REPO_ROOT, ".venv", "lib")
if os.path.isdir(venv_base):
    for entry in os.listdir(venv_base):
        site_pkg = os.path.join(venv_base, entry, "site-packages")
        if os.path.isdir(site_pkg) and site_pkg not in sys.path:
            sys.path.insert(0, site_pkg)

from backend.scanners.sast_engine import SASTEngine
from backend.scanners.secret_scanner import SecretScanner
from backend.scanners.iac_engine import IaCEngine
from backend.scanners.api_sec_engine import APISecEngine
from backend.prioritization.cisa_service import cisa_service
from backend.rules.rule_manager import rule_manager
import json

# ThreatGate Code-First Threat Modeling & Cryptographic Engine
try:
    from src.threatgate.core.engine import ThreatEngine
    from src.threatgate.core.crypto import (
        generate_keypair, sign_payload, verify_payload,
        extract_seal_from_markdown, embed_seal_into_markdown
    )
    from src.threatgate.core.delta import compute_delta, format_delta_summary
    from src.threatgate.core.test_gen import generate_security_regression_test
    THREATGATE_AVAILABLE = True
except Exception:
    THREATGATE_AVAILABLE = False


# ANSI Color Codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[91m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_GREEN = "\033[92m"
CLR_MAGENTA = "\033[95m"
CLR_CYAN = "\033[96m"


def print_banner():
    print(rf"""{CLR_CYAN}{CLR_BOLD}
   ___             __   _             __   ____                                 
  / _ \___ ___ ___/ /  (_)__  ___ _  / /  / __/______ ____  ___  ___ ____      
 / // / -_) -_) _  /  / / _ \/ _ `/ / /___\ \/ __/ _ `/ _ \/ _ \/ -_) __/      
/____/\__/\__/\_,_/  /_/_//_/\_, / /____/___/\__/\_,_/_//_/_//_/\__/_/         
                            /___/                                               
       --- Enterprise Shift-Left AST & Pre-Commit Shield ---{CLR_RESET}
""")


def list_rules(target_path: str = ".", output_json: bool = False) -> int:
    target_path = os.path.abspath(target_path)
    catalog = rule_manager.get_complete_rule_catalog(target_path)

    if output_json:
        print(json.dumps(catalog, indent=2))
        return 0

    summary = catalog["summary"]
    print(f"{CLR_BOLD}Active Security Rules Catalog:{CLR_RESET} {summary['total_active_rules']} total active rules")
    print(f"  • {CLR_CYAN}Built-in SAST:{CLR_RESET} {summary.get('sast_builtin', 0)}")
    print(f"  • {CLR_CYAN}Built-in IaC & Containers:{CLR_RESET} {summary.get('iac_builtin', 0)}")
    print(f"  • {CLR_CYAN}Built-in API Security:{CLR_RESET} {summary.get('api_builtin', 0)}")
    print(f"  • {CLR_MAGENTA}SonarQube RSPEC Rules:{CLR_RESET} {summary.get('sonarqube_rules', 0)}")
    print(f"  • {CLR_BLUE}Open Community Database:{CLR_RESET} {summary.get('open_database_rules', 0)}")
    print(f"  • {CLR_YELLOW}Platform Custom (DB):{CLR_RESET} {summary.get('platform_custom', 0)}")
    print(f"  • {CLR_GREEN}Project Custom (.sentinel/rules.yaml):{CLR_RESET} {summary.get('project_custom', 0)}\n")

    print(f"{CLR_BOLD}{'ID':<18} {'TYPE':<8} {'SEV':<10} {'TITLE'}{CLR_RESET}")
    print("-" * 80)

    # 1. Project Custom Rules
    if catalog["rules"]["project_custom"]:
        print(f"{CLR_GREEN}{CLR_BOLD}--- Project Custom Rules ({len(catalog['rules']['project_custom'])}) ---{CLR_RESET}")
        for r in catalog["rules"]["project_custom"]:
            sev = r.get("severity", "HIGH")
            color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else CLR_BLUE)
            print(f"{CLR_GREEN}{r['id']:<18}{CLR_RESET} {r.get('type', 'sast').upper():<8} {color}{sev:<10}{CLR_RESET} {r.get('name', '')[:40]}")

    # 2. Platform Custom Rules
    if catalog["rules"]["platform_custom"]:
        print(f"\n{CLR_YELLOW}{CLR_BOLD}--- Platform Custom Rules ({len(catalog['rules']['platform_custom'])}) ---{CLR_RESET}")
        for r in catalog["rules"]["platform_custom"]:
            sev = r.get("severity", "HIGH")
            color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else CLR_BLUE)
            print(f"{CLR_YELLOW}{r.get('id', ''):<18}{CLR_RESET} {r.get('rule_category', 'sast').upper():<8} {color}{sev:<10}{CLR_RESET} {r.get('name', '')[:40]}")

    # 3. SonarQube RSPEC Rules
    if catalog["rules"].get("sonarqube_rules"):
        print(f"\n{CLR_MAGENTA}{CLR_BOLD}--- SonarQube RSPEC Rules ({len(catalog['rules']['sonarqube_rules'])}) ---{CLR_RESET}")
        for r in catalog["rules"]["sonarqube_rules"][:10]:
            sev = r.get("severity", "HIGH")
            color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else CLR_BLUE)
            sonar_key = r.get("sonar_key", "")
            print(f"{CLR_MAGENTA}{r['id']:<18}{CLR_RESET} {'SONAR':<8} {color}{sev:<10}{CLR_RESET} [{sonar_key}] {r.get('name', '')[:38]}")
        if len(catalog["rules"]["sonarqube_rules"]) > 10:
            print(f"  ... and {len(catalog['rules']['sonarqube_rules']) - 10} more active SonarQube RSPEC rules")

    # 4. Built-in SAST
    print(f"\n{CLR_CYAN}{CLR_BOLD}--- Built-in SAST Rules ({len(catalog['rules']['sast_builtin'])}) ---{CLR_RESET}")
    for r in catalog["rules"]["sast_builtin"]:
        print(f"{r['id']:<18} {'SAST':<8} {'HIGH':<10} {r.get('name', '')[:45]}")

    # 5. Built-in IaC
    print(f"\n{CLR_CYAN}{CLR_BOLD}--- Built-in IaC & Container Rules ({len(catalog['rules']['iac_builtin'])}) ---{CLR_RESET}")
    for r in catalog["rules"]["iac_builtin"]:
        sev = r.get("severity", "HIGH")
        color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else CLR_BLUE)
        print(f"{r['id']:<18} {'IAC':<8} {color}{sev:<10}{CLR_RESET} {r.get('name', '')[:45]}")

    print("\n" + "=" * 80 + "\n")
    return 0


def run_scan(target_path: str, fail_on: str = "HIGH", output_json: bool = False, custom_rules_file: str = None, sonar_export: str = None) -> int:
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        if output_json:
            print(json.dumps({"error": f"Target path '{target_path}' does not exist."}))
        else:
            print(f"{CLR_RED}Error: Target path '{target_path}' does not exist.{CLR_RESET}")
        return 1

    if not output_json:
        print(f"{CLR_BOLD}Target Directory:{CLR_RESET} {target_path}")
        print(f"{CLR_BOLD}Scanning engines:{CLR_RESET} SAST (Built-in + SonarQube RSPEC), High-Entropy Secrets, IaC/Containers, OpenAPI Specs\n")

    all_findings = []

    # 1. Secrets
    secret_scanner = SecretScanner()
    secrets = secret_scanner.scan_directory(target_path)
    all_findings.extend(secrets)

    # 2. SAST (with SonarQube rules loaded automatically)
    sast = SASTEngine()
    sast_res = sast.scan_directory(target_path)
    all_findings.extend(sast_res)

    # 3. IaC & Containers
    iac = IaCEngine()
    iac_res = iac.scan_directory(target_path)
    all_findings.extend(iac_res)

    # 4. OpenAPI / Swagger
    api_scanner = APISecEngine()
    api_res = api_scanner.scan_directory(target_path)
    all_findings.extend(api_res)

    # Enrich with CISA KEV
    for f in all_findings:
        cisa_service.enrich_finding_with_cisa_kev(f)

    # Export to SonarQube Generic Issue JSON if requested
    if sonar_export:
        try:
            from backend.exporters.report_generator import ReportGenerator
            proj_info = {"name": os.path.basename(target_path) or "appsec"}
            sonar_json = ReportGenerator.generate_sonarqube_generic_issues(proj_info, None, all_findings)
            out_file = os.path.abspath(sonar_export)
            os.makedirs(os.path.dirname(out_file), exist_ok=True) if os.path.dirname(out_file) else None
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(sonar_json)
            if not output_json:
                print(f"{CLR_GREEN}{CLR_BOLD}✔ Exported SonarQube Generic Issue Report:{CLR_RESET} {out_file} ({len(all_findings)} issues)")
        except Exception as e:
            if not output_json:
                print(f"{CLR_YELLOW}Warning exporting SonarQube report: {e}{CLR_RESET}")

    if output_json:
        print(json.dumps(all_findings, indent=2))
        return 0

    # Render results
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    fail_threshold = severity_order.get(fail_on.upper(), 3)

    crit_cnt = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_cnt = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    med_cnt = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
    low_cnt = sum(1 for f in all_findings if f.get("severity") == "LOW")

    if not all_findings:
        print(f"{CLR_GREEN}{CLR_BOLD}✔ CLEAN REPOSITORY: No security vulnerabilities or leaked secrets detected!{CLR_RESET}\n")
        return 0

    print(f"{CLR_BOLD}{'SEV':<10} {'TYPE':<8} {'FILE:LINE':<35} {'TITLE'}{CLR_RESET}")
    print("-" * 90)

    for f in all_findings:
        sev = f.get("severity", "LOW")
        ftype = f.get("type", "sast").upper()
        fpath = f.get("file_path", "")
        line = f.get("line_start", 1)
        loc = f"{fpath}:{line}"
        if len(loc) > 33:
            loc = "..." + loc[-30:]

        title = f.get("title", "")
        if f.get("sonar_key"):
            title = f"[{f.get('sonar_key')}] {title}"
        if f.get("cisa_kev"):
            title = f"[🚨 CISA KEV] {title}"

        color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else (CLR_BLUE if sev == "MEDIUM" else CLR_GREEN))
        print(f"{color}{sev:<10}{CLR_RESET} {ftype:<8} {loc:<35} {title[:40]}")

    print("-" * 90)
    print(f"Summary: {CLR_RED}{crit_cnt} Critical{CLR_RESET} | {CLR_YELLOW}{high_cnt} High{CLR_RESET} | {CLR_BLUE}{med_cnt} Medium{CLR_RESET} | {CLR_GREEN}{low_cnt} Low{CLR_RESET}\n")

    failing_findings = [f for f in all_findings if severity_order.get(f.get("severity", "LOW"), 1) >= fail_threshold]
    if failing_findings:
        print(f"{CLR_RED}{CLR_BOLD}❌ PRE-COMMIT SECURITY GATE FAILED:{CLR_RESET} Detected {len(failing_findings)} violation(s) at or above {fail_on.upper()} threshold.")
        print("Please resolve or remediate these security defects before committing code.\n")
        return 1
    else:
        print(f"{CLR_GREEN}✔ Security Gate PASSED: No violations exceeding threshold '{fail_on.upper()}'.{CLR_RESET}\n")
        return 0


def init_sonar(target_path: str = ".", project_key: str = None) -> int:
    """
    Initializes SonarQube integration by creating sonar-project.properties and GitHub Actions CI workflow.
    """
    target_path = os.path.abspath(target_path)
    if not os.path.isdir(target_path):
        print(f"{CLR_RED}Error: '{target_path}' is not a valid directory.{CLR_RESET}")
        return 1

    from backend.exporters.report_generator import ReportGenerator

    folder_name = os.path.basename(target_path) or "appsec-project"
    pk = project_key or folder_name.lower().replace(" ", "-")

    proj_meta = {
        "name": folder_name,
        "git_branch": "main"
    }

    # 1. Write sonar-project.properties
    props_content = ReportGenerator.generate_sonar_project_properties(proj_meta)
    props_path = os.path.join(target_path, "sonar-project.properties")
    with open(props_path, "w", encoding="utf-8") as f:
        f.write(props_content)

    # 2. Write GitHub Actions workflow
    workflows_dir = os.path.join(target_path, ".github", "workflows")
    os.makedirs(workflows_dir, exist_ok=True)
    workflow_path = os.path.join(workflows_dir, "sonar-sast.yml")
    workflow_content = ReportGenerator.generate_github_actions_sonar_workflow(proj_meta)
    with open(workflow_path, "w", encoding="utf-8") as f:
        f.write(workflow_content)

    print(f"{CLR_GREEN}{CLR_BOLD}✔ SonarQube Integration Configured Successfully!{CLR_RESET}")
    print(f"  • Generated: {CLR_CYAN}{props_path}{CLR_RESET}")
    print(f"  • Generated: {CLR_CYAN}{workflow_path}{CLR_RESET}\n")
    print(f"{CLR_BOLD}Next steps:{CLR_RESET}")
    print(f"  1. Run audit & export to SonarQube format:")
    print(f"     {CLR_YELLOW}sentinel-cli scan . --sonar-export sonar-issues.json{CLR_RESET}")
    print(f"  2. Run SonarScanner locally or push to trigger GitHub Actions:")
    print(f"     {CLR_YELLOW}sonar-scanner -Dsonar.projectKey={pk} -Dsonar.externalIssuesReportPaths=sonar-issues.json{CLR_RESET}\n")
    return 0


def run_threat_model(target_file, sign=True, key_path=None, test_gen=True):
    if not THREATGATE_AVAILABLE:
        print(f"{CLR_RED}Error: ThreatGate module not available. Install requirements.{CLR_RESET}")
        return 1
    if not os.path.isfile(target_file):
        print(f"{CLR_RED}Error: File not found: {target_file}{CLR_RESET}")
        return 1

    with open(target_file, "r", encoding="utf-8") as f:
        code_content = f.read()

    engine = ThreatEngine()
    print(f"{CLR_BOLD}Evaluating STRIDE threats for:{CLR_RESET} {target_file}")
    report = engine.evaluate_code(target_file, code_content)

    status_label = f"{CLR_GREEN}APPROVED ✔{CLR_RESET}" if report.is_approved else f"{CLR_RED}ACTION REQUIRED ✖{CLR_RESET}"
    print(f"\n{CLR_BOLD}Verdict:{CLR_RESET} {status_label}")
    print(f"{CLR_BOLD}Summary:{CLR_RESET} {report.summary}")

    print(f"\n{CLR_BOLD}STRIDE Threats Matrix:{CLR_RESET}")
    for t in report.threats:
        st_icon = f"{CLR_GREEN}✔ Mitigated{CLR_RESET}" if t.is_mitigated else f"{CLR_RED}✖ {t.severity.value}{CLR_RESET}"
        print(f"  • [{t.id}] {t.stride_category.value:22} | {t.target_element:20} | {st_icon}")

    if report.dfd_mermaid:
        print(f"\n{CLR_CYAN}{CLR_BOLD}Mermaid Data Flow Diagram (DFD Level-1):{CLR_RESET}")
        print(report.dfd_mermaid)

    if not report.is_approved:
        print(f"\n{CLR_RED}{CLR_BOLD}✖ ACTION REQUIRED:{CLR_RESET} High/Critical threats detected. Fix code before sealing.")
        return 1

    if sign:
        key_file = key_path or os.path.join(REPO_ROOT, ".threatmodel", "private_key.pem")
        if not os.path.exists(key_file):
            print(f"{CLR_YELLOW}Initializing Ed25519 keypair in .threatmodel/...{CLR_RESET}")
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            priv_pem, pub_pem = generate_keypair()
            with open(key_file, "wb") as f: f.write(priv_pem)
            with open(os.path.join(os.path.dirname(key_file), "public_key.pem"), "wb") as f: f.write(pub_pem)

        with open(key_file, "rb") as f: priv_pem = f.read()
        report_body = engine.format_threat_model_markdown(target_file, report, code_content, digital_seal=None)
        seal = sign_payload(code_content, report_body, priv_pem)
        out_file = os.path.splitext(target_file)[0] + ".threat.md"
        full_md = engine.format_threat_model_markdown(target_file, report, code_content, digital_seal=seal)
        with open(out_file, "w", encoding="utf-8") as f: f.write(full_md)
        print(f"\n{CLR_GREEN}✔ Component Threat Model Sealed:{CLR_RESET} {out_file}")
        print(f"  • Ed25519 Seal: {seal[:24]}...")

        if test_gen:
            mitigated = [t for t in report.threats if t.is_mitigated]
            if mitigated:
                t_path = generate_security_regression_test(mitigated[0])
                print(f"{CLR_GREEN}✔ Security Regression Test Generated:{CLR_RESET} {t_path}")
    return 0


def run_verify_pr(pub_key_path=None):
    if not THREATGATE_AVAILABLE:
        print(f"{CLR_RED}Error: ThreatGate module not available.{CLR_RESET}")
        return 1
    pub_file = pub_key_path or os.path.join(REPO_ROOT, ".threatmodel", "public_key.pem")
    if not os.path.exists(pub_file):
        print(f"{CLR_RED}Error: Public key not found: {pub_file}{CLR_RESET}")
        return 1
    with open(pub_file, "rb") as f: pub_pem = f.read()

    threat_files = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "build", "dist")]
        for f in files:
            if f.endswith(".threat.md"):
                threat_files.append(os.path.join(root, f))

    if not threat_files:
        print(f"{CLR_YELLOW}No *.threat.md files found in repository to verify.{CLR_RESET}")
        return 0

    print(f"{CLR_CYAN}{CLR_BOLD}⚡ ThreatGate Fast-Path CI Verification ({len(threat_files)} components)...{CLR_RESET}")
    all_valid = True
    for tf in threat_files:
        base_no_ext = tf[:-len(".threat.md")]
        code_file = base_no_ext + ".py"
        if not os.path.exists(code_file):
            for ext in (".js", ".ts", ".go", ".java", ".c", ".cpp"):
                if os.path.exists(base_no_ext + ext):
                    code_file = base_no_ext + ext
                    break
        if not os.path.exists(code_file):
            continue
        with open(code_file, "r", encoding="utf-8") as f: c_code = f.read()
        with open(tf, "r", encoding="utf-8") as f: t_rep = f.read()
        body, seal = extract_seal_from_markdown(t_rep)
        if not seal:
            print(f"  {CLR_RED}✖ {code_file}: Missing Ed25519 Seal{CLR_RESET}")
            all_valid = False
            continue
        if verify_payload(c_code, body, seal, pub_pem):
            print(f"  {CLR_GREEN}✔ {code_file}: Ed25519 Seal VERIFIED{CLR_RESET}")
        else:
            print(f"  {CLR_RED}✖ {code_file}: TAMPERED / DRIFTED (Signature mismatch!){CLR_RESET}")
            all_valid = False

    if not all_valid:
        print(f"\n{CLR_RED}{CLR_BOLD}✖ ThreatGate CI Gate: FAILED (Code drifted or seals invalid){CLR_RESET}")
        return 1
    print(f"\n{CLR_GREEN}{CLR_BOLD}✔ ThreatGate CI Gate: APPROVED (All components verified){CLR_RESET}")
    return 0


def run_threat_graph(target_file):
    if not THREATGATE_AVAILABLE:
        print(f"{CLR_RED}Error: ThreatGate module not available.{CLR_RESET}")
        return 1
    if not os.path.isfile(target_file):
        print(f"{CLR_RED}Error: File not found: {target_file}{CLR_RESET}")
        return 1
    with open(target_file, "r", encoding="utf-8") as f: code = f.read()
    engine = ThreatEngine()
    rep = engine.evaluate_code(target_file, code)
    print(rep.dfd_mermaid or "graph LR\nClient --> Controller --> DataStore")
    return 0


def run_init_keys(out_dir=".threatmodel"):
    if not THREATGATE_AVAILABLE:
        print(f"{CLR_RED}Error: ThreatGate module not available.{CLR_RESET}")
        return 1
    target = os.path.join(REPO_ROOT, out_dir)
    os.makedirs(target, exist_ok=True)
    priv_file = os.path.join(target, "private_key.pem")
    pub_file = os.path.join(target, "public_key.pem")
    if os.path.exists(priv_file) and os.path.exists(pub_file):
        print(f"{CLR_YELLOW}Keys already exist in {out_dir}/. Skipping re-generation.{CLR_RESET}")
        return 0
    priv_pem, pub_pem = generate_keypair()
    with open(priv_file, "wb") as f: f.write(priv_pem)
    with open(pub_file, "wb") as f: f.write(pub_pem)
    print(f"{CLR_GREEN}{CLR_BOLD}✔ Successfully generated Ed25519 Keypair in {out_dir}/{CLR_RESET}")
    print(f"  • Public Key: {pub_file}")
    print(f"  • Private Key: {priv_file}")
    return 0


def install_pre_commit_hook():
    git_dir = os.path.join(REPO_ROOT, ".git")
    if not os.path.isdir(git_dir):
        print(f"{CLR_RED}Error: .git directory not found in '{REPO_ROOT}'. Not a git repository.{CLR_RESET}")
        return 1

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")

    hook_content = f"""#!/bin/sh
# Sentinel Scanner Automated Pre-Commit Hook
echo "🛡️  Running Sentinel Scanner Pre-Commit Security Gate..."
python3 "{os.path.abspath(__file__)}" scan . --fail-on=HIGH
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Commit aborted due to unresolved high/critical security findings."
    exit 1
fi
exit 0
"""
    with open(hook_path, "w") as f:
        f.write(hook_content)

    os.chmod(hook_path, 0o755)
    print(f"{CLR_GREEN}{CLR_BOLD}✔ Git pre-commit hook installed successfully at:{CLR_RESET} {hook_path}")
    print("Every `git commit` will now automatically verify code against secrets, SAST, and IaC flaws.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Sentinel Scanner Developer CLI & Pre-Commit Shield")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Scan local directory for security vulnerabilities")
    scan_p.add_argument("path", nargs="?", default=".", help="Target path to scan (default: current directory)")
    scan_p.add_argument("--fail-on", default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Severity threshold that triggers a non-zero exit code")
    scan_p.add_argument("--json", action="store_true", help="Output findings as structured JSON")
    scan_p.add_argument("--rules", default=None, help="Path to custom rules YAML/JSON file")
    scan_p.add_argument("--sonar-export", default=None, help="Export findings in SonarQube Generic Issue Import JSON format to specified file path")

    # List rules command
    rules_p = subparsers.add_parser("list-rules", help="List all active security rules (built-in and project custom)")
    rules_p.add_argument("path", nargs="?", default=".", help="Workspace path to check for project custom rules")
    rules_p.add_argument("--json", action="store_true", help="Output rule catalog as structured JSON")

    # Init SonarQube command
    init_sonar_p = subparsers.add_parser("init-sonar", help="Initialize SonarQube repository integration (sonar-project.properties & CI/CD workflow)")
    init_sonar_p.add_argument("path", nargs="?", default=".", help="Target repository directory (default: current directory)")
    init_sonar_p.add_argument("--project-key", default=None, help="SonarQube project key (defaults to folder name)")

    # Hook installer command
    subparsers.add_parser("install-hook", help="Install automated Git pre-commit security hook")

    # ThreatGate Code-First Threat Modeling
    tm_p = subparsers.add_parser("threat-model", help="Run code-first STRIDE threat modeling, render DFD graph & seal with Ed25519")
    tm_p.add_argument("path", help="Target source code file to evaluate (e.g. src/payments/refund.py)")
    tm_p.add_argument("--no-sign", action="store_true", help="Do not generate Ed25519 digital seal")
    tm_p.add_argument("--key", default=None, help="Path to Ed25519 private key")
    tm_p.add_argument("--no-test-gen", action="store_true", help="Do not generate companion pytest regression unit test")

    # ThreatGate PR Verifier (Fast Path)
    vp_p = subparsers.add_parser("verify-pr", help="Fast-path PR verification (< 2s) checking Ed25519 digital seals on *.threat.md")
    vp_p.add_argument("--key", default=None, help="Path to Ed25519 public key (.threatmodel/public_key.pem)")

    # ThreatGate DFD Graph
    tg_p = subparsers.add_parser("threat-graph", help="Generate Level-1 Data Flow Diagram (DFD) Mermaid graph for a component")
    tg_p.add_argument("path", help="Target source code file")

    # ThreatGate Init Keys
    ik_p = subparsers.add_parser("init-keys", help="Initialize Ed25519 cryptographic keypair in .threatmodel/")
    ik_p.add_argument("--out-dir", default=".threatmodel", help="Target directory for keys")

    args = parser.parse_args()

    if getattr(args, "json", False):
        # Don't print banner when JSON output requested
        pass
    else:
        print_banner()

    if args.command == "install-hook":
        sys.exit(install_pre_commit_hook())
    elif args.command == "init-sonar":
        target = getattr(args, "path", ".")
        project_key = getattr(args, "project_key", None)
        sys.exit(init_sonar(target, project_key))
    elif args.command == "list-rules":
        target = getattr(args, "path", ".")
        output_json = getattr(args, "json", False)
        sys.exit(list_rules(target, output_json))
    elif args.command == "threat-model":
        target = getattr(args, "path")
        sign = not getattr(args, "no_sign", False)
        key_path = getattr(args, "key", None)
        test_gen = not getattr(args, "no_test_gen", False)
        sys.exit(run_threat_model(target, sign=sign, key_path=key_path, test_gen=test_gen))
    elif args.command == "verify-pr":
        pub_key = getattr(args, "key", None)
        sys.exit(run_verify_pr(pub_key_path=pub_key))
    elif args.command == "threat-graph":
        target = getattr(args, "path")
        sys.exit(run_threat_graph(target))
    elif args.command == "init-keys":
        out_dir = getattr(args, "out_dir", ".threatmodel")
        sys.exit(run_init_keys(out_dir))
    elif args.command == "scan" or args.command is None:
        target = getattr(args, "path", ".")
        threshold = getattr(args, "fail_on", "HIGH")
        output_json = getattr(args, "json", False)
        custom_rules = getattr(args, "rules", None)
        sonar_export = getattr(args, "sonar_export", None)
        sys.exit(run_scan(target, threshold, output_json, custom_rules, sonar_export=sonar_export))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()


