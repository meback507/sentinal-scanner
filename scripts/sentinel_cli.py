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
    print(f"  • {CLR_CYAN}Built-in SAST:{CLR_RESET} {summary['sast_builtin']}")
    print(f"  • {CLR_CYAN}Built-in IaC & Containers:{CLR_RESET} {summary['iac_builtin']}")
    print(f"  • {CLR_CYAN}Built-in API Security:{CLR_RESET} {summary['api_builtin']}")
    print(f"  • {CLR_YELLOW}Platform Custom (DB):{CLR_RESET} {summary['platform_custom']}")
    print(f"  • {CLR_GREEN}Project Custom (.sentinel/rules.yaml):{CLR_RESET} {summary['project_custom']}\n")

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

    # 3. Built-in SAST
    print(f"\n{CLR_CYAN}{CLR_BOLD}--- Built-in SAST Rules ({len(catalog['rules']['sast_builtin'])}) ---{CLR_RESET}")
    for r in catalog["rules"]["sast_builtin"]:
        print(f"{r['id']:<18} {'SAST':<8} {'HIGH':<10} {r.get('name', '')[:45]}")

    # 4. Built-in IaC
    print(f"\n{CLR_CYAN}{CLR_BOLD}--- Built-in IaC & Container Rules ({len(catalog['rules']['iac_builtin'])}) ---{CLR_RESET}")
    for r in catalog["rules"]["iac_builtin"]:
        sev = r.get("severity", "HIGH")
        color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "HIGH" else CLR_BLUE)
        print(f"{r['id']:<18} {'IAC':<8} {color}{sev:<10}{CLR_RESET} {r.get('name', '')[:45]}")

    print("\n" + "=" * 80 + "\n")
    return 0


def run_scan(target_path: str, fail_on: str = "HIGH", output_json: bool = False, custom_rules_file: str = None) -> int:
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path):
        if output_json:
            print(json.dumps({"error": f"Target path '{target_path}' does not exist."}))
        else:
            print(f"{CLR_RED}Error: Target path '{target_path}' does not exist.{CLR_RESET}")
        return 1

    if not output_json:
        print(f"{CLR_BOLD}Target Directory:{CLR_RESET} {target_path}")
        print(f"{CLR_BOLD}Scanning engines:{CLR_RESET} SAST, High-Entropy Secrets, IaC/Containers, OpenAPI Specs\n")

    all_findings = []

    # 1. Secrets
    secret_scanner = SecretScanner()
    secrets = secret_scanner.scan_directory(target_path)
    all_findings.extend(secrets)

    # 2. SAST
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

    # List rules command
    rules_p = subparsers.add_parser("list-rules", help="List all active security rules (built-in and project custom)")
    rules_p.add_argument("path", nargs="?", default=".", help="Workspace path to check for project custom rules")
    rules_p.add_argument("--json", action="store_true", help="Output rule catalog as structured JSON")

    # Hook installer command
    subparsers.add_parser("install-hook", help="Install automated Git pre-commit security hook")

    args = parser.parse_args()

    if getattr(args, "json", False):
        # Don't print banner when JSON output requested
        pass
    else:
        print_banner()

    if args.command == "install-hook":
        sys.exit(install_pre_commit_hook())
    elif args.command == "list-rules":
        target = getattr(args, "path", ".")
        output_json = getattr(args, "json", False)
        sys.exit(list_rules(target, output_json))
    elif args.command == "scan" or args.command is None:
        target = getattr(args, "path", ".")
        threshold = getattr(args, "fail_on", "HIGH")
        output_json = getattr(args, "json", False)
        custom_rules = getattr(args, "rules", None)
        sys.exit(run_scan(target, threshold, output_json, custom_rules))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

