"""
ThreatGate Master CLI Entrypoint
Developer Shift-Left Threat Modeling, Ed25519 Cryptographic Signing,
Two-Speed PR Verification, and Threat Graph Visualizer.
"""

import os
import sys
import glob
import subprocess
from pathlib import Path
from typing import Optional
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown

from .core.crypto import (
    generate_keypair,
    sign_payload,
    verify_payload,
    extract_seal_from_markdown,
    embed_seal_into_markdown
)
from .core.engine import ThreatEngine
from .core.delta import compute_delta, format_delta_summary
from .core.test_gen import generate_security_regression_test

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="threatgate")
def main():
    """🛡️ ThreatGate: Code-First Threat Modeling & Continuous PR Gating Engine"""
    pass


@main.command("init-keys")
@click.option("--out-dir", "-o", default=".threatmodel", help="Directory to save Ed25519 keypair")
def init_keys_cmd(out_dir: str):
    """Initializes Ed25519 keypair (.threatmodel/private_key.pem and public_key.pem)."""
    target = Path(out_dir)
    target.mkdir(parents=True, exist_ok=True)
    priv_file = target / "private_key.pem"
    pub_file = target / "public_key.pem"

    if priv_file.exists() and pub_file.exists():
        console.print(f"[yellow]⚠️ Keys already exist in {out_dir}/. Skipping re-generation.[/yellow]")
        return

    priv_pem, pub_pem = generate_keypair()
    priv_file.write_bytes(priv_pem)
    pub_file.write_bytes(pub_pem)

    console.print(Panel(
        f"[green]✔ Successfully generated Ed25519 Keypair in {out_dir}/[/green]\n\n"
        f"• [bold]Public Key[/bold] (commit to Git): [cyan]{pub_file}[/cyan]\n"
        f"• [bold]Private Key[/bold] (keep secret in .env/KMS): [red]{priv_file}[/red]",
        title="🔑 ThreatGate Key Initializer",
        border_style="green"
    ))


@main.command("scan")
@click.option("--path", "-p", "file_path", required=True, help="Target source code file to evaluate")
@click.option("--sign/--no-sign", default=True, help="Automatically sign report with Ed25519 private key if approved")
@click.option("--key", "-k", "key_path", default=".threatmodel/private_key.pem", help="Path to Ed25519 private key")
@click.option("--test-gen/--no-test-gen", default=True, help="Auto-generate companion pytest regression unit tests")
@click.option("--output", "-o", "out_path", default=None, help="Custom path for *.threat.md output")
def scan_cmd(file_path: str, sign: bool, key_path: str, test_gen: bool, out_path: Optional[str]):
    """Evaluates source code for STRIDE threats, renders DFD graph, and signs component model."""
    path_obj = Path(file_path)
    if not path_obj.exists() or not path_obj.is_file():
        console.print(f"[red]❌ Error: File not found: {file_path}[/red]")
        sys.exit(1)

    code_content = path_obj.read_text(encoding="utf-8")
    engine = ThreatEngine()

    with console.status(f"[cyan]Analyzing STRIDE threats for {file_path}...[/cyan]"):
        report = engine.evaluate_code(file_path, code_content)

    # 1. Print Executive Summary
    status_text = "[bold green]APPROVED ✅[/bold green]" if report.is_approved else "[bold red]ACTION REQUIRED ⚠️[/bold red]"
    console.print(Panel(
        f"[bold]Target File:[/bold] {file_path}\n"
        f"[bold]Verdict:[/bold] {status_text}\n"
        f"[bold]Summary:[/bold] {report.summary}\n"
        f"[bold]Trust Boundaries:[/bold] {', '.join(report.trust_boundaries_crossed)}",
        title="🛡️ ThreatGate Architectural Evaluation",
        border_style="green" if report.is_approved else "red"
    ))

    # 2. Print Threat Matrix Table
    table = Table(title="STRIDE Threat Scenarios & Mitigations", header_style="bold magenta")
    table.add_column("Threat ID", style="cyan", width=10)
    table.add_column("Category", style="yellow", width=22)
    table.add_column("Severity", width=12)
    table.add_column("Element", style="white", width=24)
    table.add_column("Status", width=16)

    for t in report.threats:
        sev_color = "red" if t.severity.value in ("CRITICAL", "HIGH") else "yellow"
        sev_badge = f"[{sev_color}]{t.severity.value}[/{sev_color}]"
        status_badge = "[green]✅ Mitigated[/green]" if t.is_mitigated else "[bold red]❌ Unmitigated[/bold red]"
        table.add_row(t.id, t.stride_category.value, sev_badge, t.target_element, status_badge)

    console.print(table)

    # 3. Print Data Flow Diagram (DFD) Mermaid Graph
    if report.dfd_mermaid:
        console.print(Panel(
            f"[bold cyan]Mermaid Data Flow Diagram (DFD Level-1):[/bold cyan]\n\n"
            f"```mermaid\n{report.dfd_mermaid}\n```",
            title="📊 Architectural Threat Graph & Trust Boundaries",
            border_style="cyan"
        ))

    # 4. Handle Unmitigated Flaws
    if not report.is_approved:
        console.print("\n[bold red]❌ ACTION REQUIRED: High/Critical Threats Detected![/bold red]")
        for t in report.threats:
            if not t.is_mitigated and t.recommended_fix:
                console.print(Panel(
                    f"[bold yellow]Threat {t.id} ({t.stride_category.value}) on `{t.target_element}`[/bold yellow]\n\n"
                    f"[bold]Attack Scenario:[/bold] {t.vulnerability_details}\n\n"
                    f"[bold green]Recommended Code Replacement Diff:[/bold green]\n"
                    f"[dim]{t.recommended_fix}[/dim]",
                    title="💡 Actionable Remediation",
                    border_style="yellow"
                ))
        console.print("[dim]Apply code fixes and re-run 'threatgate scan' to seal the component.[/dim]")
        sys.exit(1)

    # 5. Cryptographic Sealing (Ed25519)
    digital_seal = None
    if sign:
        priv_key_file = Path(key_path)
        if not priv_key_file.exists():
            # Auto-generate keys if default path doesn't exist
            if key_path == ".threatmodel/private_key.pem":
                console.print("[yellow]Notice: Keypair not found. Initializing .threatmodel/...[/yellow]")
                priv_pem, pub_pem = generate_keypair()
                priv_key_file.parent.mkdir(parents=True, exist_ok=True)
                priv_key_file.write_bytes(priv_pem)
                (priv_key_file.parent / "public_key.pem").write_bytes(pub_pem)
            else:
                console.print(f"[red]❌ Error: Private key file not found: {key_path}[/red]")
                sys.exit(1)

        priv_pem = priv_key_file.read_bytes()
        # Build base report body without seal
        report_body = engine.format_threat_model_markdown(file_path, report, code_content, digital_seal=None)
        digital_seal = sign_payload(code_content, report_body, priv_pem)

    # 6. Save *.threat.md file
    out_file = Path(out_path) if out_path else path_obj.with_suffix(".threat.md")
    full_markdown = engine.format_threat_model_markdown(file_path, report, code_content, digital_seal=digital_seal)
    out_file.write_text(full_markdown, encoding="utf-8")

    console.print(f"\n[bold green]✔ Component Threat Model Saved:[/bold green] [cyan]{out_file}[/cyan]")
    if digital_seal:
        console.print(f"[bold green]✔ Sealed with Ed25519 Digital Seal:[/bold green] [dim]{digital_seal[:24]}...[/dim]")

    # 7. Generate companion security regression test
    if test_gen:
        mitigated_threats = [t for t in report.threats if t.is_mitigated]
        if mitigated_threats:
            test_path = generate_security_regression_test(mitigated_threats[0])
            console.print(f"[bold green]✔ Security Regression Unit Test Generated:[/bold green] [cyan]{test_path}[/cyan]")


@main.command("graph")
@click.option("--path", "-p", "file_path", required=True, help="Target source code file")
def graph_cmd(file_path: str):
    """Outputs the Level-1 Data Flow Diagram (DFD) Mermaid graph for a file."""
    path_obj = Path(file_path)
    if not path_obj.exists():
        console.print(f"[red]❌ File not found: {file_path}[/red]")
        sys.exit(1)

    code_content = path_obj.read_text(encoding="utf-8")
    engine = ThreatEngine()
    report = engine.evaluate_code(file_path, code_content)

    console.print(report.dfd_mermaid or "graph LR\nClient --> Controller --> DataStore")


@main.command("verify-pr")
@click.option("--key", "-k", "pub_key_path", default=".threatmodel/public_key.pem", help="Path to Ed25519 public key")
@click.option("--run-tests/--no-tests", default=True, help="Execute pytest security regression suite")
def verify_pr_cmd(pub_key_path: str, run_tests: bool):
    """Fast-Path PR Verification (< 2s): Verifies Ed25519 signatures using public key with zero LLM calls."""
    pub_key_file = Path(pub_key_path)
    if not pub_key_file.exists():
        console.print(f"[red]❌ Ed25519 Public Key not found: {pub_key_path}[/red]")
        sys.exit(1)

    pub_pem = pub_key_file.read_bytes()

    # Discover all *.threat.md files
    threat_files = list(Path(".").glob("**/*.threat.md"))
    # Filter out hidden or build dirs
    threat_files = [f for f in threat_files if not any(p in str(f) for p in (".git", "node_modules", ".venv", "build", "dist"))]

    if not threat_files:
        console.print("[yellow]⚠️ No *.threat.md files found in repository to verify.[/yellow]")
        return

    console.print(f"[bold cyan]⚡ ThreatGate Fast-Path CI Verification ({len(threat_files)} components)...[/bold cyan]")
    all_valid = True

    for tf in threat_files:
        # Expected companion code file
        base_stem = tf.name[:-len(".threat.md")] if tf.name.endswith(".threat.md") else tf.stem
        code_file = tf.with_name(base_stem + ".py")
        if not code_file.exists():
            # Try other extensions (.js, .ts, etc.)
            for ext in (".js", ".ts", ".go", ".java", ".c", ".cpp"):
                cand = tf.with_name(base_stem + ext)
                if cand.exists():
                    code_file = cand
                    break

        if not code_file.exists():
            console.print(f"  [yellow]• {tf}: Orphaned threat model (companion code file not found)[/yellow]")
            continue

        code_content = code_file.read_text(encoding="utf-8")
        report_content = tf.read_text(encoding="utf-8")
        body, seal = extract_seal_from_markdown(report_content)

        if not seal:
            console.print(f"  [bold red]❌ {code_file}: Missing Ed25519 Digital Seal[/bold red]")
            all_valid = False
            continue

        is_valid = verify_payload(code_content, body, seal, pub_pem)
        if is_valid:
            console.print(f"  [green]✔ {code_file}: Ed25519 Seal VERIFIED (Code and Model Intact)[/green]")
        else:
            console.print(f"  [bold red]❌ {code_file}: TAMPERED / DRIFTED (Signature mismatch!)[/bold red]")
            all_valid = False

    # Optional test execution
    if run_tests and Path("tests/security").exists():
        console.print("\n[cyan]Executing Threat Regression Unit Tests...[/cyan]")
        res = subprocess.run([sys.executable, "-m", "pytest", "tests/security", "-q"], capture_output=True, text=True)
        if res.returncode == 0:
            console.print("[green]✔ All Threat Regression Unit Tests PASSED[/green]")
        else:
            console.print(f"[red]❌ Threat Regression Unit Tests FAILED:\n{res.stdout}\n{res.stderr}[/red]")
            all_valid = False

    if not all_valid:
        console.print("\n[bold red]❌ ThreatGate CI Status: FAILED (Code drifted or seals invalid)[/bold red]")
        sys.exit(1)

    console.print("\n[bold green]🚀 ThreatGate CI Status: APPROVED ✅ (All components sealed & verified)[/bold green]")


@main.command("delta")
@click.option("--base", "-b", required=True, help="Baseline threat model path")
@click.option("--current", "-c", required=True, help="Current threat model path")
def delta_cmd(base: str, current: str):
    """Calculates threat delta between baseline and current threat models."""
    base_text = Path(base).read_text(encoding="utf-8") if Path(base).exists() else None
    curr_text = Path(current).read_text(encoding="utf-8") if Path(current).exists() else ""

    delta = compute_delta(base_text, curr_text)
    summary = format_delta_summary(delta, Path(current).name)
    console.print(Markdown(summary))


if __name__ == "__main__":
    main()

