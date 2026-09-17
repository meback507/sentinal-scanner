"""
AegisSec - CI/CD Quality Gate & Differential PR Webhook Evaluator
Evaluates scan findings against threat-informed Quality Gate policies,
failing builds on weaponized (🚨 Act Now) or safety-critical (ASIL-D / MISRA Rule 21.3)
defects, while permitting routine maintenance to pass without breaking velocity.
"""

from typing import Dict, Any, List, Optional


class CIQualityGate:
    """
    Automates CI/CD build blocking and Pull Request check decorations.
    """

    @classmethod
    def evaluate(
        cls,
        findings: List[Dict[str, Any]],
        policy: Optional[Dict[str, Any]] = None,
        strict_mode: bool = False,
        max_critical: int = 0,
        max_high: int = 3,
        **kwargs
    ) -> Dict[str, Any]:
        policy = policy or {
            "fail_on_act_now": True,
            "fail_on_asil_d": True,
            "max_critical": 0 if strict_mode else max_critical,
            "max_high": 0 if strict_mode else max_high,
            "max_avg_epss": 0.30
        }
        if strict_mode:
            policy["max_critical"] = 0
            policy["max_high"] = 0

        blockers = []
        warnings = []

        act_now_findings = [f for f in findings if f.get("quadrant") == "ACT_NOW"]
        critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]

        # Check for ASIL-D or MISRA violations
        asil_violations = []
        for f in findings:
            standards = f.get("standards", [])
            for s in standards:
                if "ASIL-D" in s or "Rule 21.3" in s:
                    asil_violations.append(f)
                    break

        if policy.get("fail_on_act_now") and act_now_findings:
            for f in act_now_findings:
                blockers.append({
                    "reason": "ACT_NOW_EXPLOIT",
                    "finding_id": f.get("id"),
                    "title": f.get("title"),
                    "cvss": f.get("cvss_score"),
                    "epss": f.get("epss_score"),
                    "file": f.get("file_path"),
                    "description": f"Active in-the-wild exploit detected (EPSS {f.get('epss_score')} >= 0.20)."
                })

        if policy.get("fail_on_asil_d") and asil_violations:
            for f in asil_violations:
                blockers.append({
                    "reason": "SAFETY_STANDARDS_VIOLATION",
                    "finding_id": f.get("id"),
                    "title": f.get("title"),
                    "file": f.get("file_path"),
                    "description": "Functional Safety (ISO 26262 ASIL-D / MISRA C:2012 Rule 21.3) violation."
                })

        if len(critical_findings) > policy.get("max_critical", 0):
            warnings.append(f"Critical findings count ({len(critical_findings)}) exceeds limit ({policy.get('max_critical')}).")

        passed = len(blockers) == 0
        gate_status = "PASSED" if passed else "FAILED"

        # Generate PR bot Markdown review comment
        comment_md = cls._generate_pr_comment(passed, blockers, findings)

        return {
            "passed": passed,
            "status": gate_status,
            "gate_status": gate_status,
            "exit_code": 0 if passed else 1,
            "total_evaluated": len(findings),
            "blockers_count": len(blockers),
            "blockers": blockers,
            "blocking_reasons": blockers,
            "warnings": warnings,
            "pr_comment_markdown": comment_md
        }

    @classmethod
    def format_pr_comment(cls, gate_result: Dict[str, Any]) -> str:
        """Convenience method to format PR markdown comment from evaluation result."""
        if "pr_comment_markdown" in gate_result:
            return gate_result["pr_comment_markdown"]
        return cls._generate_pr_comment(
            gate_result.get("passed", False),
            gate_result.get("blockers", []),
            gate_result.get("findings", [])
        )

    @classmethod
    def _generate_pr_comment(cls, passed: bool, blockers: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> str:
        icon = "✅" if passed else "🚨"
        header = f"## {icon} AegisSec CI/CD Quality Gate Evaluation: **{'PASSED' if passed else 'FAILED'}**\n\n"

        if passed:
            body = (
                "> **Zero blocking security threats detected.**\n"
                f"> Analyzed {len(findings)} files & dependencies. No active exploits (Act Now) or ISO 26262 ASIL-D safety violations found.\n"
                "> PR is clear to merge! 🚀"
            )
        else:
            blocker_rows = "\n".join([
                f"| `{b['file']}` | **{b['title']}** | `{b['reason']}` | {b['description']} |"
                for b in blockers
            ])
            body = f"""### ⚠️ Merge Blocked by Security Policy
The following **{len(blockers)} blocking violation(s)** must be remediated before this Pull Request can be merged:

| Affected File | Flaw Description | Rule Violation | Policy Detail |
| :--- | :--- | :--- | :--- |
{blocker_rows}

💡 *Use the **AegisSec 1-Click Autonomous Remediation PR** to apply the verified code fix.*
"""
        return header + body
