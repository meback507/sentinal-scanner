"""
ThreatGate Threat Delta Engine
Parses markdown threat tables and calculates delta differences between baseline and PR models.
"""

import re
from typing import Dict, Optional
from ..models.schemas import ThreatDeltaReport


def parse_threats_from_markdown(markdown_content: str) -> Dict[str, dict]:
    """
    Parses markdown threat tables into a dictionary indexed by Threat ID.
    Example row:
    | TH-01 | Elevation of Privilege | HIGH | transaction_id | ✅ Mitigated |
    """
    threats = {}
    if not markdown_content:
        return threats

    row_regex = r"\|\s*(TH-\d+|[A-Z0-9_\-]+)\s*\|\s*([^\|]+)\s*\|\s*([^\|]+)\s*\|\s*([^\|]+)\s*\|\s*([^\|]+)\s*\|"

    for match in re.finditer(row_regex, markdown_content):
        t_id, category, severity, element, status_col = [g.strip() for g in match.groups()]
        if t_id.lower() in ("threat id", "id", "---", ":---", ":---:"):
            continue
        is_mitigated = any(w in status_col.lower() for w in ("mitigated", "resolved", "passed", "✅", "true"))
        threats[t_id] = {
            "id": t_id,
            "category": category,
            "severity": severity.upper(),
            "element": element,
            "is_mitigated": is_mitigated,
            "raw_status": status_col
        }
    return threats


def compute_delta(baseline_md: Optional[str], current_md: str) -> ThreatDeltaReport:
    """
    Computes delta between baseline (target branch) and current branch threat models.
    """
    current_threats = parse_threats_from_markdown(current_md)
    baseline_threats = parse_threats_from_markdown(baseline_md) if baseline_md else {}

    neutralized = []
    new_unmitigated = []

    for t_id, data in current_threats.items():
        # Threat was previously present and unmitigated, but is now mitigated
        if t_id in baseline_threats:
            if not baseline_threats[t_id]["is_mitigated"] and data["is_mitigated"]:
                neutralized.append(f"{t_id}: {data['category']} on `{data['element']}`")
        elif data["is_mitigated"]:
            # Newly introduced element that was immediately mitigated
            neutralized.append(f"{t_id}: {data['category']} on `{data['element']}` (New)")

        # Any threat currently unmitigated
        if not data["is_mitigated"]:
            new_unmitigated.append(f"[{data['severity']}] {t_id}: {data['category']} on `{data['element']}`")

    return ThreatDeltaReport(
        neutralized_threats=neutralized,
        new_unmitigated_threats=new_unmitigated,
        is_pr_acceptable=(len(new_unmitigated) == 0)
    )


def format_delta_summary(delta: ThreatDeltaReport, component_path: str = "Component") -> str:
    """
    Renders a high-contrast PR review summary comment for GitHub / GitLab.
    """
    status_badge = "APPROVED ✅" if delta.is_pr_acceptable else "ACTION REQUIRED ⚠️"
    lines = [
        f"### 🛡️ ThreatGate: Threat Delta Summary for `{component_path}`",
        f"* **Gate Verdict**: `{status_badge}`",
        f"* **Neutralized Threats**: `{len(delta.neutralized_threats)}`"
    ]
    if delta.neutralized_threats:
        for item in delta.neutralized_threats:
            lines.append(f"  - ✅ {item}")

    lines.append(f"* **Open Unmitigated Threats**: `{len(delta.new_unmitigated_threats)}`")
    if delta.new_unmitigated_threats:
        for item in delta.new_unmitigated_threats:
            lines.append(f"  - ❌ {item}")

    if delta.is_pr_acceptable:
        lines.append("\n*All STRIDE threats are adequately mitigated. PR is unlocked for merging.*")
    else:
        lines.append("\n*Unmitigated threats detected! Review replacement diffs or apply mitigations before merging.*")

    return "\n".join(lines)

