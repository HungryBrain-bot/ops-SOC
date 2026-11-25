"""Case report -> Markdown for a SOAR entry or comment.

Deterministic template. ADR 001 puts report wording on the `writing` model
tier; when that lands it fills `summary` and `recommended_actions`, and this
template still lays out the evidence so every claim keeps its evidence ID.
"""

from opssoc.case import CaseReport


def to_markdown(report: CaseReport) -> str:
    lines = [
        f"## ops-SOC investigation {report.case_id}",
        "",
        f"**Verdict:** {report.verdict.value.replace('_', ' ')}  ",
        f"**Severity:** {report.severity.value}  ",
        f"**Source alert:** `{report.source_alert_id}`",
    ]
    if report.mitre_techniques:
        lines.append(f"**ATT&CK:** {', '.join(report.mitre_techniques)}")
    lines += ["", "### Summary", "", report.summary, ""]
    if report.missing_telemetry:
        lines += ["### Missing telemetry", "",
                  "Factors the agent could not answer because the data is not there:", ""]
        lines += [f"- {item}" for item in report.missing_telemetry]
        lines.append("")
    if report.evidence:
        lines += ["### Evidence", "", "| ID | Source | Finding | Data |", "|---|---|---|---|"]
        for item in report.evidence:
            finding = item.finding.replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {item.id} | {item.source} | {finding} | {item.provenance} |")
        lines.append("")
        queries = [item for item in report.evidence if item.query]
        if queries:
            lines += ["### Queries", ""]
            for item in queries:
                lines += [f"{item.id}:", "", "```kql", item.query, "```", ""]
    if report.recommended_actions:
        lines += ["### Recommended next steps", ""]
        lines += [f"{i}. {action}" for i, action in enumerate(report.recommended_actions, 1)]
        lines.append("")
    lines.append("_Written by ops-SOC. No action was taken in any connected system._")
    return "\n".join(lines)
