"""Case report -> Markdown for a SOAR entry or comment.

Deterministic template. The case note (writing tier) fills `summary`; everything else is
laid out from the report so every claim keeps its evidence ID. When the report carries
the investigation `detail` (ADR 009 point 3), the entry shows the whole investigation for
every outcome: factor answers, telemetry coverage, hypotheses, timeline, every evidence
record and query, what was not checked, and the run's cost. A report without `detail`
renders as before.
"""

from opssoc.case import CaseReport


def _cell(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _ids(ids) -> str:
    return ", ".join(ids or []) or "-"


def route_fields(report: CaseReport) -> dict:
    """Fields a SOAR playbook can route or notify on (besides verdict and severity)."""
    d = report.detail or {}
    if not d:
        return {}
    status = d.get("status") or ""
    return {"confidence": d.get("confidence") or "none",
            "agent-status": "verdict" if status == "verdict" else "stopped"}


def _detail(d: dict) -> list[str]:
    lines: list[str] = []
    if d.get("status") != "verdict":
        lines += [f"**Agent status:** {d.get('status')}", ""]
        last = d.get("last_rejected")
        if last:
            lines += [f"Last verdict the checks rejected ({last.get('verdict')}):", ""]
            lines += [f"- {p}" for p in last.get("problems") or []]
            lines.append("")
    if d.get("factors"):
        lines += [f"### Factors ({d.get('factor_set')})", "",
                  "| ID | Factor | Weight | State | Evidence | Reason |",
                  "|---|---|---|---|---|---|"]
        for f in d["factors"]:
            lines.append(f"| {f['id']} | {_cell(f.get('name'))} | {f.get('weight')} | "
                         f"{f.get('state')} | {_ids(f.get('evidence_ids'))} | "
                         f"{_cell(f.get('reason'))} |")
        tally = d.get("tally") or {}
        counts = [f"{state}: " + ", ".join(f"{w} {n}" for w, n in by_w.items() if n)
                  for state, by_w in tally.items() if any(by_w.values())]
        if counts:
            lines += ["", "Tally (counted by code, weights uncalibrated): " + "; ".join(counts)]
        lines.append("")
    if d.get("coverage"):
        lines += ["### Telemetry coverage", "",
                  "| Table | State | Rows | From alert time | Last seen | Detail |",
                  "|---|---|---|---|---|---|"]
        for r in d["coverage"]:
            lines.append(f"| {r.get('table')} | {r.get('state')} | {r.get('rows', '-')} | "
                         f"{r.get('rows_from_alert', '-')} | {r.get('last_seen', '-')} | "
                         f"{_cell(r.get('detail', ''))[:200]} |")
        lines.append("")
    if d.get("hypotheses"):
        lines += ["### Hypotheses", ""]
        for h in d["hypotheses"]:
            lines.append(f"- **{h.get('status')}** ({h.get('explanation', '-')}): "
                         f"{_cell(h.get('hypothesis'))} [{_ids(h.get('evidence_ids'))}]")
        lines.append("")
    if d.get("timeline"):
        lines += ["### Timeline", "", "| Time | Event | Evidence |", "|---|---|---|"]
        for t in d["timeline"]:
            lines.append(f"| {_cell(t.get('time'))} | {_cell(t.get('event'))} | "
                         f"{_ids(t.get('evidence_ids'))} |")
        lines.append("")
    return lines


def _records(d: dict) -> list[str]:
    index = d.get("evidence_index") or []
    if not index:
        return []
    lines = ["### All evidence records", "", "| ID | Kind | Purpose | Rows | Cited | Data |",
             "|---|---|---|---|---|---|"]
    for e in index:
        rows = f"{e.get('row_count')}{' (truncated)' if e.get('truncated') else ''}"
        lines.append(f"| {e['id']} | {e.get('kind')} | {_cell(e.get('purpose'))} | {rows} | "
                     f"{'yes' if e.get('cited') else 'no'} | {e.get('data')} |")
    lines.append("")
    queries = [e for e in index if e.get("query")]
    if queries:
        lines += ["### Queries", ""]
        for e in queries:
            lines += [f"{e['id']}{'' if e.get('cited') else ' (not cited)'}:", "",
                      "```kql", e["query"], "```", ""]
    return lines


def _tail(d: dict) -> list[str]:
    lines: list[str] = []
    if d.get("not_checked"):
        lines += ["### Not checked", ""] + [f"- {_cell(x)}" for x in d["not_checked"]] + [""]
    run = d.get("run") or {}
    lines += ["### Run", "",
              f"Agent {d.get('agent_version')}; models {', '.join(run.get('models') or [])}; "
              f"{run.get('llm_turns')} model turns, {run.get('queries')} queries, "
              f"USD {run.get('cost_usd')}; {d.get('rejected_verdicts', 0)} verdicts rejected "
              "by the checks." + (f" Record: `{d['record']}`." if d.get("record") else ""), ""]
    return lines


def to_markdown(report: CaseReport) -> str:
    d = report.detail or {}
    lines = [
        f"## ops-SOC investigation {report.case_id}",
        "",
        f"**Verdict:** {report.verdict.value.replace('_', ' ')}  ",
        f"**Severity:** {report.severity.value}  ",
        f"**Source alert:** `{report.source_alert_id}`",
    ]
    if d.get("confidence"):
        lines[-1] += "  "
        lines.append(f"**Confidence:** {d['confidence']}")
    if report.mitre_techniques:
        lines[-1] += "  "
        lines.append(f"**ATT&CK:** {', '.join(report.mitre_techniques)}")
    lines += ["", "### Summary", "", report.summary, ""]
    if report.missing_telemetry:
        lines += ["### Missing telemetry", "",
                  "Factors the agent could not answer because the data is not there:", ""]
        lines += [f"- {item}" for item in report.missing_telemetry]
        lines.append("")
    lines += _detail(d)
    if report.evidence:
        lines += ["### Findings and the evidence they cite" if d else "### Evidence", "",
                  "| ID | Source | Finding | Data |", "|---|---|---|---|"]
        for item in report.evidence:
            lines.append(f"| {item.id} | {item.source} | {_cell(item.finding)} | "
                         f"{item.provenance} |")
        lines.append("")
    if d:
        lines += _records(d)
    else:
        queries = [item for item in report.evidence if item.query]
        if queries:
            lines += ["### Queries", ""]
            for item in queries:
                lines += [f"{item.id}:", "", "```kql", item.query, "```", ""]
    if report.recommended_actions:
        lines += ["### Recommended next steps", ""]
        lines += [f"{i}. {action}" for i, action in enumerate(report.recommended_actions, 1)]
        lines.append("")
    if d:
        lines += _tail(d)
    lines.append("_Written by ops-SOC. No action was taken in any connected system._")
    return "\n".join(lines)
