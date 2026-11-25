"""Threat intel agent (ADR 001 point 4, ADR 008).

The analysis is deterministic (opssoc/intel/finance.py) and is the agent's main output:
priority techniques, coverage gaps against detection_As_Code, and KEV entries, each with
its source. An LLM only writes an optional narrative brief from that data, on the
writing tier; every group, technique and CVE ID the brief names is checked against the
data, and a brief that names anything else is rejected.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from opssoc.agents import AgentDefinition, load_definition
from opssoc.agents.investigation.agent import fence
from opssoc.llm.base import BudgetExceeded, LLMError, Provider, Tier

DEFINITION = Path(__file__).with_name("agent.md")
IDS = re.compile(r"\b(G\d{4}|T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,})\b")


def known_ids(analysis: dict) -> set[str]:
    ids = {g["id"] for g in analysis["groups"]}
    ids |= {t["id"] for t in analysis["priority_techniques"]}
    ids |= {e["cve"] for e in analysis["kev"]}
    return ids


def check_brief(text: str, analysis: dict) -> list[str]:
    unknown = sorted(set(IDS.findall(text)) - known_ids(analysis))
    problems = [f"names IDs not in the data: {', '.join(unknown)}"] if unknown else []
    if len(text.split()) > 450:
        problems.append(f"{len(text.split())} words; the limit is 400")
    if not IDS.search(text):
        problems.append("names no group, technique or CVE ID")
    return problems


def brief_input(analysis: dict, top: int) -> dict:
    """What the model sees: the top of the ranking, the gaps and the KEV entries, with
    group names; no free text from ATT&CK beyond the names."""
    names = {g["id"]: g["name"] for g in analysis["groups"]}
    tiers = {g["id"]: g["tier"] for g in analysis["groups"]}
    return {
        "profile_note": "curated profile of groups that public reports show targeting finance; "
                        f"status {analysis['profile_status']}",
        "groups": [{"id": i, "name": names[i], "tier": tiers[i]} for i in names],
        "top_techniques": [{k: t[k] for k in ("id", "name", "tactics", "score", "groups",
                                              "coverage", "rules")}
                           for t in analysis["priority_techniques"][:top]],
        "gaps": [t["id"] for t in analysis.get("gaps") or []],
        "kev": [{k: e.get(k) for k in ("cve", "vendor", "product", "name", "ransomware",
                                       "groups")} for e in analysis["kev"] if e["in_kev"]],
        "sources": {"attack": analysis["attack_version"], "kev": analysis["kev_version"]},
    }


@dataclass
class Brief:
    text: str | None
    status: str
    attempts: list[dict] = field(default_factory=list)
    cost_usd: float = 0.0
    model: str | None = None


def write_brief(provider: Provider, analysis: dict,
                definition: AgentDefinition | None = None) -> Brief:
    d = definition or load_definition(DEFINITION)
    tier = Tier(d.settings.get("tier_brief", "writing"))
    payload = fence(None, brief_input(analysis, int(d.number("top_techniques", 25))))
    brief = Brief(None, "not written")
    try:
        conv = provider.conversation(tier, d.prompt, [], max_tokens=3000,
                                     purpose="finance threat brief")
        brief.model = conv.model
        turn = conv.send(payload)
        for attempt in range(int(d.number("max_brief_attempts", 2))):
            brief.cost_usd += turn.usage.cost_usd
            problems = check_brief(turn.text, analysis)
            brief.attempts.append({"text": turn.text, "problems": problems})
            if not problems:
                brief.text, brief.status = turn.text.strip(), "accepted"
                return brief
            if attempt + 1 < int(d.number("max_brief_attempts", 2)):
                turn = conv.send("Rejected:\n- " + "\n- ".join(problems)
                                 + "\nRewrite it using only IDs from the data.")
        brief.status = "rejected: " + "; ".join(brief.attempts[-1]["problems"])
    except (BudgetExceeded, LLMError) as exc:
        brief.status = f"not written: {exc}"
    return brief


def report_markdown(analysis: dict, brief: Brief | None = None) -> str:
    """The deterministic report; the brief, when accepted, goes first and is labelled as
    model-written."""
    lines = ["# Finance-sector threat priorities", "",
             f"Sources: {analysis['attack_version']} (MITRE STIX bundle), CISA KEV "
             f"{analysis['kev_version']}. Group list: curated profile "
             f"(intel/finance_profile.json, status {analysis['profile_status']}). "
             "Neither source has a sector field; the profile is a judgment.", ""]
    if brief and brief.text:
        lines += ["## Brief (model-written, IDs checked against the data below)", "",
                  brief.text, ""]
    c = analysis["counts"]
    lines += ["## Summary", "",
              f"- {c['groups']} groups, {c['techniques']} techniques they use.",
              f"- {c['cves_named']} CVEs named by ATT&CK for these groups; {c['cves_in_kev']} "
              f"in KEV, {c['kev_ransomware_known']} with known ransomware use.", ""]
    top = analysis["top"]
    lines += [f"## Top {top} techniques", "",
              "| Technique | Name | Score | Groups | detection_As_Code |", "|---|---|---|---|---|"]
    for t in analysis["priority_techniques"][:top]:
        cov = t["coverage"] + (f" ({', '.join(t['rules'])})" if t["rules"] else "")
        lines.append(f"| {t['id']} | {t['name']} | {t['score']} | {len(t['groups'])} | {cov} |")
    if analysis.get("gaps") is not None:
        lines += ["", "## Gaps (top techniques with no rule)", ""]
        lines += [f"- {t['id']} {t['name']}: {len(t['groups'])} groups" for t in analysis["gaps"]]
    if analysis.get("pre_compromise"):
        lines += ["", "Not in any log a SIEM rule reads (reconnaissance / resource "
                  "development): " + ", ".join(t["id"] for t in analysis["pre_compromise"])]
    lines += ["", "## KEV entries ATT&CK links to these groups", "",
              "| CVE | Product | Ransomware | Groups |", "|---|---|---|---|"]
    for e in analysis["kev"]:
        if e["in_kev"]:
            lines.append(f"| {e['cve']} | {e['vendor']} {e['product']} | {e['ransomware']} | "
                         f"{', '.join(e['groups'])} |")
    missing = [e["cve"] for e in analysis["kev"] if not e["in_kev"]]
    if missing:
        lines += ["", f"Named by ATT&CK but not in KEV: {', '.join(missing)}"]
    lines += ["", "## Groups", ""]
    for g in analysis["groups"]:
        ev = g.get("web_evidence") or {}
        src = (ev.get("sources") or [{}])[0]
        line = f"- {g['id']} {g['name']} ({g['tier']}, web evidence {ev.get('status', 'none')})"
        if src:
            line += (f": \"{src['quote']}\" ({src['publisher']}, {src['url']}, "
                     f"fetched {src['fetched']})")
        if g.get("source_sentence"):
            line += f"; ATT&CK: \"{g['source_sentence']}\""
        lines.append(line)
    lines += ["", "## What this does not say", "",
              "- Which groups target this organisation, or how likely an attack is.",
              "- Whether a covered rule is deployed and active for a customer "
              "(detection_As_Code's log-source gate decides that).",
              "- Techniques ATT&CK has not recorded for these groups."]
    return "\n".join(lines) + "\n"


def write_outputs(out: Path, analysis: dict, brief: Brief | None) -> tuple[Path, Path]:
    out.mkdir(parents=True, exist_ok=True)
    data = dict(analysis, brief=None if brief is None else brief.__dict__)
    js, md = out / "finance_priorities.json", out / "finance_priorities.md"
    js.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    md.write_text(report_markdown(analysis, brief), encoding="utf-8")
    return js, md
