"""The investigation agent (ADR 001 point 3, ADR 006; factor checklist ADR 009).

Input: an alert ID and a read-only connector. The agent reads the alert, forms
hypotheses, runs KQL through the connector, and every result becomes an evidence
record (EV-n) with its query, provenance and a hash of the rows. It ends by submitting
a verdict whose timeline, findings and factor answers cite evidence IDs; the citations,
the factor answers and the decision rules (factors.py) are checked before the verdict is
accepted.

The caller never passes an expected outcome, nothing is pre-labelled, and a verdict
the checks reject is sent back to the model with the reasons. If no valid verdict comes
within the budgets, the result is ``inconclusive`` with the reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from opssoc.agents import AgentDefinition, load_definition
from opssoc.agents.investigation import coverage as cov
from opssoc.agents.investigation import factors as fx
from opssoc.case import CaseReport, EvidenceItem, Severity, Verdict
from opssoc.connectors.base import QueryResult, ReadOnlyViolation, SecurityConnector
from opssoc.llm.base import (
    BudgetExceeded,
    LLMError,
    Provider,
    Tier,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    Usage,
)

DEFINITION = Path(__file__).with_name("agent.md")
VERDICTS = ("true_positive", "benign", "inconclusive", "insufficient_telemetry")
CONFIDENCE = ("low", "medium", "high")
EV_ID = re.compile(r"^EV-\d+$")
TIME_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")

_ids = {"type": "array", "items": {"type": "string"}}
TOOLS = [
    ToolSpec("get_alert", "Read one alert by ID (Graph alerts_v2 shape). Recorded as evidence.",
             {"type": "object", "properties": {"alert_id": {"type": "string"}},
              "required": ["alert_id"], "additionalProperties": False}),
    ToolSpec("get_incident", "Read an incident and its alerts. Recorded as evidence.",
             {"type": "object", "properties": {"incident_id": {"type": "string"}},
              "required": ["incident_id"], "additionalProperties": False}),
    ToolSpec("run_hunting_query",
             "Run a read-only KQL query (advanced hunting). Management commands are refused. "
             "The result is recorded as evidence and its ID returned.",
             {"type": "object",
              "properties": {"kql": {"type": "string"},
                             "purpose": {"type": "string",
                                         "description": "Which hypothesis this tests."}},
              "required": ["kql", "purpose"], "additionalProperties": False}),
    ToolSpec("submit_verdict", "Submit the verdict. Ends the investigation if it is accepted.",
             {"type": "object",
              "properties": {
                  "verdict": {"type": "string", "enum": list(VERDICTS)},
                  "confidence": {"type": "string", "enum": list(CONFIDENCE)},
                  "summary": {"type": "string"},
                  "hypotheses": {"type": "array", "items": {
                      "type": "object",
                      "properties": {"hypothesis": {"type": "string"},
                                     "explanation": {"type": "string",
                                                     "enum": list(fx.EXPLANATIONS)},
                                     "status": {"type": "string",
                                                "enum": ["supported", "refuted", "open"]},
                                     "evidence_ids": _ids},
                      "required": ["hypothesis", "explanation", "status", "evidence_ids"],
                      "additionalProperties": False}},
                  "factors": {"type": "array", "items": {
                      "type": "object",
                      "properties": {"factor": {"type": "string",
                                                "description": "Factor ID, e.g. F1."},
                                     "state": {"type": "string", "enum": list(fx.STATES)},
                                     "reason": {"type": "string"},
                                     "evidence_ids": _ids},
                      "required": ["factor", "state", "reason", "evidence_ids"],
                      "additionalProperties": False}},
                  "timeline": {"type": "array", "items": {
                      "type": "object",
                      "properties": {"time": {"type": "string"},
                                     "event": {"type": "string"},
                                     "evidence_ids": _ids},
                      "required": ["time", "event", "evidence_ids"],
                      "additionalProperties": False}},
                  "findings": {"type": "array", "items": {
                      "type": "object",
                      "properties": {"statement": {"type": "string"},
                                     "evidence_ids": _ids},
                      "required": ["statement", "evidence_ids"],
                      "additionalProperties": False}},
                  "not_checked": {"type": "array", "items": {"type": "string"}},
                  "recommended_actions": {"type": "array", "items": {"type": "string"}},
                  "mitre_techniques": {"type": "array", "items": {"type": "string"}},
              },
              "required": ["verdict", "confidence", "summary", "hypotheses", "factors", "timeline",
                           "findings", "not_checked", "recommended_actions",
                           "mitre_techniques"],
              "additionalProperties": False}),
]


@dataclass
class Evidence:
    id: str
    kind: str            # alert | incident | query
    source: str          # backend
    query: str | None
    purpose: str
    provenance: list[str]
    columns: list
    rows: list[dict]
    truncated: bool
    sha256: str

    def text(self) -> str:
        return json.dumps(self.rows, sort_keys=True, default=str)


@dataclass
class Investigation:
    alert_id: str
    status: str                      # verdict | inconclusive: <reason>
    verdict: dict | None
    evidence: list[Evidence]
    case_note: str | None = None
    rejected_verdicts: list[dict] = field(default_factory=list)
    llm_turns: int = 0
    queries: int = 0
    usage: Usage = field(default_factory=Usage)
    models: list[str] = field(default_factory=list)
    agent_version: str = ""
    factor_set: str = ""
    factor_tally: dict | None = None
    missing_telemetry: list[dict] = field(default_factory=list)

    def to_json(self) -> dict:
        data = asdict(self)
        data["evidence"] = [dict(asdict(e), rows_count=len(e.rows)) for e in self.evidence]
        return data


def fence(evidence_id: str | None, payload: dict) -> str:
    """Tool output as data. The closing tag is neutralised inside the payload so log text
    cannot end the fence early."""
    body = json.dumps(payload, default=str, ensure_ascii=False)
    body = body.replace("</tool_output", "<\\/tool_output")
    attr = f' evidence_id="{evidence_id}"' if evidence_id else ""
    return f'<tool_output{attr} trust="untrusted-data">\n{body}\n</tool_output>'


def _hash(rows: list) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, default=str).encode()).hexdigest()


def _shown(rows: list[dict], limit: int, cell_chars: int) -> list[dict]:
    out = []
    for row in rows[:limit]:
        out.append({k: (v[:cell_chars] + "...[cut]") if isinstance(v, str) and len(v) > cell_chars
                    else v for k, v in row.items()})
    return out


def _time_key(value: str) -> str | None:
    """'2020-09-04T20:09:57.091Z' and '2020-09-04 20:09:57' -> '2020-09-04T20:09'."""
    value = value.strip()
    if not TIME_PREFIX.match(value):
        return None
    return value[:10] + "T" + value[11:16]


def check_verdict(verdict: dict, evidence: dict[str, Evidence],
                  factor_set: fx.FactorSet | None = None) -> list[str]:
    """Reasons to reject a submitted verdict; empty when accepted: the citation checks
    (`check_citations`), then the factor answers and decision rules of ADR 009
    (`factors.check_factors`, `factors.check_decision`)."""
    fset = factor_set or fx.for_alert({})
    return (check_citations(verdict, evidence) + fx.check_factors(verdict, evidence, fset)
            + fx.check_decision(verdict, evidence, fset))


def check_citations(verdict: dict, evidence: dict[str, Evidence]) -> list[str]:
    """Checks citations exist, every timeline entry and finding cites something, timeline
    times appear in the cited evidence, and a decided verdict rests on at least one
    finding (ADR 006)."""
    problems = []
    if verdict.get("verdict") not in VERDICTS:
        problems.append(f"verdict must be one of {VERDICTS}")
    if verdict.get("confidence") not in CONFIDENCE:
        problems.append(f"confidence must be one of {CONFIDENCE}")
    sections = [("timeline", "event"), ("findings", "statement"), ("hypotheses", "hypothesis"),
                ("factors", "factor")]
    for section, label in sections:
        for n, item in enumerate(verdict.get(section) or []):
            ids = item.get("evidence_ids") or []
            name = f"{section}[{n}] ({str(item.get(label, ''))[:60]!r})"
            if not ids and section not in ("hypotheses", "factors"):
                problems.append(f"{name} cites no evidence")
            unknown = [i for i in ids if i not in evidence]
            if unknown:
                problems.append(f"{name} cites unknown evidence {unknown}")
            if section == "timeline" and ids and not unknown:
                key = _time_key(str(item.get("time", "")))
                if key is None:
                    problems.append(f"{name}: time {item.get('time')!r} is not ISO 8601")
                else:
                    cited = " ".join(evidence[i].text().replace(" ", "T") for i in ids)
                    if key not in cited:
                        problems.append(f"{name}: time {item.get('time')!r} does not appear "
                                        f"in {ids}")
    if verdict.get("verdict") in ("true_positive", "benign") and not verdict.get("findings"):
        problems.append("a true_positive or benign verdict needs at least one finding")
    return problems


class InvestigationAgent:
    def __init__(self, connector: SecurityConnector, provider: Provider,
                 definition: AgentDefinition | None = None) -> None:
        self.connector = connector
        self.provider = provider
        self.definition = definition or load_definition(DEFINITION)
        d = self.definition
        self.max_turns = int(d.number("max_llm_turns", 24))
        self.max_queries = int(d.number("max_queries", 20))
        self.max_usd = d.number("max_case_usd", 3.0)
        self.rows_shown = int(d.number("rows_shown", 50))
        self.cell_chars = int(d.number("cell_chars", 1500))
        self.coverage_before = d.number("coverage_before_hours", 24)
        self.coverage_after = d.number("coverage_after_hours", 1)
        self.coverage_stale = d.number("coverage_stale_minutes", 15)

    # -- evidence ---------------------------------------------------------------

    def _record(self, inv: Investigation, kind: str, query: str | None, purpose: str,
                result: QueryResult | None = None, obj: dict | None = None) -> Evidence:
        n = len(inv.evidence)
        if result is not None:
            ev = Evidence(f"EV-{n}", kind, result.backend, query, purpose, result.provenance,
                          result.columns, result.rows, result.truncated, _hash(result.rows))
        else:
            rows = [obj or {}]
            ev = Evidence(f"EV-{n}", kind, self.connector.backend, query, purpose,
                          _provenance_of(obj or {}), [], rows, False, _hash(rows))
        inv.evidence.append(ev)
        return ev

    def _coverage(self, inv: Investigation, rows: list[dict], purpose: str,
                  query: str | None = None) -> Evidence:
        ev = Evidence(f"EV-{len(inv.evidence)}", "coverage", self.connector.backend, query,
                      purpose, [self.connector.backend, "telemetry coverage, computed by "
                                "ops-SOC code (ADR 009)"], [], rows, False, _hash(rows))
        inv.evidence.append(ev)
        return ev

    def _show(self, ev: Evidence) -> str:
        payload = {"evidence_id": ev.id, "kind": ev.kind, "provenance": ev.provenance,
                   "row_count": len(ev.rows), "truncated_at_source": ev.truncated,
                   "columns": ev.columns,
                   "rows": _shown(ev.rows, self.rows_shown, self.cell_chars)}
        if len(ev.rows) > self.rows_shown:
            payload["note"] = (f"showing {self.rows_shown} of {len(ev.rows)} rows; "
                               "narrow the query to see others")
        return fence(ev.id, payload)

    # -- tools ------------------------------------------------------------------

    def _tool(self, inv: Investigation, call: ToolCall) -> ToolResult:
        args = call.arguments
        try:
            if call.name == "get_alert":
                alert = self.connector.get_alert(str(args["alert_id"]))
                return ToolResult(call.id, self._show(
                    self._record(inv, "alert", None, "read alert", obj=alert)))
            if call.name == "get_incident":
                incident = self.connector.get_incident(str(args["incident_id"]))
                return ToolResult(call.id, self._show(
                    self._record(inv, "incident", None, "read incident", obj=incident)))
            if call.name == "run_hunting_query":
                if inv.queries >= self.max_queries:
                    return ToolResult(call.id, f"query budget used ({self.max_queries}); "
                                      "submit your verdict now", is_error=True)
                inv.queries += 1
                kql = str(args["kql"])
                result = self.connector.hunt(kql)
                return ToolResult(call.id, self._show(
                    self._record(inv, "query", kql, str(args.get("purpose", "")), result)))
        except ReadOnlyViolation as exc:
            return ToolResult(call.id, f"refused: {exc}", is_error=True)
        except KeyError as exc:
            return ToolResult(call.id, f"not found: {exc}", is_error=True)
        except (ValueError, RuntimeError) as exc:  # query errors from the engine / API
            if call.name == "run_hunting_query":
                missing = cov.unreadable_tables(self.connector, str(args.get("kql", "")))
                if missing:
                    ev = self._coverage(inv, [{"table": t, "state": "missing_table",
                                               "detail": str(exc)[:300],
                                               "source": "query failed; schema query for "
                                                         "this table failed too"}
                                              for t in missing],
                                        "a query named a table that cannot be read",
                                        str(args.get("kql", "")))
                    return ToolResult(call.id, self._show(ev), is_error=True)
            return ToolResult(call.id, fence(None, {"error": str(exc)[:2000]}), is_error=True)
        return ToolResult(call.id, f"unknown tool {call.name}", is_error=True)

    # -- loop -------------------------------------------------------------------

    def run(self, alert_id: str) -> Investigation:
        inv = Investigation(alert_id, "inconclusive: not started", None, [],
                            agent_version=f"{self.definition.name} v{self.definition.version}")
        try:
            alert = self.connector.get_alert(alert_id)
        except KeyError as exc:
            inv.status = f"inconclusive: alert not found ({exc})"
            return inv
        first = self._record(inv, "alert", None, "the alert under investigation", obj=alert)
        fset = fx.for_alert(alert)
        inv.factor_set = fset.label
        probed = self._coverage(inv, cov.probe(self.connector, fset, alert,
                                               self.coverage_before, self.coverage_after,
                                               self.coverage_stale),
                                "telemetry coverage for the factor tables around the alert")
        tier = Tier(self.definition.settings.get("tier_investigate", "reasoning"))
        conv = self.provider.conversation(tier, self.definition.prompt, TOOLS,
                                          purpose=f"investigate {alert_id}")
        inv.models.append(conv.model)
        opening = (f"Investigate alert {alert_id}.\n\n{fset.render()}\n\n"
                   f"The alert is evidence {first.id}:\n{self._show(first)}\n\n"
                   f"Telemetry coverage for the factor tables is evidence {probed.id}:\n"
                   f"{self._show(probed)}")
        try:
            turn = self._turn(inv, lambda: conv.send(opening))
            nudged = False
            last_call = False
            while True:
                verdict_calls = [c for c in turn.tool_calls if c.name == "submit_verdict"]
                results = []
                for call in turn.tool_calls:
                    if call.name == "submit_verdict":
                        continue
                    results.append(self._tool(inv, call))
                for call in verdict_calls:
                    problems = check_verdict(call.arguments, {e.id: e for e in inv.evidence},
                                             fset)
                    if not problems:
                        inv.verdict = call.arguments
                        inv.status = "verdict"
                        inv.factor_tally = fx.tally(call.arguments, fset)
                        inv.missing_telemetry = fx.missing_telemetry(
                            call.arguments, {e.id: e for e in inv.evidence}, fset)
                        break
                    inv.rejected_verdicts.append({"verdict": call.arguments,
                                                  "problems": problems})
                    results.append(ToolResult(call.id, "verdict rejected:\n- "
                                              + "\n- ".join(problems), is_error=True))
                if inv.verdict is not None:
                    break
                if last_call:
                    inv.status = "inconclusive: stopped: budget (no valid verdict after the " \
                                 "final request)"
                    break
                reason = self._budget_left(inv)
                prompt = None
                if reason:
                    last_call = True
                    prompt = (f"Budget reached ({reason}). Submit your verdict now with "
                              "submit_verdict, using only the evidence you have.")
                if not turn.tool_calls:
                    if turn.stop in ("refusal", "max_tokens"):
                        inv.status = f"inconclusive: model stopped ({turn.stop})"
                        break
                    if nudged and not last_call:
                        inv.status = "inconclusive: the model ended without submit_verdict"
                        break
                    nudged = True
                    turn = self._turn(inv, lambda p=prompt: conv.send(
                        p or "End the investigation by calling submit_verdict."))
                    continue
                turn = self._turn(inv, lambda r=results, p=prompt: conv.send_tool_results(r, p))
        except BudgetExceeded as exc:
            inv.status = f"inconclusive: stopped: budget ({exc})"
        except LLMError as exc:
            inv.status = f"inconclusive: LLM error ({exc})"
        if inv.verdict is not None:
            inv.case_note = self._case_note(inv)
        return inv

    def _turn(self, inv: Investigation, send) -> Turn:
        turn = send()
        inv.llm_turns += 1
        inv.usage.add(turn.usage)
        if turn.model not in inv.models:
            inv.models.append(turn.model)
        return turn

    def _budget_left(self, inv: Investigation) -> str | None:
        if inv.llm_turns >= self.max_turns - 1:
            return f"{self.max_turns} model turns"
        if inv.usage.cost_usd >= self.max_usd:
            return f"USD {self.max_usd:.2f} for this case"
        return None

    def _case_note(self, inv: Investigation) -> str | None:
        """A short analyst note for the SOAR, written on the writing tier from the
        accepted verdict only. If it fails, the verdict's own summary is used."""
        tier = Tier(self.definition.settings.get("tier_case_note", "writing"))
        system = ("Write a case note for a SOC analyst: three to five plain sentences. "
                  "State the verdict and confidence, the key evidence with its IDs, and what "
                  "was not checked. Use only the verdict JSON you are given.")
        try:
            conv = self.provider.conversation(tier, system, [], max_tokens=2000,
                                              purpose=f"case note {inv.alert_id}")
            turn = self._turn(inv, lambda: conv.send(fence(None, inv.verdict)))
        except (BudgetExceeded, LLMError):
            return None
        return turn.text.strip() or None


# -- case report --------------------------------------------------------------------

SEVERITY = {"informational": Severity.INFORMATIONAL, "low": Severity.LOW,
            "medium": Severity.MEDIUM, "high": Severity.HIGH}


def _provenance_of(alert: dict) -> list[str]:
    prov = (alert.get("additionalData") or {}).get("provenance")
    return [prov] if prov else []


def _label(ev: Evidence) -> str:
    text = " ".join(ev.provenance)
    if "mapped by" in text:
        return "mapped"
    if text.startswith("live") or "(live" in ev.source:
        return "live"
    if "seeded by" in text:
        return "seeded alert"
    if "computed by ops-SOC" in text:
        return "computed"
    return "recorded"


def to_case_report(inv: Investigation, alert: dict) -> CaseReport:
    """The SOAR writer's input. Only cited evidence goes in; each item says which
    findings cite it."""
    v = inv.verdict or {}
    cited: dict[str, list[str]] = {}
    for item in (v.get("findings") or []) + (v.get("timeline") or []):
        text = item.get("statement") or item.get("event") or ""
        for ev_id in item.get("evidence_ids") or []:
            cited.setdefault(ev_id, []).append(text)
    by_id = {e.id: e for e in inv.evidence}
    items = []
    for ev_id, texts in sorted(cited.items(), key=lambda kv: int(kv[0][3:])):
        if ev_id not in by_id:
            continue
        ev = by_id[ev_id]
        items.append(EvidenceItem(id=ev_id, source=f"{ev.source.split(' ')[0]}:{ev.kind}",
                                  finding="; ".join(dict.fromkeys(texts))[:1000],
                                  query=ev.query, provenance=_label(ev)))
    verdict = v.get("verdict") if inv.status == "verdict" else "inconclusive"
    summary = inv.case_note or v.get("summary") or inv.status
    if inv.status != "verdict":
        summary = f"No verdict: {inv.status}."
    host = next((e.get("deviceDnsName") for e in alert.get("evidence") or []
                 if e.get("deviceDnsName")), None)
    title = alert.get("title", "alert") + (f" on {host}" if host else "")
    case_id = "OPS-" + re.sub(r"[^A-Za-z0-9_-]", "_", inv.alert_id)[:60]
    return CaseReport(
        case_id=case_id, title=title, verdict=Verdict(verdict),
        severity=SEVERITY.get(str(alert.get("severity", "")).lower(), Severity.INFORMATIONAL),
        summary=f"[{v.get('confidence', 'n/a')} confidence] {summary}" if v else summary,
        source_alert_id=inv.alert_id, evidence=items,
        recommended_actions=list(v.get("recommended_actions") or []),
        mitre_techniques=list(v.get("mitre_techniques") or alert.get("mitreTechniques") or []),
        missing_telemetry=[f"{m['factor']} {m['name']} ({m['weight']}): " + "; ".join(
            f"{g['table']} {g['state']} [{g['evidence_id']}]" for g in m["gaps"])
            for m in inv.missing_telemetry])
