"""Eval harness (ADR 007): ground truth integrity, case matching, scoring. Offline.

Alerts here are built by the seeding code from rows of detection_As_Code's committed
Kusto results (recorded OTRF events, mapped by DaC) and, for the benign cases, from
rows written in the shape the eval rules return. Investigation records are written in
the test; they are not model output.
"""

import json
import re
from pathlib import Path

import pytest

from opssoc.eval import __main__ as cli
from opssoc.eval.cases import load_cases, load_eval_rules, load_sources, match
from opssoc.eval.score import score_case, summarise
from opssoc.replay import seed
from opssoc.replay.__main__ import PINS

DAC_RULES = {"e07878fc-1056-45fc-91bf-0fffe5a4ce10", "cbbad913-22f2-49cb-ad4c-85b2370acc24",
             "20cda3e9-edbf-48e5-8994-fe1dbd1d3d18", "00e5982f-6fb1-4920-a25e-1c5ddd845015"}
CASES = load_cases()


def test_ground_truth_integrity():
    sources = load_sources()
    eval_ids = {r.id for r in load_eval_rules()}
    assert len({c.id for c in CASES}) == len(CASES) == 12
    for case in CASES:
        assert case.rule in DAC_RULES | eval_ids
        assert case.dataset in PINS["datasets"]
        assert case.expected_verdict in ("true_positive", "benign")
        assert case.key_facts
        if case.label["kind"] == "otrf-metadata":
            assert sources[case.label["ref"]]["dataset"] == case.dataset
        else:
            assert case.label["kind"] == "ops-soc-judgment" and len(case.label["basis"]) > 100
    for ref, source in sources.items():
        assert re.fullmatch(r"SDWIN-\d{12}", ref) and len(source["sha256"]) == 64
    assert {c.expected_verdict for c in CASES} == {"true_positive", "benign"}


def test_eval_rules_are_loosened_rules_not_detections():
    rules = load_eval_rules()
    assert [r.id for r in rules] == ["ops-eval-e1", "ops-eval-e2"]
    for rule in rules:
        assert rule.data["status"] == "eval"
        assert set(rule.required_fields("sentinel")) <= {"SecurityEvent", "Event"}
    # e2 is A2 without its three writer exclusions.
    assert "where not" not in rules[1].data["sentinel"]["query"]


def test_agent_code_never_reads_ground_truth():
    for path in Path("opssoc/agents").rglob("*"):
        if path.suffix in (".py", ".md"):
            text = path.read_text(encoding="utf-8")
            assert "ground_truth" not in text and "opssoc.eval" not in text, path


A3 = {"id": "20cda3e9-edbf-48e5-8994-fe1dbd1d3d18", "name": "SAM dump", "severity": "High"}
E1 = {"id": "ops-eval-e1", "name": "reg.exe saved or exported an HKLM registry key"}
SAM_ROW = {"TimeGenerated": "2020-09-22T08:28:42.564Z", "Computer": "WORKSTATION5.theshire.local",
           "Account": "THESHIRE\\pgustavo", "NewProcessName": "C:\\Windows\\System32\\reg.exe",
           "CommandLine": "\"C:\\windows\\system32\\reg.exe\" save HKLM\\sam sam",
           "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
EXPORT_ROW = {"TimeGenerated": "2020-09-04T07:09:22.199Z",
              "Computer": "WORKSTATION5.theshire.local", "Account": "THESHIRE\\WORKSTATION5$",
              "NewProcessName": "C:\\Windows\\System32\\reg.exe",
              "ParentProcessName": "C:\\Windows\\System32\\cmd.exe", "Commands": 14,
              "CommandLine": "reg  export \"HKLM\\SOFTWARE\\Microsoft\\Wlansvc\" Reg\\x.reg.txt /y"}


def test_match_pairs_and_reports_gaps():
    alerts = [seed.to_alert(A3, SAM_ROW, "otrf-empire-reg-dump-sam", "t"),
              seed.to_alert(E1, SAM_ROW, "otrf-empire-reg-dump-sam", "t", seed.PROBE_KIND),
              seed.to_alert(E1, EXPORT_ROW, "otrf-empire-runkey-standard-user", "t",
                            seed.PROBE_KIND),
              seed.to_alert(A3, SAM_ROW, "otrf-bitsadmin-download", "t")]
    m = match(CASES, alerts)
    assert m.pairs["tp-a3-reg-save-sam"]["id"] == alerts[0]["id"]
    assert m.pairs["tp-e1-reg-save-sam"]["id"] == alerts[1]["id"]
    assert m.pairs["bn-e1-network-watcher-diagnostics"]["id"] == alerts[2]["id"]
    assert [a["id"] for a in m.unlabelled] == [alerts[3]["id"]]
    assert "tp-a4-bitsadmin: 0 alerts match (need exactly 1)" in m.problems
    twice = match(CASES, alerts + [dict(alerts[0], id="dup")])
    assert "tp-a3-reg-save-sam: 2 alerts match (need exactly 1)" in twice.problems


def record(verdict=None, status="verdict", rows=None):
    rows = rows if rows is not None else [SAM_ROW]
    return {"status": status, "verdict": verdict, "llm_turns": 5, "queries": 3,
            "rejected_verdicts": [], "models": ["m"], "usage": {"cost_usd": 0.42},
            "evidence": [{"id": "EV-0", "kind": "alert", "source": "replay", "query": None,
                          "purpose": "", "provenance": [], "columns": [], "rows": rows,
                          "truncated": False, "sha256": "x"}]}


def tp_verdict(**over):
    v = {"verdict": "true_positive", "confidence": "high",
         "summary": "reg.exe saved HKLM\\sam from powershell.exe.",
         "hypotheses": [], "timeline": [{"time": "2020-09-22T08:28:42Z",
                                         "event": "reg.exe save", "evidence_ids": ["EV-0"]}],
         "findings": [{"statement": "SAM saved", "evidence_ids": ["EV-0"]}],
         "not_checked": [], "recommended_actions": [], "mitre_techniques": []}
    v.update(over)
    return v


CASE = next(c for c in CASES if c.id == "tp-a3-reg-save-sam")


def test_score_correct_case():
    r = score_case(CASE, record(tp_verdict()))
    assert r["verdict_correct"] and r["citations_valid"]
    # No factor answers (agent v1 shape): the ADR 009 checks fail, citations still hold.
    assert r["factor_checks_valid"] is False and r["factor_tally"] is None
    assert r["key_fact_recall"] == 1.0 and r["grounded_fact_recall"] == 1.0
    assert r["cost_usd"] == 0.42 and r["facts_missing"] == []


def test_score_ungrounded_facts_and_wrong_verdict():
    # Facts stated, but the cited evidence does not hold powershell.exe.
    rows = [dict(SAM_ROW, ParentProcessName="cmd.exe")]
    r = score_case(CASE, record(tp_verdict(verdict="benign"), rows=rows))
    assert not r["verdict_correct"]
    assert r["key_fact_recall"] == 1.0 and r["grounded_fact_recall"] == pytest.approx(0.667)


def test_score_no_verdict_and_invalid_citation():
    none = score_case(CASE, record(status="inconclusive: stopped: budget (x)"))
    assert none["verdict"] is None and not none["verdict_correct"]
    assert none["facts_missing"] == CASE.key_facts
    bad = score_case(CASE, record(tp_verdict(findings=[{"statement": "x",
                                                        "evidence_ids": ["EV-4"]}])))
    assert bad["citations_valid"] is False


def test_summary():
    results = [score_case(CASE, record(tp_verdict())),
               score_case(CASE, record(status="inconclusive: stopped: budget (x)"))]
    s = summarise(results)
    assert s["cases"] == 2 and s["verdict_accuracy"] == 0.5 and s["budget_stops"] == 1
    assert s["confusion"] == {"true_positive -> no verdict": 1,
                              "true_positive -> true_positive": 1}
    assert s["cost_usd"] == 0.84


def test_run_refuses_without_yes(tmp_path):
    alerts = tmp_path / "alerts.json"
    alerts.write_text(json.dumps({"alerts": []}))
    with pytest.raises(SystemExit, match="alerts match"):
        cli.main(["run", "--provider", "anthropic", "--alerts", str(alerts)])
