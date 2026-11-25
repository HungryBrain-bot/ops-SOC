"""Threat intel (ADR 008): ATT&CK and KEV readers, profile checks, priorities, coverage,
KEV links, brief checks. Offline, on recorded extracts of the pinned snapshots
(tests/fixtures/intel/README.md). Scripted brief turns are written here, not model output.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from opssoc.agents.threat_intel.agent import (
    check_brief,
    report_markdown,
    write_brief,
)
from opssoc.intel import finance
from opssoc.intel.attack import Attack, plain
from opssoc.intel.kev import Kev
from opssoc.llm import SpendTracker, Tier, Turn, Usage
from opssoc.llm.scripted import ScriptedProvider

FIX = Path("tests/fixtures/intel")
ATTACK = Attack.from_bundle(json.loads((FIX / "attack_subset.json").read_text()))
KEV = Kev.from_catalog(json.loads((FIX / "kev_subset.json").read_text()))
COBALT = ("Cobalt Group is a financially motivated threat group that has primarily targeted "
          "financial institutions since at least 2016.")
OILRIG = ("The group has targeted a variety of sectors, including financial, government, "
          "energy, chemical, and telecommunications.")


WEB = {"status": "confirmed", "sources": [{"publisher": "P", "url": "https://example.org/r",
                                           "fetched": "2026-11-25", "quote": "q"}]}


def pg(gid, name, tier, sentence, web=WEB):
    return finance.ProfileGroup(gid, name, tier, sentence, web)


def profile(**over):
    p = {"status": "proposed", "tier_weights": {"primary": 2, "listed": 1},
         "groups": [pg("G0080", "Cobalt Group", "primary", COBALT),
                    pg("G0049", "OilRig", "listed", OILRIG)],
         "excluded": [{"id": "G0032", "name": "Lazarus Group", "reason": "r"}]}
    p.update(over)
    return p


@dataclass
class FakeRule:
    data: dict
    folder: Path


def rule(name, techniques, status="test"):
    return FakeRule({"status": status, "mapping": {"attack": {"techniques": techniques}}},
                    Path(name))


def test_plain_strips_links_and_citations():
    assert plain("[Cobalt Group](https://attack.mitre.org/groups/G0080) used X."
                 "(Citation: Talos Cobalt Group July 2018) Then Y.") == \
        "Cobalt Group used X. Then Y."


def test_attack_reader():
    assert ATTACK.version == "ATT&CK Enterprise v20.1"
    assert {"G0080", "G0082", "G0049", "G0032"} <= set(ATTACK.groups)
    assert ATTACK.techniques["T1059.001"].tactics == ["execution"]
    assert ATTACK.techniques["T1059.001"].is_subtechnique
    assert {"T1059.001", "T1566.001", "T1588.002"} <= ATTACK.techniques_of("G0080")
    cves = dict(ATTACK.cve_mentions("G0080"))
    assert "CVE-2017-11882" in cves and "CVE-2017-11882" in cves["CVE-2017-11882"]


def test_profile_check():
    assert finance.check_profile(profile(), ATTACK) == []
    bad = profile(groups=[pg("G0080", "Cobalt", "primary", "made up"),
                          pg("G9999", "X", "listed", "y"),
                          pg("G0032", "Lazarus", "main", "z")])
    problems = finance.check_profile(bad, ATTACK)
    assert "G0080: source sentence not in its ATT&CK description" in problems
    assert any(p.startswith("G9999: not an active group") for p in problems)
    assert "G0032: unknown tier main" in problems
    assert "G0032: both included and excluded" in problems


def test_profile_check_web_evidence():
    # A group chosen from web reporting alone has no ATT&CK sentence; that passes.
    assert finance.check_profile(profile(groups=[pg("G0032", "Lazarus", "listed", None)],
                                         excluded=[]), ATTACK) == []
    bad = profile(groups=[
        pg("G0080", "Cobalt", "primary", COBALT, web={}),
        pg("G0049", "OilRig", "listed", OILRIG,
           web={"status": "not_found", "sources": [{"publisher": "P", "url": "u"}]})])
    problems = finance.check_profile(bad, ATTACK)
    assert "G0080: web evidence status None, needs one of ['confirmed', 'weak']" in problems
    assert "G0080: no web evidence source" in problems
    assert "G0049: web evidence status 'not_found', needs one of ['confirmed', 'weak']" in problems
    assert "G0049: web source missing fetched, quote" in problems


def test_priorities_and_coverage():
    rules = [rule("A1", ["T1059.001"]), rule("P", ["T1566"]), rule("X", ["T1588.002"],
                                                                     "experimental")]
    result = finance.analyse(profile(), ATTACK, KEV, rules, top=10)
    by_id = {t["id"]: t for t in result["priority_techniques"]}
    assert by_id["T1059.001"]["score"] == 3 and by_id["T1059.001"]["groups"] == ["G0049",
                                                                               "G0080"]
    assert by_id["T1059.001"]["coverage"] == "exact"
    assert by_id["T1566.001"]["coverage"] == "partial"          # rule maps the parent
    assert by_id["T1059.003"]["coverage"] == "none"             # sibling is not coverage
    assert by_id["T1588.002"]["coverage"] == "none"             # experimental rule ignored
    gaps = [t["id"] for t in result["gaps"]]
    assert "T1059.003" in gaps and "T1588.002" not in gaps      # resource development
    assert [t["id"] for t in result["pre_compromise"]] == ["T1588.002"]
    assert result["priority_techniques"][0]["score"] >= result["priority_techniques"][-1]["score"]


def test_parent_technique_partially_covered_by_sub_technique_rule():
    result = finance.analyse(profile(), ATTACK, KEV, [rule("A1", ["T1059.001"])])
    t1059 = next(t for t in result["priority_techniques"] if t["id"] == "T1059")
    assert t1059["coverage"] == "partial" and t1059["rules"] == ["A1"]


def test_kev_links():
    rows = {r["cve"]: r for r in finance.kev_links(profile(), ATTACK, KEV)}
    assert rows["CVE-2017-11882"]["in_kev"] and rows["CVE-2017-11882"]["groups"] == ["G0080"]
    assert rows["CVE-2017-11882"]["vendor"] == "Microsoft"
    assert rows["CVE-2017-11774"]["groups"] == ["G0049"]
    assert all(r["attack_sentences"] for r in rows.values())


def test_no_rules_means_no_gap_list():
    assert finance.analyse(profile(), ATTACK, KEV, None)["gaps"] is None


ANALYSIS = finance.analyse(profile(), ATTACK, KEV, [rule("A1", ["T1059.001"])])


def test_check_brief():
    assert check_brief("G0080 uses T1059.001; patch CVE-2017-11882.", ANALYSIS) == []
    assert check_brief("G0082 and T9999 matter.", ANALYSIS) == [
        "names IDs not in the data: G0082, T9999"]
    assert "names no group, technique or CVE ID" in check_brief("Patch things.", ANALYSIS)


def scripted(turns, tmp_path, cap=100.0):
    spend = SpendTracker(tmp_path / "s.jsonl", cap_usd=cap,
                         env={"OPSSOC_LLM_PRICES": '{"scripted-writing": [2, 10]}'})
    return ScriptedProvider({Tier.WRITING: turns}, spend)


def test_brief_rejected_then_accepted(tmp_path):
    provider = scripted([Turn("APT38 (G0082) uses T1059.001.", [], "end", "", Usage(100, 50)),
                         Turn("Cobalt Group (G0080) uses T1059.001; patch CVE-2017-11882.",
                              [], "end", "", Usage(100, 50))], tmp_path)
    brief = write_brief(provider, ANALYSIS)
    assert brief.status == "accepted" and brief.text.startswith("Cobalt Group")
    assert brief.attempts[0]["problems"] == ["names IDs not in the data: G0082"]
    sent = provider.conversations[0].events
    assert sent[0][1].startswith("<tool_output") and "Rejected:" in sent[2][1]
    assert brief.cost_usd == pytest.approx(2 * (100 * 2 + 50 * 10) / 1e6)


def test_brief_budget(tmp_path):
    brief = write_brief(scripted([], tmp_path, cap=0.0), ANALYSIS)
    assert brief.text is None and brief.status.startswith("not written: monthly LLM cap")


def test_report_markdown():
    md = report_markdown(ANALYSIS)
    assert md.startswith("# Finance-sector threat priorities")
    assert "| T1059.001 |" in md and "exact (A1)" in md
    assert "CVE-2017-11882" in md and COBALT in md
    assert "## What this does not say" in md and "model-written" not in md


def test_real_profile_file_shape():
    p = finance.load_profile()
    assert p["status"] == "proposed" and len(p["groups"]) == 25
    assert {g.tier for g in p["groups"]} == {"primary", "listed"}
    assert len({g.id for g in p["groups"]}) == 25
    assert all(e["reason"] for e in p["excluded"])
    # Owner's rule (2026-11-25): every included group has a fetched web source.
    assert all(g.web_evidence["status"] in {"confirmed", "weak"} and g.web_evidence["sources"]
               for g in p["groups"])
    assert {e["id"] for e in p["excluded"]} == {"G0048", "G1054", "G1009",
                                                 "G0018", "G0053", "G0037"}
    assert {"G0032", "G0085", "G1049"} <= {g.id for g in p["groups"]}
