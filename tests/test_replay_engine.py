"""Replay against a real Kusto emulator. Runs only when OPSSOC_KUSTO_URL is set
(CI job `replay-kusto`); the data must be loaded first with
`python -m opssoc.replay fetch && python -m opssoc.replay seed` (seed needs a
detection_As_Code checkout in OPSSOC_DAC_PATH and loads every dataset at the end)."""

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from opssoc.connectors import ReplayConnector
from opssoc.replay.kusto import KustoClient

pytestmark = pytest.mark.skipif(not os.environ.get("OPSSOC_KUSTO_URL"),
                                reason="needs the Kusto emulator (OPSSOC_KUSTO_URL)")


@pytest.fixture(scope="module")
def replay():
    return ReplayConnector(KustoClient())


def test_reg_save_sam_is_found(replay):
    result = replay.hunt(
        "DeviceProcessEvents | where FileName =~ 'reg.exe' and ProcessCommandLine has 'save' "
        "and ProcessCommandLine has @'HKLM\\sam' | project DeviceName, InitiatingProcessFileName")
    assert result.rows == [{"DeviceName": "workstation5.theshire.local",
                            "InitiatingProcessFileName": "powershell.exe"}]
    assert any("not Defender telemetry" in p for p in result.provenance)


def test_encoded_powershell_parent_chain(replay):
    result = replay.hunt(
        "DeviceProcessEvents | where FileName =~ 'powershell.exe' and ProcessCommandLine has '-enc'"
        " | project InitiatingProcessFileName, InitiatingProcessParentFileName")
    assert {"InitiatingProcessFileName": "wscript.exe",
            "InitiatingProcessParentFileName": "explorer.exe"} in result.rows


def test_tables_and_types(replay):
    result = replay.hunt("DeviceNetworkEvents | summarize n=count(), ports=dcount(RemotePort)")
    assert result.rows[0]["n"] == 301
    query = "DeviceNetworkEvents | take 1 | project RemotePort, Timestamp"
    types = dict(replay.hunt(query).columns)
    assert types == {"RemotePort": "int", "Timestamp": "datetime"}


ALERTS = Path("data/replay/alerts.json")


@pytest.mark.skipif(not ALERTS.is_file(), reason="run `python -m opssoc.replay seed` first")
def test_seeded_alerts_match_dac_results(replay):
    """The four endpoint rules give the same matches on the six datasets as DaC's committed
    Kusto results (A1 2, A2 2, A3 2, A4 1), now as alerts with one dataset each."""
    alerts = json.loads(ALERTS.read_text())["alerts"]
    dac = [a for a in alerts if "dacRule" in a["additionalData"]]
    by_rule = Counter(a["additionalData"]["dacRule"][:8] for a in dac)
    assert by_rule == {"e07878fc": 2, "cbbad913": 2, "20cda3e9": 2, "00e5982f": 1}
    assert len({a["id"] for a in dac}) == 7
    assert all(a["classification"] == "unknown" for a in alerts)
    listed = replay.list_alerts(top=100)
    assert len(listed) == len(alerts)
    incident = replay.get_incident(listed[0]["incidentId"])
    assert listed[0] in incident["alerts"]


def test_sentinel_tables_loaded(replay):
    result = replay.hunt("SecurityEvent | where EventID == 4688 | count")
    assert result.rows[0]["Count"] > 0
    assert any("detection_As_Code" in p for p in result.provenance)


@pytest.mark.skipif(not ALERTS.is_file(), reason="run `python -m opssoc.replay seed` first")
def test_investigation_tools_on_the_emulator(replay, tmp_path):
    """The agent's tools against the real emulator: a scripted turn (written here, not
    model output) queries around a seeded A3 alert; the result is recorded as evidence
    with the replay mapping label."""
    from opssoc.agents.investigation import InvestigationAgent
    from opssoc.llm import SpendTracker, Tier, ToolCall, Turn, Usage
    from opssoc.llm.scripted import ScriptedProvider

    alert = next(a for a in replay.list_alerts() if a["providerAlertId"].startswith("20cda3e9"))
    kql = ("DeviceProcessEvents | where FileName =~ 'reg.exe' and ProcessCommandLine has "
           "'save' | project Timestamp, DeviceName, InitiatingProcessFileName")
    spend = SpendTracker(tmp_path / "s.jsonl", env={"OPSSOC_LLM_PRICES":
                                                     '{"scripted-reasoning": [0, 0]}'})
    provider = ScriptedProvider({Tier.REASONING: [
        Turn("", [ToolCall("c1", "run_hunting_query", {"kql": kql, "purpose": "p"})],
             "tool_use", "", Usage()),
        Turn("done", [], "end", "", Usage()), Turn("done", [], "end", "", Usage())]}, spend)
    inv = InvestigationAgent(replay, provider).run(alert["id"])
    assert inv.status == "inconclusive: the model ended without submit_verdict"
    ev = inv.evidence[2]  # EV-1 is the coverage probe (ADR 009)
    assert ev.rows and all(r["InitiatingProcessFileName"] == "powershell.exe" for r in ev.rows)
    assert any("not Defender telemetry" in p for p in ev.provenance)


@pytest.mark.skipif(not ALERTS.is_file(), reason="run `python -m opssoc.replay seed --eval-rules`")
def test_eval_rules_and_ground_truth_cover_every_alert():
    """CI seeds with --eval-rules: e1 matches the SAM save and the grouped Network Watcher
    exports, e2 the two Updater values and Defender's own Run value. Every alert is
    labelled by exactly one ground-truth case."""
    from opssoc.eval.cases import load_cases, match

    alerts = json.loads(ALERTS.read_text())["alerts"]
    by_eval = Counter(a["additionalData"].get("evalRule") for a in alerts
                      if "evalRule" in a["additionalData"])
    assert by_eval == {"ops-eval-e1": 2, "ops-eval-e2": 3}
    m = match(load_cases(), alerts)
    assert m.problems == [] and m.unlabelled == []
    assert len(m.pairs) == 14  # 12 alerts; two constructed cases reuse a labelled alert


def test_key_facts_are_in_the_recorded_data():
    """Every key fact a case expects is a string from that dataset's recorded events."""
    from opssoc.eval.cases import load_cases
    from opssoc.replay.__main__ import dataset_events

    text = {}
    for case in [c for c in load_cases() if not c.hide_tables]:
        if case.dataset not in text:
            raw = json.dumps(dataset_events(case.dataset))
            text[case.dataset] = raw.replace("\\\\", "\\").lower()
        missing = [f for f in case.key_facts if f.lower() not in text[case.dataset]]
        assert not missing, (case.id, missing)


def test_coverage_probe_on_the_emulator(replay):
    """ADR 009 step 2: the probe on seeded alerts in the real emulator. The A3 alert's
    host has process and Security rows around it, and no network or registry rows. A
    table that does not exist is found by its schema query (the emulator's error does
    not name it). The A4 bitsadmin alert's host has no Device* rows within the window:
    the recorded Sysmon events are about four hours after the Security events."""
    from opssoc.agents.investigation import coverage as cov
    from opssoc.agents.investigation import factors as fx

    fset = fx.for_alert({})
    a3 = next(a for a in replay.list_alerts(100) if a["providerAlertId"].startswith("20cda3e9"))
    states = {r["table"]: r["state"] for r in cov.probe(replay, fset, a3)}
    assert states == {"DeviceProcessEvents": "present", "DeviceNetworkEvents": "no_rows_for_host",
                      "DeviceFileEvents": "present", "DeviceRegistryEvents": "no_rows_for_host",
                      "SecurityEvent": "present"}
    assert cov.unreadable_tables(replay, "DeviceLogonEvents | take 1") == ["DeviceLogonEvents"]
    assert cov.unreadable_tables(replay, "DeviceProcessEvents | where NoSuchColumn == 1") == []
    a4 = next(a for a in replay.list_alerts(100)
              if a["additionalData"]["replayDataset"] == "otrf-bitsadmin-download")
    states = {r["table"]: r["state"] for r in cov.probe(replay, fset, a4)}
    assert states["DeviceProcessEvents"] == "no_rows_for_host"
    assert states["SecurityEvent"] == "present"
