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
    by_rule = Counter(a["additionalData"]["dacRule"][:8] for a in alerts)
    assert by_rule == {"e07878fc": 2, "cbbad913": 2, "20cda3e9": 2, "00e5982f": 1}
    assert len({a["id"] for a in alerts}) == 7
    assert all(a["classification"] == "unknown" for a in alerts)
    listed = replay.list_alerts()
    assert len(listed) == 7
    incident = replay.get_incident(listed[0]["incidentId"])
    assert listed[0] in incident["alerts"]


def test_sentinel_tables_loaded(replay):
    result = replay.hunt("SecurityEvent | where EventID == 4688 | count")
    assert result.rows[0]["Count"] > 0
    assert any("detection_As_Code" in p for p in result.provenance)
