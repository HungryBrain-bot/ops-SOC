"""Replay against a real Kusto emulator. Runs only when OPSSOC_KUSTO_URL is set
(CI job `replay-kusto`); the data must be loaded first with
`python -m opssoc.replay fetch && python -m opssoc.replay load`."""

import os

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
    assert result.rows[0]["n"] == 64
    query = "DeviceNetworkEvents | take 1 | project RemotePort, Timestamp"
    types = dict(replay.hunt(query).columns)
    assert types == {"RemotePort": "int", "Timestamp": "datetime"}
