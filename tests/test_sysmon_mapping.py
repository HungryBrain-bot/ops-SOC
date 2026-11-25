from pathlib import Path

import pytest

from opssoc.replay.sysmon_to_defender import (
    TABLES,
    SysmonToDefender,
    read_events,
    registry_key,
    registry_value,
    schema,
)

FIXTURE = Path(__file__).parent / "fixtures" / "otrf_empire_launcher_vbs_extract.jsonl"


@pytest.fixture(scope="module")
def mapped():
    return SysmonToDefender().map(read_events(FIXTURE))


def by_file(rows, name):
    return next(r for r in rows if r["FileName"] == name)


def test_counts_and_skips(mapped):
    assert mapped.counts() == {"DeviceProcessEvents": 3, "DeviceNetworkEvents": 1,
                               "DeviceFileEvents": 1, "DeviceRegistryEvents": 2}
    assert dict(mapped.skipped) == {("Security", 5158): 1}


def test_every_column_is_in_the_vendor_schema(mapped):
    for table in TABLES:
        columns = schema(table)
        for row in mapped.rows[table]:
            assert set(row) <= set(columns), table
            assert row["Type"] == table


def test_process_create_uses_the_parent_as_initiating_process(mapped):
    ps = by_file(mapped.rows["DeviceProcessEvents"], "powershell.exe")
    assert ps["ActionType"] == "ProcessCreated"
    assert ps["ProcessCommandLine"].startswith(
        '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -noP -sta -w 1 -enc')
    assert ps["InitiatingProcessFileName"] == "wscript.exe"
    assert "launcher.vbs" in ps["InitiatingProcessCommandLine"]
    # grandparent from the event itself (explorer.exe's own Sysmon 1 is not in the dataset)
    assert ps["InitiatingProcessParentFileName"] == "explorer.exe"
    assert ps["DeviceName"] == "workstation5.theshire.local"
    assert ps["AccountDomain"] == "THESHIRE" and ps["AccountName"] == "pgustavo"
    assert len(ps["SHA256"]) == 64 and ps["SHA256"] == ps["SHA256"].lower()


def test_parent_not_in_dataset_falls_back_to_the_event(mapped):
    wscript = by_file(mapped.rows["DeviceProcessEvents"], "wscript.exe")
    assert wscript["InitiatingProcessFileName"] == "explorer.exe"
    assert wscript["InitiatingProcessCommandLine"]  # from ParentCommandLine
    assert "InitiatingProcessSHA256" not in wscript


def test_network_event_is_resolved_to_its_process(mapped):
    net = mapped.rows["DeviceNetworkEvents"][0]
    assert net["ActionType"] == "ConnectionSuccess"
    assert (net["RemoteIP"], net["RemotePort"]) == ("10.10.10.5", 80)
    assert net["InitiatingProcessFileName"] == "powershell.exe"
    assert net["InitiatingProcessParentFileName"] == "wscript.exe"
    assert net["Protocol"] == "Tcp"


def test_registry_events(mapped):
    rows = {r["ActionType"]: r for r in mapped.rows["DeviceRegistryEvents"]}
    created = rows["RegistryKeyCreated"]
    assert created["RegistryKey"] == (
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings")
    value = rows["RegistryValueSet"]
    assert value["RegistryKey"].startswith("HKEY_USERS\\S-1-5-21-")
    assert value["RegistryValueName"] == "ProxyBypass"
    assert value["InitiatingProcessFileName"] == "WScript.exe"


def test_registry_helpers():
    assert registry_key("HKCU\\Software\\X") == "HKEY_CURRENT_USER\\Software\\X"
    assert registry_value("DWORD (0x0000001f)") == ("Dword", "31")
    assert registry_value("C:\\evil.exe") == ("String", "C:\\evil.exe")
    assert registry_value(None) == ("", "")
