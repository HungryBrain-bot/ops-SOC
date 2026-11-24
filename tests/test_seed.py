"""Seeded replay alerts (ADR 004): alert shape, evidence, rule selection. Offline.

The rule fields below are a trimmed copy of detection_As_Code rule A3 (commit 51080aa).
The matched rows are copied from DaC's committed Kusto-emulator results
(detections/endpoint/A3-.../tests/results/kusto.json and A2's), i.e. recorded OTRF
events as mapped by DaC's harness. The engine run itself is tests/test_replay_engine.py.
"""

from dataclasses import dataclass, field

from opssoc.replay import seed

A3 = {"id": "20cda3e9-edbf-48e5-8994-fe1dbd1d3d18", "version": 1, "status": "test",
      "name": "SAM, SYSTEM or SECURITY hive saved with reg.exe or copied from the config folder",
      "severity": "High", "description": "A process command line that saves\n  the SAM hive.",
      "mapping": {"attack": {"techniques": ["T1003.002"], "tactics": ["credential-access"]}}}
A3_ROW = {"TimeGenerated": "2020-09-22T08:28:42.564Z",
          "Computer": "WORKSTATION5.theshire.local", "Account": "THESHIRE\\pgustavo",
          "NewProcessName": "C:\\Windows\\System32\\reg.exe",
          "CommandLine": "\"C:\\windows\\system32\\reg.exe\" save HKLM\\sam sam",
          "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}
A2_ROW = {"TimeGenerated": "2020-09-04T07:06:22.49Z", "Computer": "WORKSTATION5.theshire.local",
          "UserName": "NT AUTHORITY\\SYSTEM",
          "Image": "C:\\windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "TargetObject": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                          "\\Updater",
          "Details": "powershell -Win Hidden -enc $x"}


def test_alert_shape_and_provenance():
    alert = seed.to_alert(A3, A3_ROW, "otrf-empire-reg-dump-sam", "2026-11-24T00:00:00Z")
    assert alert["id"].startswith("rpl-") and alert["incidentId"].startswith("rpl-inc-")
    assert alert["title"] == A3["name"]
    assert alert["description"] == "A process command line that saves the SAM hive."
    assert alert["severity"] == "high"
    assert alert["mitreTechniques"] == ["T1003.002"]
    assert alert["categories"] == ["CredentialAccess"]
    assert alert["firstActivityDateTime"] == "2020-09-22T08:28:42.564Z"
    assert alert["customDetails"] == A3_ROW
    # Not pre-labelled: the verdict is the investigation's, not the seed's.
    assert (alert["status"], alert["classification"], alert["determination"]) == (
        "new", "unknown", "unknown")
    prov = alert["additionalData"]["provenance"]
    assert "otrf-empire-reg-dump-sam" in prov and "not a Defender or Sentinel alert" in prov


def test_alert_ids_are_stable_and_incident_groups_by_dataset_and_host():
    a = seed.to_alert(A3, A3_ROW, "ds", "t1")
    b = seed.to_alert(A3, A3_ROW, "ds", "t2")
    c = seed.to_alert(A3, dict(A3_ROW, Computer="workstation5.THESHIRE.local"), "ds", "t1")
    d = seed.to_alert(A3, A3_ROW, "other", "t1")
    assert a["id"] == b["id"] != c["id"]
    assert a["incidentId"] == c["incidentId"] != d["incidentId"]


def test_process_evidence():
    ev = {e["@odata.type"].rsplit(".", 1)[-1]: e for e in seed.evidence(A3_ROW)}
    assert ev["deviceEvidence"] == {"@odata.type": "#microsoft.graph.security.deviceEvidence",
                                    "deviceDnsName": "WORKSTATION5.theshire.local",
                                    "hostName": "WORKSTATION5", "dnsDomain": "theshire.local"}
    assert ev["userEvidence"]["userAccount"] == {"accountName": "pgustavo",
                                                 "domainName": "THESHIRE"}
    proc = ev["processEvidence"]
    assert proc["imageFile"] == {"fileName": "reg.exe",
                                 "filePath": "C:\\Windows\\System32\\reg.exe"}
    assert proc["parentProcessImageFile"]["fileName"] == "powershell.exe"
    assert "save HKLM\\sam" in proc["processCommandLine"]


def test_registry_evidence():
    ev = {e["@odata.type"].rsplit(".", 1)[-1]: e for e in seed.evidence(A2_ROW)}
    reg = ev["registryValueEvidence"]
    assert reg["registryHive"] == "HKU"
    assert reg["registryKey"].endswith("CurrentVersion\\Run")
    assert reg["registryValueName"] == "Updater"
    assert ev["userEvidence"]["userAccount"] == {"accountName": "SYSTEM",
                                                 "domainName": "NT AUTHORITY"}
    assert ev["processEvidence"]["imageFile"]["fileName"] == "powershell.exe"


def test_unknown_severity():
    assert seed.to_alert(dict(A3, severity="Critical"), A3_ROW, "d", "t")["severity"] == "unknown"


@dataclass
class FakeRule:
    data: dict
    tables: dict = field(default_factory=dict)

    def required_fields(self, siem):
        return self.tables


def test_runnable_needs_loaded_tables_and_skips_experimental():
    q = {"sentinel": {"query": "SecurityEvent | take 1"}}
    ok = FakeRule(dict(q, status="test"), {"SecurityEvent": ["EventID"]})
    exp = FakeRule(dict(q, status="experimental"), {"SecurityEvent": ["EventID"]})
    other = FakeRule(dict(q, status="test"), {"SigninLogs": ["x"]})
    mixed = FakeRule(dict(q, status="test"), {"SecurityEvent": [], "SigninLogs": []})
    none = FakeRule({"status": "test"}, {"SecurityEvent": []})
    assert seed.runnable([ok, exp, other, mixed, none], {"SecurityEvent", "Event"}) == [ok]
