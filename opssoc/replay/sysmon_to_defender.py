"""OTRF Sysmon events -> Defender advanced hunting rows. THIS PROJECT'S MAPPING.

Microsoft does not publish a Sysmon-to-Defender mapping, and Defender for
Endpoint does not read Sysmon. This module builds rows in the shape of the
Defender tables (schemas in ``schemas/``) from recorded Sysmon events so the
agents' KQL can run on recorded data. Every row it produces is mapped data,
not Defender telemetry, and the replay connector labels results that read
these tables (docs/components/otrf-defender-mapping.md).

Input: OTRF Security-Datasets events, NXLog-flattened JSON, one per line
(EventData fields as top-level keys, plus NXLog metadata).

| Sysmon | Table | ActionType |
|---|---|---|
| 1 process create | DeviceProcessEvents | ProcessCreated |
| 3 network connection | DeviceNetworkEvents | ConnectionSuccess / InboundConnectionAccepted |
| 11 file create | DeviceFileEvents | FileCreated |
| 23 / 26 file delete | DeviceFileEvents | FileDeleted |
| 12 CreateKey / DeleteKey | DeviceRegistryEvents | RegistryKeyCreated / RegistryKeyDeleted |
| 12 registry DeleteValue | DeviceRegistryEvents | RegistryValueDeleted |
| 13 registry SetValue | DeviceRegistryEvents | RegistryValueSet |

Other events (Sysmon 7, 10, 22, ... and every non-Sysmon channel) are not
mapped and are counted as skipped.

Approximations (none of these is evidence of how Defender records an event):
- ``DeviceId`` is a SHA-1 of the lower-cased host name, made up here.
- ``DeviceName`` is the lower-cased Sysmon host name (FQDN).
- Initiating-process fields of events 3/11/12/13 come from the event's own
  Image/ProcessId/User, and command line, hashes and parent from the Sysmon 1
  event with the same ProcessGuid when the dataset holds one; otherwise empty.
- ``InitiatingProcessParent*`` of a process-create row comes from the Sysmon 1
  event of the parent's ProcessGuid when present.
- Sysmon 3 does not say whether a connection succeeded; Initiated=true is
  mapped to ConnectionSuccess.
- Registry hive prefixes are expanded (HKLM -> HKEY_LOCAL_MACHINE, HKU ->
  HKEY_USERS, HKCR -> HKEY_CLASSES_ROOT, HKCU -> HKEY_CURRENT_USER). How
  Defender writes per-user hives is not verified.
- Registry value data: "DWORD (0x..)" / "QWORD (0x..)" become type Dword /
  Qword with the decimal value; anything else is type String, data unchanged.
- ``ReportId`` is the Sysmon RecordNumber; ``Timestamp`` and ``TimeGenerated``
  are Sysmon UtcTime.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
TABLES = ("DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents", "DeviceRegistryEvents")
MAPPING_LABEL = "mapped by ops-SOC from OTRF Sysmon (not Defender telemetry)"

HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKU": "HKEY_USERS",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKCU": "HKEY_CURRENT_USER",
}
REG_NUMBER = re.compile(r"^(DWORD|QWORD) \((0x[0-9a-fA-F]+)\)$")


@cache
def schema(table: str) -> dict[str, str]:
    """Column -> Kusto type for one table, from the vendored definition."""
    data = json.loads((SCHEMA_DIR / f"{table}.json").read_text(encoding="utf-8"))
    return {col["Name"]: col["Type"] for col in data["Properties"]}


@dataclass
class MappingResult:
    rows: dict[str, list[dict]] = field(default_factory=lambda: {t: [] for t in TABLES})
    skipped: Counter = field(default_factory=Counter)  # (channel, event id) -> count

    def counts(self) -> dict[str, int]:
        return {table: len(rows) for table, rows in self.rows.items()}


def utc(value: str) -> str:
    """Sysmon UtcTime ("2020-09-04 20:09:55.035") -> ISO 8601 UTC."""
    return value.replace(" ", "T") + "Z" if value else ""


def split_user(user: str | None) -> tuple[str, str]:
    if not user or "\\" not in user:
        return "", user or ""
    domain, name = user.split("\\", 1)
    return domain, name


def split_path(path: str | None) -> tuple[str, str]:
    """C:\\a\\b.exe -> ("C:\\a\\b.exe", "b.exe"); Defender's FolderPath holds the full path."""
    if not path:
        return "", ""
    return path, path.rsplit("\\", 1)[-1]


def hashes(value: str | None) -> dict[str, str]:
    out = {}
    for part in (value or "").split(","):
        if "=" in part:
            algo, digest = part.split("=", 1)
            out[algo.strip().upper()] = digest.strip().lower()
    return out


def as_int(value) -> int | None:
    if value in (None, "", "-"):
        return None
    text = str(value)
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def registry_key(target: str) -> str:
    hive, _, rest = target.partition("\\")
    return f"{HIVES.get(hive.upper(), hive)}\\{rest}" if rest else HIVES.get(hive.upper(), hive)


def registry_value(details: str | None) -> tuple[str, str]:
    if details is None:
        return "", ""
    match = REG_NUMBER.match(details)
    if match:
        return match[1].capitalize(), str(int(match[2], 16))
    return "String", details


def device_id(host: str) -> str:
    return hashlib.sha1(host.lower().encode()).hexdigest()


class SysmonToDefender:
    def __init__(self) -> None:
        self.processes: dict[str, dict] = {}  # ProcessGuid -> Sysmon 1 event

    def map(self, events: Iterable[dict]) -> MappingResult:
        events = list(events)
        sysmon = [e for e in events if e.get("Channel") == SYSMON_CHANNEL]
        for event in sysmon:
            if event.get("EventID") == 1 and event.get("ProcessGuid"):
                self.processes[event["ProcessGuid"]] = event
        result = MappingResult()
        for event in events:
            table, row = self.row(event) if event.get("Channel") == SYSMON_CHANNEL else (None, None)
            if table is None:
                result.skipped[(event.get("Channel") or "", event.get("EventID"))] += 1
                continue
            result.rows[table].append(self._fit(table, row))
        return result

    # -- per event --------------------------------------------------------------

    def row(self, event: dict) -> tuple[str | None, dict | None]:
        eid = event.get("EventID")
        if eid == 1:
            return "DeviceProcessEvents", self._process(event)
        if eid == 3:
            return "DeviceNetworkEvents", self._network(event)
        if eid in (11, 23, 26):
            return "DeviceFileEvents", self._file(event)
        if eid in (12, 13):
            return self._registry(event)
        return None, None

    def _common(self, event: dict) -> dict:
        host = (event.get("Hostname") or "").lower()
        time = utc(event.get("UtcTime") or "")
        return {
            "Timestamp": time,
            "TimeGenerated": time,
            "DeviceName": host,
            "DeviceId": device_id(host) if host else "",
            "ReportId": as_int(event.get("RecordNumber")),
            "Type": None,  # set in _fit
            "SourceSystem": "ops-SOC replay",
        }

    def _initiating(self, guid: str | None, image: str | None, pid, user: str | None) -> dict:
        """Initiating-process columns for the process with this ProcessGuid."""
        known = self.processes.get(guid or "")
        image = image or (known or {}).get("Image")
        folder, name = split_path(image)
        domain, account = split_user(user or (known or {}).get("User"))
        out = {
            "InitiatingProcessFileName": name,
            "InitiatingProcessFolderPath": folder,
            "InitiatingProcessId": as_int(pid if pid not in (None, "") else
                                          (known or {}).get("ProcessId")),
            "InitiatingProcessAccountDomain": domain,
            "InitiatingProcessAccountName": account,
        }
        if known:
            digest = hashes(known.get("Hashes"))
            parent_folder, parent_name = split_path(known.get("ParentImage"))
            out.update({
                "InitiatingProcessCommandLine": known.get("CommandLine") or "",
                "InitiatingProcessCreationTime": utc(known.get("UtcTime") or ""),
                "InitiatingProcessIntegrityLevel": known.get("IntegrityLevel") or "",
                "InitiatingProcessSHA1": digest.get("SHA1", ""),
                "InitiatingProcessSHA256": digest.get("SHA256", ""),
                "InitiatingProcessMD5": digest.get("MD5", ""),
                "InitiatingProcessParentFileName": parent_name,
                "InitiatingProcessParentId": as_int(known.get("ParentProcessId")),
                "InitiatingProcessVersionInfoCompanyName": known.get("Company") or "",
                "InitiatingProcessVersionInfoProductName": known.get("Product") or "",
                "InitiatingProcessVersionInfoFileDescription": known.get("Description") or "",
                "InitiatingProcessVersionInfoOriginalFileName":
                    known.get("OriginalFileName") or "",
            })
            parent = self.processes.get(known.get("ParentProcessGuid") or "")
            if parent:
                out["InitiatingProcessParentCreationTime"] = utc(parent.get("UtcTime") or "")
        return out

    def _process(self, e: dict) -> dict:
        folder, name = split_path(e.get("Image"))
        domain, account = split_user(e.get("User"))
        digest = hashes(e.get("Hashes"))
        row = self._common(e) | {
            "ActionType": "ProcessCreated",
            "FileName": name,
            "FolderPath": folder,
            "ProcessCommandLine": e.get("CommandLine") or "",
            "ProcessId": as_int(e.get("ProcessId")),
            "ProcessCreationTime": utc(e.get("UtcTime") or ""),
            "ProcessIntegrityLevel": e.get("IntegrityLevel") or "",
            "AccountDomain": domain,
            "AccountName": account,
            "LogonId": as_int(e.get("LogonId")),
            "SHA1": digest.get("SHA1", ""),
            "SHA256": digest.get("SHA256", ""),
            "MD5": digest.get("MD5", ""),
            "ProcessVersionInfoCompanyName": e.get("Company") or "",
            "ProcessVersionInfoProductName": e.get("Product") or "",
            "ProcessVersionInfoFileDescription": e.get("Description") or "",
            "ProcessVersionInfoOriginalFileName": e.get("OriginalFileName") or "",
        }
        parent = self.processes.get(e.get("ParentProcessGuid") or "")
        initiating = self._initiating(e.get("ParentProcessGuid"), e.get("ParentImage"),
                                      e.get("ParentProcessId"),
                                      e.get("ParentUser") or (parent or {}).get("User"))
        if not parent:
            # The parent's own create event is not in the dataset: only what Sysmon 1
            # records about the parent is known.
            initiating["InitiatingProcessCommandLine"] = e.get("ParentCommandLine") or ""
        return row | initiating

    def _network(self, e: dict) -> dict:
        initiated = str(e.get("Initiated", "")).lower() == "true"
        local_ip, local_port, remote_ip, remote_port = (
            (e.get("SourceIp"), e.get("SourcePort"), e.get("DestinationIp"),
             e.get("DestinationPort")) if initiated else
            (e.get("DestinationIp"), e.get("DestinationPort"), e.get("SourceIp"),
             e.get("SourcePort")))
        remote_host = e.get("DestinationHostname") if initiated else e.get("SourceHostname")
        return self._common(e) | {
            "ActionType": "ConnectionSuccess" if initiated else "InboundConnectionAccepted",
            "LocalIP": local_ip or "",
            "LocalPort": as_int(local_port),
            "RemoteIP": remote_ip or "",
            "RemotePort": as_int(remote_port),
            "RemoteUrl": "" if remote_host in (None, "-") else remote_host,
            "Protocol": (e.get("Protocol") or "").capitalize(),
        } | self._initiating(e.get("ProcessGuid"), e.get("Image"), e.get("ProcessId"),
                             e.get("User"))

    def _file(self, e: dict) -> dict:
        folder, name = split_path(e.get("TargetFilename"))
        digest = hashes(e.get("Hashes"))
        return self._common(e) | {
            "ActionType": "FileCreated" if e.get("EventID") == 11 else "FileDeleted",
            "FileName": name,
            "FolderPath": folder,
            "SHA1": digest.get("SHA1", ""),
            "SHA256": digest.get("SHA256", ""),
            "MD5": digest.get("MD5", ""),
        } | self._initiating(e.get("ProcessGuid"), e.get("Image"), e.get("ProcessId"),
                             e.get("User"))

    def _registry(self, e: dict) -> tuple[str | None, dict | None]:
        kind = e.get("EventType")
        action = {"CreateKey": "RegistryKeyCreated", "DeleteKey": "RegistryKeyDeleted",
                  "DeleteValue": "RegistryValueDeleted", "SetValue": "RegistryValueSet"}.get(kind)
        if action is None:
            return None, None
        target = e.get("TargetObject") or ""
        if action in ("RegistryValueSet", "RegistryValueDeleted"):
            key, _, value_name = target.rpartition("\\")
        else:
            key, value_name = target, ""
        value_type, value_data = registry_value(e.get("Details"))
        return "DeviceRegistryEvents", self._common(e) | {
            "ActionType": action,
            "RegistryKey": registry_key(key),
            "RegistryValueName": value_name,
            "RegistryValueType": value_type,
            "RegistryValueData": value_data,
        } | self._initiating(e.get("ProcessGuid"), e.get("Image"), e.get("ProcessId"),
                             e.get("User"))

    @staticmethod
    def _fit(table: str, row: dict) -> dict:
        columns = schema(table)
        unknown = set(row) - set(columns)
        if unknown:
            raise KeyError(f"{table}: mapping writes columns not in the schema: {sorted(unknown)}")
        row["Type"] = table
        return {k: v for k, v in row.items() if v is not None}


def read_events(path: Path | str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
