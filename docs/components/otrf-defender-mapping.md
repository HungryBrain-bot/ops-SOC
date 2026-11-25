# OTRF Sysmon -> Defender tables (this project's mapping)

Code: `opssoc/replay/sysmon_to_defender.py`. Decision: ADR 003, point 6.

**Every row this produces is mapped data, not Defender telemetry.** Defender for Endpoint
does not read Sysmon, and Microsoft publishes no mapping between them.

## What it maps

| Sysmon event | Table | ActionType |
|---|---|---|
| 1 process create | DeviceProcessEvents | ProcessCreated |
| 3 network connection | DeviceNetworkEvents | ConnectionSuccess (Initiated=true) / InboundConnectionAccepted |
| 11 file create | DeviceFileEvents | FileCreated |
| 23, 26 file delete | DeviceFileEvents | FileDeleted |
| 12 CreateKey / DeleteKey / DeleteValue | DeviceRegistryEvents | RegistryKeyCreated / RegistryKeyDeleted / RegistryValueDeleted |
| 13 SetValue | DeviceRegistryEvents | RegistryValueSet |

Everything else (Sysmon 7, 10, 22, ... and non-Sysmon channels) is skipped and counted.

Pinned datasets and what they produce (`python -m opssoc.replay map`, 2026-11-24):

| Dataset | Process | Network | File | Registry | Skipped |
|---|---|---|---|---|---|
| otrf-empire-launcher-vbs | 5 | 10 | 24 | 483 | 1,545 |
| otrf-empire-runkey-elevated-user | 0 | 46 | 2 | 32 | 577 |
| otrf-empire-reg-dump-sam | 1 | 0 | 4 | 0 | 733 |
| otrf-bitsadmin-download | 2 | 8 | 8 | 70 | 336 |

## How it works

Two passes per dataset: first every Sysmon 1 event is indexed by `ProcessGuid`; then each
event becomes a row. The initiating process of a process-create row is the Sysmon parent;
for network, file and registry rows it is the event's own process, filled out from that
process's Sysmon 1 event when the dataset has it (command line, hashes, integrity level,
parent). Rows are checked against Microsoft's table definition: a column that is not in
the vendor schema is an error, not silently dropped.

## Approximations

- `DeviceId`: SHA-1 of the lower-cased host name, invented here.
- `DeviceName`: Sysmon host name, lower-cased (FQDN, or a short name where the dataset has
  one).
- Initiating-process fields are empty when the dataset has no Sysmon 1 for that process
  (common: long-running processes started before the recording).
- Sysmon 3 does not say whether a connection succeeded; Initiated=true is mapped to
  ConnectionSuccess.
- Registry hives are expanded (HKLM -> HKEY_LOCAL_MACHINE, HKU -> HKEY_USERS, HKCR ->
  HKEY_CLASSES_ROOT, HKCU -> HKEY_CURRENT_USER). How Defender writes per-user hives is not
  verified.
- Registry value data: `DWORD (0x..)` / `QWORD (0x..)` -> Dword / Qword with the decimal
  value; anything else -> String, unchanged.
- `ReportId` is the Sysmon RecordNumber; `Timestamp` = `TimeGenerated` = Sysmon UtcTime.
- No `AccountSid`, `AccountUpn`, object IDs, signer info, file sizes or remote-session
  fields: Sysmon does not record them in these events.

## What it does not do

- It is not evidence of Defender's field values (`ActionType` strings beyond those above,
  path formats, casing). A detection that works on mapped rows can still miss on real
  Defender data.
- No `DeviceImageLoadEvents` (Sysmon 7), `DeviceEvents` or process-access events
  (Sysmon 10): not mapped yet.
