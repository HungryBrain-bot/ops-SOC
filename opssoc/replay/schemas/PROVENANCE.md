# Reference table schemas (Defender advanced hunting tables, as streamed to Sentinel)

Column names and types are Microsoft's own table definitions from the Azure-Sentinel
repository, `.script/tests/KqlvalidationsTests/CustomTables/<Table>.json` at commit
`c0c2dc267d7b5840299e76e195b0407f3f9c92c8` (MIT licence), downloaded unchanged with curl on
2026-11-24. They are the definitions Microsoft uses to validate its own KQL, not a live
workspace's schema.

| File | Columns | SHA-256 |
|---|---|---|
| DeviceProcessEvents.json | 75 | 72d3e08a03d7b3bd793f30c06a14264b7a935c0e580502de4587deec50d094d2 |
| DeviceNetworkEvents.json | 52 | 1f81a20343d941372e214f0e49c4fd337be3046bd0c8a51b870ccb8815e5fa48 |
| DeviceFileEvents.json | 65 | 5319a4cf9b5a6942a4c165c89cd69265322b810f49eeac8452652335f5548169 |
| DeviceRegistryEvents.json | 50 | f5aaefcd38d865d053343d9ab4845f317baeca02d4855bde342f954295d06821 |

detection_As_Code vendors the first three from the same commit
(`schemas/reference/sentinel/`). The Learn advanced-hunting page for DeviceRegistryEvents
(fetched 2026-11-24) lists 43 columns; the Sentinel definition adds the Log Analytics
columns (TenantId, TimeGenerated, Type, SourceSystem, MachineGroup, _BilledSize, _IsBillable).
