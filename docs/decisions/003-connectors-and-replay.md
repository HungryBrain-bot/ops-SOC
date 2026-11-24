# 003. Read-only connectors: Graph security API live, Kusto emulator replay

## Status
Accepted (2026-11-24)

## Context
ADR 001 fixes one read-only connector interface with a live and a replay backend, Graph
security API first. This ADR fixes the interface, the live connector's calls and auth, the
replay engine, and how recorded Sysmon data stands in for Defender tables.

## Decision
1. **Interface** (`opssoc/connectors/base.py`): `hunt(kql, timespan)`, `list_alerts(top)`,
   `get_incident(id)`. Every hunting result is a `QueryResult` with `columns`, `rows`,
   `backend`, `provenance` and `truncated` (cap 10,000 rows). Agents carry `provenance`
   into evidence.
2. **Read-only is enforced in the interface**, before any backend: KQL management commands
   (leading `.`, after comments) and empty or over-long queries are refused.
3. **Live: Microsoft Graph v1.0** (`opssoc/connectors/graph.py`).
   `POST /security/runHuntingQuery` (`Query`, optional `Timespan`),
   `GET /security/alerts_v2`, `GET /security/incidents/{id}?$expand=alerts`. OAuth 2.0
   client credentials, scope `https://graph.microsoft.com/.default`, credentials only from
   `GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`, `GRAPH_CLIENT_SECRET`. Least-privilege
   application permission for hunting: `ThreatHunting.Read.All`
   ([runHuntingQuery](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0),
   fetched 2026-11-24).
4. **Replay engine: the Kusto emulator (Kustainer)**, same image digest as
   detection_As_Code. Tables are created from Microsoft's own table definitions
   (Azure-Sentinel repo, commit c0c2dc2; `opssoc/replay/schemas/PROVENANCE.md`).
5. **Recorded data: OTRF Security-Datasets**, pinned by commit and SHA-256
   (`opssoc/replay/datasets.json`), verified on every download.
6. **Sysmon -> Defender mapping is this project's** (`opssoc/replay/sysmon_to_defender.py`):
   Sysmon 1/3/11/23/26/12/13 become `DeviceProcessEvents`, `DeviceNetworkEvents`,
   `DeviceFileEvents`, `DeviceRegistryEvents`. The mapping refuses to write a column the
   vendor schema does not have. Every replay result that reads a `Device*` table carries
   the label "mapped by ops-SOC from OTRF Sysmon (not Defender telemetry)".
7. **Replay alerts** come from `data/replay/alerts.json`, written by the alert-seeding step
   (detection_As_Code rules over the loaded data), which is a separate change.

## Alternatives considered
- **Log Analytics query API as the live path.** Reaches Sentinel tables only, not
  Defender's 30-day advanced hunting data; kept as a later fallback (ADR 001).
- **Run KQL in Python against JSON rows.** Tests a reimplementation, not the query.
- **Leave Defender tables empty in replay.** No invented mapping, but the investigation
  agent could never be tested on endpoint data.
- **Azure SDK / msgraph-sdk.** Hides the requests; four calls do not need it.

## Consequences
- Graph behaviour is "not verified" until a logged live call: requests follow the reference
  pages and the test responses are written from them.
- Kustainer is the ADX engine. Defender-only functions (e.g. `FileProfile`,
  `DeviceFromIP`) fail on replay, visibly, and work only live.
- Replay ignores `Timespan`; recorded data is from 2020 and would fall outside any
  relative window. The result says so in `provenance`.
- Mapped `Device*` rows approximate Defender (component doc lists every approximation).
  A query that passes on replay can still behave differently on real Defender data.

## Amendment (2026-11-24)
Point 7: the alert-seeding step is built; see ADR 004. Replay `SecurityEvent` / `Event`
results are labelled as mapped by detection_As_Code. Replay now holds six OTRF datasets.
