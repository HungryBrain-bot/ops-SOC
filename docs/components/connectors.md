# Connectors

Decision: [ADR 003](../decisions/003-connectors-and-replay.md). Code: `opssoc/connectors/`.

## What it does

Gives the agents one read-only way to query security data and read alerts and incidents,
whether a tenant is connected or not.

| Method | Graph (live) | Replay |
|---|---|---|
| `hunt(kql, timespan)` | `POST /v1.0/security/runHuntingQuery` | KQL in the Kusto emulator over OTRF data |
| `list_alerts(top)` | `GET /v1.0/security/alerts_v2` | `data/replay/alerts.json` (empty until alert seeding exists) |
| `get_incident(id)` | `GET /v1.0/security/incidents/{id}?$expand=alerts` | alerts in that file with this `incidentId` |

Every `QueryResult` has `provenance`. Replay results always name the backend; results that
read a `Device*` table also say the rows are mapped by ops-SOC, not Defender telemetry.

## How it works

- `guard_query` runs first on every query: refuses KQL management commands (a leading `.`,
  also after `//` comments), empty queries and queries over 20,000 characters. Results are
  capped at 10,000 rows (`truncated` set).
- Graph: OAuth client credentials (`GRAPH_TENANT_ID`, `GRAPH_CLIENT_ID`,
  `GRAPH_CLIENT_SECRET`); the token is cached until a minute before expiry. Every request is
  built as a `Request` first, so it can be printed (auth redacted) and tested without a
  network.
- Replay: `python -m opssoc.replay fetch` downloads the pinned datasets and checks SHA-256;
  `python -m opssoc.replay load` creates the four `Device*` tables from Microsoft's table
  definitions and ingests the mapped rows; `python -m opssoc.replay map --out DIR` writes
  the rows as JSONL without an emulator. See [otrf-defender-mapping.md](otrf-defender-mapping.md).

Run the emulator locally:

```
docker run -e ACCEPT_EULA=Y -p 8080:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux
export OPSSOC_KUSTO_URL=http://localhost:8080
python -m opssoc.replay fetch && python -m opssoc.replay load
python -m pytest tests/test_replay_engine.py
```

## Why this method

- One interface with two backends means the agents are tested on the same code path they
  run live on; only the transport and data differ.
- A real KQL engine on recorded data tests the agents' queries, not a reimplementation.
- The read-only guard sits in the interface so no backend can be the weak point.

## What it does not do

- Not verified against a live tenant. Graph request shapes come from the v1.0 reference
  pages; test responses are written from them. Permissions for `alerts_v2` and
  `incidents` are not checked.
- `guard_query` is not a KQL parser. Graph's hunting API is read-only by design; the guard
  stops the replay engine (which accepts management commands) and catches mistakes early.
- No pagination of `alerts_v2` (`@odata.nextLink` not followed yet).
- No Sentinel-only tables in replay yet (`SecurityEvent`, `SigninLogs`): the Defender tables
  come first. No Log Analytics fallback connector yet.
- Replay ignores `Timespan` and is the ADX engine, not Defender's: Defender-only functions
  fail there.
