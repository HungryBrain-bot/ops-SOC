# 004. Replay alerts are seeded by running detection_As_Code rules over each OTRF dataset

## Status
Accepted (2026-11-24)

## Context
The replay connector (ADR 003) answers hunting queries from recorded OTRF data, but OTRF
datasets are recorded attack telemetry with no alerts. The investigation agent starts from
an alert, so replay needs alerts. ADR 001 makes detection_As_Code (DaC) the source of
detection logic.

## Decision
1. **Alerts come from DaC rules, not from hand-written files.** `python -m opssoc.replay seed`
   loads each pinned OTRF dataset on its own into the Kusto emulator and runs every DaC rule
   whose Sentinel tables are loaded. Each matched row becomes one alert. Experimental rules
   are skipped (DaC deploys them disabled).
2. **DaC is used as a library from a pinned checkout** (`OPSSOC_DAC_PATH`, commit
   `DAC_COMMIT` in `opssoc/replay/dac_bridge.py`). ops-SOC imports DaC's rules, its
   OTRF -> `SecurityEvent` / `Event` mapping, the tables' reference schemas and its value
   coercion; it copies none of them. CI checks out the same commit and fails if the
   workflow pin and the code pin differ.
3. **Alerts have the Graph `alerts_v2` shape**, so the agents read replay and live alerts
   the same way: `title`, `description`, `severity`, `mitreTechniques`, `categories` from
   the rule; times, `evidence` (device, user, process, registry value) and `customDetails`
   (the whole matched row) from the match. `detectionSource` `scheduledAlerts`,
   `serviceSource` `microsoftSentinel`, as a Sentinel analytics rule would carry.
4. **Alerts are not pre-labelled.** `status` `new`, `classification` and `determination`
   `unknown`. Ground truth for scoring lives in the eval harness, not in the alert the
   agent reads.
5. **Provenance in every alert**: `additionalData.provenance` names the rule, version,
   dataset and engine, and says it is not a Defender or Sentinel alert. The replay
   connector labels `SecurityEvent` / `Event` results as mapped by DaC.
6. **One incident per dataset and host** (`incidentId` from a hash of both). Alert IDs are a
   hash of rule, dataset and matched row, so re-seeding gives the same IDs.
7. The Graph connector sends `Prefer: include-unknown-enum-members` on alert and incident
   reads, so newer enum members (for example `serviceSource` values) are returned by name.

## Alternatives considered
- **Hand-written alerts per dataset**: quick, but they would be our own claims about what a
  SIEM would raise. Running the real rules makes every alert reproducible from recorded
  data and a pinned rule.
- **Copying DaC's rules and mapping into ops-SOC**: two copies drift. Importing a pinned
  commit keeps one source and makes a bump a deliberate change.
- **One load of all datasets, then the rules once**: the same matches, but an alert could
  not say which dataset it came from, which the eval harness needs.
- **Running the rules over the mapped Defender `Device*` tables**: DaC's rules are written
  for Sentinel tables; rewriting them for Defender would be new detection logic.

## Consequences
- Replay alerts exist only for behaviour a DaC rule detects: on the six pinned datasets, the
  four endpoint rules give 7 alerts (A1 2, A2 2, A3 2, A4 1), the same matches as DaC's
  committed Kusto results. Identity, LLM, recon and foothold rules have no data loaded.
- Seeding needs PyYAML (`pip install -e .[seed]`); runtime stays stdlib-only.
- Graph's documented value set for `categories` was not found on the alert page (fetched
  2026-11-24); seeded alerts use CamelCase tactic names (`CredentialAccess`), an
  assumption.
- Bumping DaC changes the alerts; bump `DAC_COMMIT` and the CI pin together.
