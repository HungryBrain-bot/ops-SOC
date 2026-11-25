# Replay alerts (seeding)

Code: `opssoc/replay/seed.py`, `opssoc/replay/dac_bridge.py`, `opssoc/replay/__main__.py`
(`seed`). Decision: ADR 004.

## What it does
Gives the replay backend alerts to investigate. For each pinned OTRF dataset it loads the
replay tables (Defender `Device*` mapped by ops-SOC; Sentinel `SecurityEvent` and `Event`
mapped by detection_As_Code) into the Kusto emulator, runs every detection_As_Code (DaC)
rule whose Sentinel tables are loaded, and turns each matched row into an alert shaped like
a Graph `alerts_v2` alert. It writes them to `data/replay/alerts.json`, then loads all
datasets together for hunting. `ReplayConnector.list_alerts` and `get_incident` read that
file.

## How
```
pip install -e ".[dev,seed]"
export OPSSOC_DAC_PATH=/path/to/detection_As_Code   # at DAC_COMMIT
export OPSSOC_KUSTO_URL=http://localhost:8080        # Kustainer
python -m opssoc.replay fetch
python -m opssoc.replay seed
```

| Alert field | From |
|---|---|
| `id` | `rpl-` + hash(rule id, dataset, matched row): stable across runs |
| `incidentId` | `rpl-inc-` + hash(dataset, lower-cased host) |
| `title`, `description`, `severity` | the rule (`severity` lower-cased; unknown value -> `unknown`) |
| `mitreTechniques`, `categories` | the rule's ATT&CK mapping (tactics in CamelCase) |
| `firstActivityDateTime`, `lastActivityDateTime` | the row's `TimeGenerated` |
| `evidence` | `deviceEvidence` (Computer), `userEvidence` (Account / UserName), `processEvidence` (NewProcessName / Image, CommandLine, ParentProcessName), `registryValueEvidence` (TargetObject, Details) |
| `customDetails` | the whole matched row |
| `status` / `classification` / `determination` | `new` / `unknown` / `unknown` |
| `additionalData` | provenance sentence, dataset, rule id and version, DaC commit |

Evidence property names were checked against the Graph v1.0 pages for alert, alertEvidence,
deviceEvidence, processEvidence, registryValueEvidence, fileDetails and userAccount
(fetched 2026-11-24).

## Why this method
Running pinned rules over recorded data makes every alert reproducible and traceable to a
rule and a dataset; nothing in an alert is our own claim about what a SIEM would raise.
Using DaC as a library keeps one copy of the rules and the OTRF -> Sentinel mapping.

## Result (CI job `replay-kusto`)
Six datasets, rules A1-A4 (the four non-experimental rules on `SecurityEvent` / `Event`):
7 alerts, A1 2, A2 2, A3 2, A4 1, matching DaC's committed results
(`detections/endpoint/*/tests/results/kusto.json` at DAC_COMMIT). The CI run uploads
`alerts.json` as the `replay-alerts` artifact.

## What it does not do
- It is not Defender or Sentinel. Real alerts carry fields this does not fill (alertWebUrl,
  tenantId, detectorId, comments, Defender-generated evidence and verdicts).
- No alert for behaviour no DaC rule detects, and none from identity, LLM, recon or
  foothold rules (their tables have no replay data).
- Evidence is only what the rule's `project` keeps; a rule projecting other columns gets
  only `customDetails`.
- Incident grouping (dataset + host) is ours; Defender correlates differently.
- `categories` value format is an assumption (no documented value set found).
- Alerts are not labelled true or false positive; the eval harness holds ground truth.
- Rules run on the recording timestamps; a rule with a time window relative to now would
  need the data rebased, which DaC's endpoint rules do not.
