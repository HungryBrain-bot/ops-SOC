---
name: replay-data
description: "Use when loading OTRF data into the Kusto emulator, seeding replay alerts from detection_As_Code rules, adding an OTRF dataset, bumping the detection_As_Code pin, or when a replay engine test fails on counts."
---

# Replay data

Replay = recorded OTRF data in the Kusto emulator (ADR 003) plus alerts seeded by running
detection_As_Code (DaC) rules over it (ADR 004). Docs: `docs/components/connectors.md`,
`otrf-defender-mapping.md`, `replay-alerts.md`.

## Run it
```
pip install -e ".[dev,seed]"
export OPSSOC_KUSTO_URL=http://localhost:8080          # Kustainer, digest in ci.yml
export OPSSOC_DAC_PATH=/path/to/detection_As_Code      # checked out at DAC_COMMIT
python -m opssoc.replay fetch      # pinned zips, SHA-256 verified
python -m opssoc.replay seed       # per-dataset rule runs -> data/replay/alerts.json, then load all
python -m pytest tests/test_replay_engine.py
```
No Docker locally? Push and read CI job `replay-kusto` (artifact `replay-alerts`).

## Add an OTRF dataset
1. Only datasets with a reuse licence (OTRF is MIT). Pin it in `opssoc/replay/datasets.json`
   at the existing commit with the zip's SHA-256 (download once, hash it).
2. Run `fetch` and `map`; record per-table counts in `docs/components/otrf-defender-mapping.md`.
3. Update the counts the engine tests assert, and the expected seeded alerts if a rule now
   matches it. Explain any change in BUILD_LOG.md.

## Bump the DaC pin
1. Change `DAC_COMMIT` in `opssoc/replay/dac_bridge.py` and the `ref` in ci.yml together
   (CI checks they match).
2. Compare the new alert counts with DaC's committed `tests/results/kusto.json` for each
   rule; the seeded matches should equal DaC's own run on the same datasets.
3. Log it in BUILD_LOG.md with the old and new counts.

## Rules
- Never hand-edit `data/replay/alerts.json` or add alerts by hand; alerts come only from
  rule runs. Never set `classification` / `determination` in a seeded alert.
- Every alert keeps `additionalData.provenance`; every replay result keeps its mapping label.
- Replay is not a tenant: never describe a replay result as Defender or Sentinel output.
