# CLAUDE.md

## Project

ops-SOC: a SOC platform with three LLM agents (investigation, finance-sector
threat intelligence, detection engineering) over Microsoft Defender and
Microsoft Sentinel (Sentinel onboarded to the Defender portal), writing
results to a SOAR (Cortex XSOAR or Google SecOps SOAR). No live tenant exists: everything except API credentials is built
and tested here, on recorded OTRF data in the Kusto emulator.

Architecture: docs/decisions/001-architecture.md (ADR 001). SOAR writer:
docs/decisions/002-soar-writer.md (ADR 002). Connectors and replay:
docs/decisions/003-connectors-and-replay.md (ADR 003).

Before adding an agent, connector, data source or write path beyond Scope,
check the request is explicit from the owner (Venu).

## Scope

| Area | In scope | Out of scope |
|------|----------|--------------|
| Agents | Investigation, threat intel (finance), detection (via detection_As_Code) | Hunting agent |
| Data connectors | Graph security API (alerts_v2, incidents, runHuntingQuery); Sentinel Log Analytics + ARM incidents as fallback; CISA KEV; MITRE ATT&CK STIX | Any other SIEM / EDR |
| Writes | One SOAR writer (Cortex XSOAR incident + entry; Google SecOps SOAR case comment), dry-run by default, test mode against a local stub server | Response actions (isolate, disable, close, reassign) |
| LLMs | Anthropic Claude and OpenAI behind one client | Self-hosted models |
| Test data | OTRF Security-Datasets (pinned), alerts seeded by DaC rules, OTRF Sysmon mapped to Defender `Device*` tables (labelled as this project's mapping) | Data without a reuse licence |

## Conventions (from detection_As_Code)

- Every component has a doc in `docs/components/` written as it is built:
  what it does, how, why this method, what it does not do.
- Design decisions are ADRs in `docs/decisions/`. ADRs and BUILD_LOG.md are
  append-only; correct with dated amendments.
- Data is labelled recorded (dataset + file), mapped by this project, or
  hand-written. Hand-written or mapped data is never presented as recorded.
- Citations come from fetched primary sources with the fetch date. Never cite
  from memory; never invent campaign details, group IDs or CVEs.
- Live-API behaviour is "not verified" until a live call is made and logged
  in BUILD_LOG.md. Emulated engines are named as emulated.
- A check is described by exactly what it tests, and what it misses.
- Secrets only via environment variables / GitHub Actions secrets.
- Tool and log output reaches an LLM as fenced data, never as instructions.

## Model usage

Per task, not per agent (ADR 001): `reasoning` (hypotheses, evidence
judgment, verdict) on Claude Opus or the OpenAI top tier; `extraction` and
`writing` (log summaries, reports, SOAR notes, docs) on Sonnet or below.
LLM spend cap USD 100 per month (default, in settings).

## Testing

`python -m pytest` and `ruff check .` before every commit. CI
(`.github/workflows/ci.yml`) runs both plus a SOAR test push to the stub
server for each target.

- `tests/test_soar.py` - SOAR writer: dry-run output, test push over HTTP to
  the stub (XSOAR and SecOps, incl. pre-processing block, closed
  investigation, unknown case), live-mode credential check and ledger.
- `tests/test_connectors.py` - read-only guard; Graph requests, token,
  errors, row cap (fake transport, responses written from docs); replay
  provenance labels (Device* and SecurityEvent / Event), alerts file,
  `Prefer` header on alert reads.
- `tests/test_seed.py` - seeded alert shape, evidence, stable IDs, rule
  selection (offline, rows copied from detection_As_Code's results).
- `tests/test_sysmon_mapping.py` - Sysmon -> Defender mapping on a recorded
  OTRF extract; every column in the vendor schema.
- `tests/test_replay_engine.py` - replay in the real Kusto emulator, incl.
  the 7 seeded alerts; skipped unless OPSSOC_KUSTO_URL is set (CI job
  `replay-kusto`, which checks out detection_As_Code at the pinned commit).

Last run (2026-11-24, replay alerts): 49 passed, 5 skipped (engine tests,
run in CI); ruff clean.

Skills (`.claude/skills/`): `build-and-document`, `replay-data`.

## Current status

- Built: SOAR writer for Cortex XSOAR and Google SecOps SOAR with
  dry-run, test (local stub server) and live modes
  (docs/components/soar-writer.md). ADRs 001-002 accepted.
- Built: read-only connector interface; Graph security connector (live);
  replay connector on the Kusto emulator; OTRF Sysmon -> Defender Device*
  mapping (ours, labelled) on six pinned OTRF datasets
  (docs/components/connectors.md, otrf-defender-mapping.md).
- Built: replay alert seeding (ADR 004, docs/components/replay-alerts.md):
  detection_As_Code rules run per dataset in the emulator -> Graph
  alerts_v2-shaped alerts with provenance, not pre-labelled. DaC is imported
  from a pinned checkout (`OPSSOC_DAC_PATH`); replay also loads Sentinel
  `SecurityEvent` / `Event` (DaC's mapping). Expected: 7 alerts (A1-A4).
- Verified: the writer's requests pass the stub server over HTTP; mapping on
  recorded OTRF events. Not verified: any live SOAR or Graph call; SecOps
  `caseComments.create` URL and body field; XSOAR incident ID =
  investigation ID; Defender's registry hive format.
- Not verified: Graph `categories` value format (seeded alerts use CamelCase
  tactics).
- Next: investigation agent; eval harness; threat intel agent.
- Open: CISA sources beyond KEV; Google SecOps `caseComments.create` body
  fields (unverified).

## Do NOT

- Don't add response actions or any write besides the SOAR writer.
- Don't let a request select the outcome, pre-label evidence, or return
  canned verdicts.
- Don't add real API keys, tenant names or customer data.
- Don't describe replay runs as running against a real tenant.
