# Build Log

## 2026-11-24 - Review, scope and architecture

- Reviewed `opsmind-hackathon` at b85ce99: the request's `scenario_id` picks
  evidence, verdict and remediation; all tools (incl. MCP) return fixtures;
  evidence is pre-tagged with the hypothesis it supports; the LLM reasoner is
  never called. Decision: new repo, not an evolution of the hackathon code.
- Owner decisions (project thread): three agents (investigation, finance
  threat intel, detection-as-code), no hunting agent; Sentinel + Defender;
  build up to integration, no live tenant; OTRF for test data; CISA + MITRE
  for intel; Claude and OpenAI switchable; Sentinel treated as onboarded to
  the Defender portal (owner's deadline January 2027); map OTRF Sysmon to
  Defender tables; Opus for investigation reasoning, Sonnet or below for
  fetching, docs and SOAR write-up; USD 100 LLM spend cap; results written
  to a SOAR.
- Checked sources (2026-11-24): Graph v1.0 security API overview
  (alerts_v2, incidents, runHuntingQuery with ThreatHunting.Read.All; Sentinel
  alerts only after Defender-portal onboarding); Sentinel incidents ARM API
  2025-09-01; CISA KEV via cisagov/kev-data (catalog 2026.11.23, 1,792
  entries, no sector field; cisa.gov refused automated fetches); ATT&CK
  Enterprise STIX v20.1 (178 active groups, no sector field, 46 mention
  financ/bank); Microsoft Q&A answer giving 2027-03-31 for Sentinel's
  Azure-portal retirement (not yet checked against Learn).
- Wrote ADR 001 (proposed). Repo created by the owner; this is the first
  commit.
- Next: owner approves ADR 001 and picks the SOAR target; then the connector
  interface and replay backend.

## 2026-11-24 - ADR cleanup and SOAR writer decision

- ADR 001 rewritten to hold design decisions only (no project history or
  discussion), and marked Accepted after the owner merged PR #1. Rewritten
  rather than amended because it had been accepted for less than an hour and
  nothing builds on its wording yet.
- SOAR targets set by the owner: Cortex XSOAR and Google SecOps SOAR ("GSOAR"
  read as Google SecOps SOAR). No SOAR instance exists, so the writer gets a
  test mode that pushes over HTTP to a local stub server (ADR 002).
- Checked: XSOAR 8 incident and entry APIs (Cortex docs, fetched). Google
  SecOps v1 cases have no create method; `caseComments.create` exists but its
  page body did not render through the fetch tool, so its request line and
  fields are unverified. docs.cloud.google.com is blocked for direct curl
  from this environment.
- Next: SOAR writer code with stub server and tests; then the connector
  interface and replay backend.

## 2026-11-24 - SOAR writer

- Built `opssoc/soar/`: one `SoarWriter` driver, XSOAR and Google SecOps
  writers, a stdlib stub SOAR server, a CLI, and the case report model the
  writer reads. Stdlib only at runtime.
- Test push: `python -m opssoc.soar write --mode test` starts the stub and
  sends over real HTTP. Both targets write successfully to the stub.
- Verified: 17 tests pass; ruff clean. Not verified: anything against a real
  XSOAR or SecOps instance (none exists).
- Example report `examples/case_report.json` is hand-written and labelled so.
- Added CI (pytest, ruff, SOAR test push per target). First run is this PR.

## 2026-11-24 - Connectors and replay backend

- Built the read-only connector interface (query guard, row cap, provenance),
  the Graph security connector (runHuntingQuery, alerts_v2, incidents;
  client-credentials auth), the replay connector, a Kusto emulator client,
  and the OTRF Sysmon -> Defender Device* mapping. ADR 003.
- Checked: Graph runHuntingQuery reference (Query, Timespan default 30 days,
  ThreatHunting.Read.All, response schema/results); DeviceRegistryEvents
  columns on Learn (43) and in the Azure-Sentinel table definition (50).
  Vendored the four Device* table definitions from Azure-Sentinel c0c2dc2
  with hashes.
- Recorded data: four OTRF datasets, same pins as detection_As_Code; mapped
  counts in docs/components/otrf-defender-mapping.md. Test extract of 8
  recorded events committed (MIT).
- No Docker daemon in this environment, so the emulator tests run only in
  CI (job `replay-kusto`, same Kustainer digest as detection_As_Code).
- Verified locally: 41 tests pass, ruff clean. Not verified: any live Graph
  call.

## 2026-11-24 - Replay alerts seeded from detection_As_Code

- Built `opssoc/replay/seed.py` and `dac_bridge.py`: each pinned OTRF dataset
  is loaded alone, every non-experimental DaC rule whose Sentinel tables are
  loaded runs over it, and each matched row becomes a Graph alerts_v2-shaped
  alert in `data/replay/alerts.json`. ADR 004; docs/components/replay-alerts.md.
- DaC is imported from a checkout at commit 51080aa (`OPSSOC_DAC_PATH`); CI
  checks it out and fails if the workflow and code pins differ. Seeding needs
  PyYAML (`[seed]` extra); runtime stays stdlib-only.
- Replay now also loads `SecurityEvent` / `Event` (DaC's mapping; 45,370
  recorded events over six datasets, the same total DaC reports) and labels
  those results. Added two OTRF datasets (runkey-standard-user,
  sam-copy-esentutl) so replay holds the six datasets DaC's endpoint rules
  were tested on. Device* totals now 129 / 301 / 252 / 14,076.
- Graph connector sends `Prefer: include-unknown-enum-members` on alert and
  incident reads.
- Checked (fetched 2026-11-24): Graph alert, alertEvidence, deviceEvidence,
  processEvidence, registryValueEvidence, fileDetails, userAccount pages for
  property names. Not found: a documented value set for `categories`.
- Expected seeded alerts: 7 (A1 2, A2 2, A3 2, A4 1), equal to DaC's committed
  Kusto results; asserted in tests/test_replay_engine.py (CI only, no Docker here).
- Added skills `build-and-document` and `replay-data`.
- Verified locally: 49 passed, 5 skipped; ruff clean.

## 2026-11-24 - LLM layer and investigation agent

- Built `opssoc/llm/` (ADR 005): provider-agnostic conversation interface;
  Anthropic (Messages API, `anthropic` 2.13.0) and OpenAI (Responses API,
  `openai` 3.58.0) through the official SDKs as an optional `[llm]` extra;
  tiers reasoning / extraction / writing; JSONL spend ledger and monthly cap
  (USD 100); scripted provider for tests only.
- Anthropic choices from the claude-api skill: adaptive thinking left on,
  effort per tier, no forced tool_choice, strict tools, server-side refusal
  fallback (`fallbacks: "default"`). Prices fetched from the Anthropic
  pricing page (2026-11-24), including fallback models.
- OpenAI: no default model IDs or prices (none checked against an OpenAI
  source); both come from the environment.
- Built `opssoc/agents/investigation/` (ADR 006): definition file with prompt
  and budgets, four tools (get_alert, get_incident, run_hunting_query,
  submit_verdict), evidence records with row hashes, fenced tool output,
  verdict checks (citations exist, timeline times appear in cited rows,
  decided verdicts have findings), budgets, writing-tier case note, case
  report for the SOAR writer. Added `get_alert` to the connectors (Graph
  `GET /security/alerts_v2/{id}`).
- Not run with a real model: the owner asked not to spend on LLM calls yet.
  Tests use a scripted provider and fake SDK clients. Engine test runs the
  agent's query tool against the emulator in CI.
- Verified locally: 73 passed, 6 skipped; ruff clean.
