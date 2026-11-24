# CLAUDE.md

## Project

ops-SOC: a SOC platform with three LLM agents (investigation, finance-sector
threat intelligence, detection engineering) over Microsoft Defender and
Microsoft Sentinel (Sentinel onboarded to the Defender portal). Successor to
the `opsmind-hackathon` demo, which was a scripted replay and is not reused
as a base. No live tenant exists: everything except API credentials is built
and tested here, on recorded OTRF data in the Kusto emulator.

Architecture: docs/decisions/001-architecture.md (ADR 001).

Before adding an agent, connector, data source or write path beyond Scope,
check the request is explicit from the owner (Venu).

## Scope

| Area | In scope | Out of scope |
|------|----------|--------------|
| Agents | Investigation, threat intel (finance), detection (via detection_As_Code) | Hunting agent |
| Data connectors | Graph security API (alerts_v2, incidents, runHuntingQuery); Sentinel Log Analytics + ARM incidents as fallback; CISA KEV; MITRE ATT&CK STIX | Any other SIEM / EDR |
| Writes | One SOAR writer: incident comment / case note, dry-run by default | Response actions (isolate, disable, close, reassign) |
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

`python -m pytest` and `ruff check` before every commit (none yet).

## Current status

- Built: nothing yet. ADR 001 proposed.
- Open: SOAR target (proposed: Graph incident comments); USD 100 cap period
  (assumed monthly); CISA sources beyond KEV.

## Do NOT

- Don't add response actions or any write besides the SOAR writer.
- Don't reintroduce request-selected scenarios, pre-tagged evidence or canned
  verdicts (the opsmind-hackathon failure modes).
- Don't add real API keys, tenant names or customer data.
- Don't describe replay runs as running against a real tenant.
