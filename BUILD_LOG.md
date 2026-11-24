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
