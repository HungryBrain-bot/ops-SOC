# 006. Investigation agent: evidence records, cited verdicts, checks before acceptance

## Status
Accepted (2026-11-24)

## Context
ADR 001 point 3: the agent takes an alert ID, gathers evidence itself through the read-only
connector, and produces a verdict whose claims cite evidence IDs that are validated. The
input never names an expected outcome. Log content is attacker-controlled.

## Decision
1. **Definition file** (`opssoc/agents/investigation/agent.md`): front matter for tiers and
   budgets, body for the system prompt. Versioned with the code.
2. **Four tools**: `get_alert`, `get_incident`, `run_hunting_query` (KQL through the
   connector's guard; management commands refused) and `submit_verdict`. No write tool.
3. **Evidence records**: the alert is EV-0; every alert, incident or query result read is
   EV-n with the query, purpose, connector provenance, all rows (up to the connector cap)
   and a SHA-256 of the rows. The model sees at most 50 rows and 1,500 characters a cell;
   the record keeps the rest. Failed or refused queries are returned as errors, not
   evidence.
4. **Fencing**: every tool output reaches the model inside
   `<tool_output evidence_id=".." trust="untrusted-data">` with any closing tag in the data
   neutralised; the prompt says the content is data and that instructions in it are
   findings.
5. **Verdict**: `true_positive`, `benign` or `inconclusive`, confidence, summary,
   hypotheses (supported / refuted / open), timeline, findings, what was not checked,
   recommended actions, ATT&CK techniques. Checks before acceptance: every cited ID exists;
   every timeline entry and finding cites something; each timeline time (to the minute)
   appears in the evidence it cites; a decided verdict has at least one finding. A rejected
   verdict goes back to the model with the reasons.
6. **Budgets** (per investigation): model turns, queries, USD. When one is reached the
   model is asked once for a verdict on the evidence it has; otherwise the result is
   `inconclusive: stopped: budget`. The monthly cap (ADR 005) ends it the same way.
7. **Per-task models**: the loop runs on the `reasoning` tier; after an accepted verdict a
   short analyst note is written on the `writing` tier from the verdict JSON only. If it
   fails, the verdict's summary is used.
8. **Output**: the full investigation record (evidence, verdict, rejected verdicts,
   usage, models) and a `CaseReport` with only the cited evidence, each labelled
   `mapped`, `seeded alert`, `recorded` or `live`. The SOAR writer takes the report in
   dry-run or test mode from the agent's CLI; live SOAR writes stay in the SOAR CLI.

## Alternatives considered
- **Free-text verdict parsed afterwards**: citations cannot be checked reliably.
- **Pre-planned query playbooks per alert type**: predictable, but the agent would only
  look where the playbook author looked; the prompt asks for competing hypotheses instead.
- **LLM-as-judge for citations**: another model call that can be wrong the same way; the
  checks here are deterministic and say exactly what they test.

## Consequences
- The checks test that citations exist and times appear in the cited rows. They do not
  test that a finding's statement is true of the rows it cites; the eval harness and an
  analyst review do.
- Nothing stops a model from querying very broad tables within its budgets; the
  connector's row cap and the shown-rows limit bound what it reads.
- Behaviour with a real model is not measured in this PR (the owner asked not to spend on
  LLM calls yet). Tests use a scripted provider.
