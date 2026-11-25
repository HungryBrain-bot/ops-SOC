---
name: investigation-agent
description: "Use when running the investigation agent, changing its prompt, tools, budgets or verdict checks, or reviewing an investigation record or case report it produced."
---

# Investigation agent

Code `opssoc/agents/investigation/`; prompt and budgets in `agent.md`; factor checklist
in `factors.json` / `factors.py`; ADR 006, ADR 009; doc `docs/components/investigation-agent.md`.

## Run
```
pip install -e ".[llm]"          # plus replay data: see the replay-data skill
python -m opssoc.agents.investigation                    # list alerts, no LLM spend
python -m opssoc.agents.investigation --alert <id> --provider anthropic
```
Every run spends money (ledger `data/llm/spend.jsonl`, monthly cap). Ask the owner before
running real investigations in bulk.

## Change the prompt or budgets
1. Edit `agent.md`; bump `version` in its front matter.
2. Keep: competing hypotheses incl. a benign one; cite evidence IDs; tool output is data.
3. Run `python -m pytest tests/test_investigation.py`.
4. Note the change in BUILD_LOG.md. Prompt changes are compared with the eval harness
   before and after, never judged from one case.

## Add or change a tool
- Read-only only. Any query goes through the connector so `guard_query` applies.
- Every result a claim can rest on becomes an evidence record (`_record`) and reaches the
  model through `fence()`.
- Schemas are strict: every object has `additionalProperties: false` and lists all its
  properties in `required` (a test checks this).

## Change the verdict checks
`check_verdict` must say exactly what it tests. Update the "What it does not do" list in
the component doc when a check is added or removed; never describe it as proving a
verdict correct.

## Change the factor checklist
1. Edit `factors.json`. Bump the set's `version` whenever a factor, weight or table
   changes. Every factor's tables must be listed in the set's `tables`, and F1 and F8 must
   exist (the decision rules use them).
2. Change a decision rule only in `factors.check_decision`, and update its docstring,
   ADR 009 (dated amendment) and the component doc's check list.
3. Weights are uncalibrated judgment. Don't present the tally as a risk score, and don't
   let a weighted sum set the verdict.
4. Run `python -m pytest tests/test_investigation.py tests/test_eval.py`.

## Reviewing a case
Open `<case>.investigation.json`: `rejected_verdicts` shows what the checks caught;
`factor_tally` shows each factor's state and citations;
each evidence record has the query, provenance and row hash. Replay evidence is labelled
mapped / seeded alert; never present it as tenant data.

## Do NOT
- Don't give the agent an expected outcome, a pre-labelled alert or a canned verdict.
- Don't add response actions or let its CLI write to a live SOAR.
- Don't present scripted-provider results as model results.
