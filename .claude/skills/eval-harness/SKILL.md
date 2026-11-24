---
name: eval-harness
description: "Use when running or scoring the investigation eval, adding or changing a ground-truth case or eval rule, or comparing a prompt, model or budget change on the agent."
---

# Eval harness

Code `opssoc/eval/`; ADR 007; doc `docs/components/eval-harness.md`.

## Run
```
python -m opssoc.replay seed --eval-rules
python -m opssoc.eval cases                    # must print no PROBLEM / UNLABELLED lines
python -m opssoc.eval run --provider anthropic --yes
```
`run` spends money (cases x per-case budget at worst). Get the owner's go-ahead before a
full run; use `--only <case>` to try one.

## Compare a change
Run the same cases before and after, on the same provider and models, more than once if
the difference is small. Report accuracy, recall, grounded recall, invalid citations,
inconclusive/budget stops and cost side by side. Never report one blended number, and
never claim an improvement from a single run of 12 cases.

## Add a case
1. The alert must come from a rule run over recorded data (`seed`); never write an alert
   by hand.
2. Label source: OTRF metadata (add it to `sources` with its file hash and fetch date) or
   `ops-soc-judgment` with the recorded evidence that supports it in `basis`.
3. Key facts: strings from the recorded events; the CI test checks they are in the data.
4. `python -m opssoc.eval cases` must show every alert labelled exactly once.

## Add an eval rule
Loosen an existing detection_As_Code rule so it also matches recorded background
activity; set `status: eval`; never deploy it. Record why in ADR 007's amendments.

## Do NOT
- Don't let the agent, its prompt or its tools read `ground_truth.json`.
- Don't score scripted-provider runs and present them as model results.
- Don't relabel a case to make a run pass; amend the label only with new evidence, noted
  in BUILD_LOG.md.
