# 007. Eval harness: labelled replay alerts, scored investigation records

## Status
Accepted (2026-11-24)

## Context
The investigation agent (ADR 006) needs a repeatable measure of whether it reaches the
right verdict and states the facts that matter. Replay alerts (ADR 004) come only from
recorded OTRF attack simulations, so every one of them is a true positive: an eval of
those alone rewards an agent that always says "true positive".

## Decision
1. **Cases label seeded alerts** (`opssoc/eval/ground_truth.json`): rule ID, replay dataset
   and substrings of the matched row identify exactly one alert; the case gives the
   expected verdict, the label's source and key facts. The agent receives only the alert
   ID and never reads this file (a test checks the agent code does not reference it).
2. **Label sources**: for attack activity, the OTRF dataset metadata (`SDWIN-*.yaml`, read
   with git at the pinned OTRF commit on 2026-11-24, file hashes recorded). For benign
   activity, which OTRF metadata does not describe, this project's judgment, marked
   `ops-soc-judgment` with the recorded evidence it rests on.
3. **Benign cases come from eval rules** (`opssoc/eval/rules.json`): loosened versions of
   detection_As_Code endpoint rules (A3 widened to any `reg save|export HKLM`; A2 without
   its writer exclusions). They match both the recorded attacks and recorded background
   activity: Azure Network Watcher diagnostics exporting registry keys, and Defender
   setting its own Run value. Seeded only with `seed --eval-rules`; never deployed.
   Their alerts say they come from an ops-SOC eval rule, and because these rules produce
   true positives as well as benign alerts, that label does not give the answer away.
4. **Key facts** are strings from the recorded events (checked in CI against the data).
   Scoring counts a fact as stated if it appears in the verdict text, and as grounded if
   it also appears in the rows of the evidence the verdict cites.
5. **Scores per case**: verdict correct, key-fact recall, grounded-fact recall, citations
   re-checked on the stored evidence, rejected verdicts, cost, turns, queries. Summary:
   accuracy overall and per label source, confusion, inconclusive and budget stops,
   cost. No single blended score.
6. **Runs spend money only when asked**: `python -m opssoc.eval run` prints the worst-case
   cost (cases x per-case budget) and needs `--yes`. CI checks the cases against the
   seeded alerts and the facts against the data; it never calls an LLM.
7. **Coverage is strict**: every case must match exactly one alert and every seeded alert
   must be labelled; CI fails otherwise, so a rule or dataset change cannot shift the eval
   silently.

## Alternatives considered
- **Hand-written benign alerts with invented events**: easy to balance, but the agent would
  investigate events no system recorded. Benign cases here are recorded events.
- **LLM-as-judge scoring**: scores reasoning quality, but adds a model whose errors look
  like the agent's. Deterministic checks first; a judge can be added later and reported
  separately.
- **Labelling per dataset**: every alert in an attack dataset would be "malicious",
  including the background activity the eval rules find. Labels are per alert.

## Consequences
- 12 cases: 10 true positive, 2 benign. Too few and too unbalanced for fine comparisons;
  treat results as a smoke test of the agent, not a benchmark. More benign cases need
  more recorded benign data or more eval rules.
- Several cases share activity (A1 and A2 both see the Run-key persistence; e1 and A3 the
  SAM save), so results are not independent.
- The two benign labels are judgments; the bitsadmin case downloads a red-team test file
  that OTRF calls malicious, which an analyst in a lab might call an authorised test.
- No model has been run against the eval yet (no LLM spend in this PR).
