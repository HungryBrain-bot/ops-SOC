---
name: threat-intel
description: "Use when running the finance threat-intel analysis, reviewing or changing the finance group profile, bumping the ATT&CK or KEV snapshot, or handing coverage gaps to detection work."
---

# Threat intel (finance)

Code `opssoc/intel/`, `opssoc/agents/threat_intel/`; profile `intel/finance_profile.json`;
ADR 008; doc `docs/components/threat-intel.md`.

## Run
```
python -m opssoc.agents.threat_intel fetch
python -m opssoc.agents.threat_intel check     # must print 0 problem(s)
OPSSOC_DAC_PATH=<detection_As_Code checkout> python -m opssoc.agents.threat_intel analyse
```
`--brief` calls the LLM (spends money); the deterministic report is complete without it.

## Change the profile
1. A group qualifies only if a fetched public report names financial-sector organisations
   (banks, financial institutions, financial-services, investment or crypto-exchange
   firms, ATMs, SWIFT) among its victims or targets (owner's rule, 2026-11-25). Being
   "financially motivated", stealing cards at merchants, targeting finance policy bodies or
   robbing other businesses' bank accounts is not enough.
2. Search for the group's victims, then fetch the report itself. Prefer the vendor's or
   agency's own page over news coverage; when only news coverage loads, say so in `note`.
   Record `web_evidence`: status (`confirmed`, `weak` for a label-only mention), and
   sources with publisher, URL, publication date, fetch date and a quote.
3. If the group's ATT&CK description also names finance, copy that sentence from the
   pinned bundle (links and citations removed by `opssoc.intel.attack.plain`); otherwise
   leave `source_sentence` null. `check_profile` must return no problems.
4. A group you leave out goes in `excluded` with the reason and its `web_evidence`
   (`not_found` or `not_finance`).
5. Never add a group or quote from memory. Any change to the groups sets `status` back to
   `proposed`. Only the owner moves it to `approved`, and an approval is recorded in
   `approval` (by, date, basis); `check` requires it.

## Bump a snapshot
1. Download the new file at a commit, hash it, update URL, commit, version and SHA-256 in
   `opssoc/intel/snapshots.json`.
2. Re-run `check_profile`: groups can be revoked, renamed or have descriptions changed.
3. Update the counts in `tests/test_intel_snapshots.py` and the component doc, and log the
   old and new counts in BUILD_LOG.md.

## Gaps to detections
`build/intel/finance_gaps.json` (schema `opssoc.finance-gaps/1`) is the detection agent's
input. It is written only when `OPSSOC_DAC_PATH` is set. It holds the gaps, the partly
covered techniques and their related rules, and the groups behind each one. A gap is not a
request for a rule: adding one follows detection_As_Code's own scope rules and needs the
owner's approval. If you change the file's fields, bump the schema version and update
`tests/test_threat_intel.py::test_gap_handoff`.

## Do NOT
- Don't let the model choose groups, techniques or CVEs; it only writes the brief.
- Don't present the group list as "who is targeting us" or the ranking as likelihood.
- Don't call a technique covered because a rule exists for a sibling sub-technique.
