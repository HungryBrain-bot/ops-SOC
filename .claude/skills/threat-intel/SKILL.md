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
OPSSOC_DAC_PATH=<detection_As_Code checkout> python -m opssoc.agents.threat_intel analyse
```
`--brief` calls the LLM (spends money); the deterministic report is complete without it.

## Change the profile
1. A group qualifies only if its ATT&CK description states it targeted the financial
   sector, financial institutions, banks or banking systems, ATMs or SWIFT. "Financially
   motivated" is not enough.
2. Copy the sentence from the pinned bundle's description (links and citations removed by
   `opssoc.intel.attack.plain`); `check_profile` must return no problems.
3. A borderline group you leave out goes in `excluded` with the reason.
4. Never add a group from memory or a news article: only from the pinned ATT&CK data.
   Leave `status` as `proposed` until the owner signs it off.

## Bump a snapshot
1. Download the new file at a commit, hash it, update URL, commit, version and SHA-256 in
   `opssoc/intel/snapshots.json`.
2. Re-run `check_profile`: groups can be revoked, renamed or have descriptions changed.
3. Update the counts in `tests/test_intel_snapshots.py` and the component doc, and log the
   old and new counts in BUILD_LOG.md.

## Gaps to detections
The `gaps` list in `finance_priorities.json` is the input for new detection_As_Code
rules. Adding a rule there follows detection_As_Code's own scope rules and owner approval.

## Do NOT
- Don't let the model choose groups, techniques or CVEs; it only writes the brief.
- Don't present the group list as "who is targeting us" or the ranking as likelihood.
- Don't call a technique covered because a rule exists for a sibling sub-technique.
