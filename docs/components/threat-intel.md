# Threat intel agent (finance)

Code: `opssoc/intel/` (snapshots, ATT&CK and KEV readers, finance analysis),
`opssoc/agents/threat_intel/` (definition, brief, report, CLI). Profile:
`intel/finance_profile.json`. Decision: ADR 008.

## What it does
From pinned MITRE ATT&CK and CISA KEV snapshots and a curated list of finance-targeting
groups, it computes which ATT&CK techniques matter most for a financial-services
organisation, which of them the detection_As_Code rules do not cover, and which KEV
vulnerabilities ATT&CK says those groups exploited. Optionally a model writes a short
brief from those results, with every ID checked.

## How
```
python -m opssoc.agents.threat_intel fetch                 # pinned snapshots, SHA-256 checked
OPSSOC_DAC_PATH=../detection_As_Code \
python -m opssoc.agents.threat_intel analyse [--brief --provider anthropic]
```
Writes `build/intel/finance_priorities.json` and `.md`. CI job `intel` runs this without
`--brief` and uploads the result as the `finance-priorities` artifact.

Result on the pinned snapshots (2026-11-24): 25 groups, 269 techniques, 30 CVEs named by
ATT&CK for them, 27 in KEV (14 with known ransomware use). Top five techniques:
T1588.002 Tool (resource development, outside SIEM telemetry), T1059.001 PowerShell
(covered by DaC A1), T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1105
Ingress Tool Transfer (covered by DaC A4). 21 of the top 25 have no rule (unchanged after the 2026-11-25 profile revision; 291 techniques, 28 KEV CVEs).

## Why this method
The sector judgment is in one reviewable file with a source sentence per group; every
number after that is computed from pinned data, so two runs agree and a reviewer can trace
each line. The model only phrases what was computed, and the ID check stops it adding
groups, techniques or CVEs.

## What it does not do
- It does not say who is targeting a given organisation, or how likely an attack is.
- Coverage is "a rule maps this technique", not "deployed, active and detecting every
  procedure"; DaC's gate and coverage layers answer that per customer.
- It uses only direct group -> technique relationships; software and campaign links are
  not inherited.
- CISA advisories beyond KEV are not read (open question in ADR 001).
- The profile is `proposed` until the owner reviews it; the 2 / 1 tier weights are a
  judgment.
- Web evidence (ADR 008 amendment, 2026-11-25): every group names a fetched report of a
  finance victim or target. The check tests that the record is complete (status, URL,
  fetch date, quote); it does not refetch the page or check that the quote is on it. The
  quotes came through a summarising fetch tool. A report that names a sector shows that the
  group targeted it once, not how often or how recently.
- The brief check catches unknown IDs and length, not wrong statements about known IDs.
