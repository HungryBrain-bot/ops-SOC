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
python -m opssoc.agents.threat_intel check                 # profile vs. the pinned bundle
OPSSOC_DAC_PATH=../detection_As_Code \
python -m opssoc.agents.threat_intel analyse [--brief --provider anthropic]
```
`analyse` writes to `build/intel/`:
- `finance_priorities.json` and `.md`: the full analysis and the report.
- `finance_gaps.json`: written only when DaC rules were loaded. It is the detection agent's
  input (schema `opssoc.finance-gaps/1`): the top-25 techniques with no rule, those only
  partly covered (with the related rules), and the pre-compromise ones, each with the
  profile groups behind it, plus the ATT&CK, KEV and DaC versions. It has no timestamp, so
  the same inputs give the same file. A run without DaC removes a stale copy.

`check` exits 1 if a group is not active in the bundle, an ATT&CK sentence is not verbatim,
web evidence is incomplete, or the status is not `proposed` / `approved`. An `approved`
profile must also have `approval.by`, `date` and `basis`. CI job `intel` runs `check`, then
`analyse` without `--brief` against DaC at the pinned commit, and uploads `build/intel/` as
the `finance-priorities` artifact.

Result on the pinned snapshots, using the profile approved on 2026-11-25 and DaC 51080aa:
- 25 groups (6 primary, 19 listed) and 291 techniques.
- ATT&CK names 31 CVEs for these groups: 28 are in KEV, and 15 of those have known
  ransomware use.
- Top five techniques:
  - T1059.001 PowerShell, covered by DaC A1.
  - T1588.002 Tool: resource development, outside SIEM telemetry.
  - T1566.001 Spearphishing Attachment.
  - T1204.002 Malicious File.
  - T1105 Ingress Tool Transfer, covered by DaC A4.
- Coverage of the top 25:
  - 3 exact: A1, A2, A4.
  - 1 partial: T1078, from the B-track T1078.004 rules and B12.
  - 1 pre-compromise: T1588.002.
  - 20 gaps.

## Why this method
The sector judgment is in one reviewable file with a fetched web source per group (and the ATT&CK sentence where there is one); every
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
