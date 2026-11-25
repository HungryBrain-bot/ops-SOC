# 008. Threat intel agent: deterministic finance priorities, model-written brief checked

## Status
Accepted (2026-11-24)

## Context
ADR 001 point 4: finance-sector intelligence from MITRE ATT&CK and CISA KEV, with a
curated, reviewable group list because neither source has a sector field, and a coverage
gap list against detection_As_Code. Neither source links KEV entries to groups.

## Decision
1. **Pinned snapshots** (`opssoc/intel/snapshots.json`): ATT&CK Enterprise v20.1 STIX from
   mitre-attack/attack-stix-data at a8db2f5, and the KEV catalog 2026.11.23 from
   cisagov/kev-data at 6192ecd, each by URL at a commit and SHA-256. Downloaded on demand
   into `data/intel/`, never committed; refreshing is a deliberate pin bump.
2. **Finance profile** (`intel/finance_profile.json`, JSON so the runtime needs no YAML):
   25 active groups whose ATT&CK description states that they targeted the financial
   sector, financial institutions, banks or banking systems, ATMs or SWIFT. Each carries
   the sentence from its description (checked verbatim against the pinned bundle in CI).
   Tiers: `primary` (finance is the main stated target, 7 groups) and `listed` (one of
   several sectors, 18 groups). "Financially motivated" alone, payment-card theft from
   other sectors, and crypto-only targeting do not qualify; six borderline groups are
   listed as excluded with the reason. Status `proposed` until the owner reviews it.
3. **Priorities are computed, not generated** (`opssoc/intel/finance.py`): each technique
   the profile's groups use (direct group -> technique "uses" relationships) is scored by
   the sum of tier weights (primary 2, listed 1). Techniques whose only tactics are
   reconnaissance or resource development are reported apart from gaps, because no log a
   SIEM rule reads records them.
4. **KEV links come from ATT&CK text**: a CVE named in a profile group's description or
   "uses" relationship descriptions is linked to that group, with the sentence; KEV adds
   vendor, product and known ransomware use. CVEs ATT&CK names that are not in KEV are
   listed as such.
5. **Coverage** against the pinned detection_As_Code rules' ATT&CK mapping
   (non-experimental): `exact`, `partial` (a rule maps the parent, or the technique is a
   parent and a rule maps one of its sub-techniques), else none. A sibling sub-technique is
   not coverage. The gap list is the top 25 with no coverage; it is the input the
   detection agent will take.
6. **The LLM writes only an optional brief** (writing tier) from the computed data. Every
   G/T/CVE ID it names must be in the data, at most 400 words; a rejected brief gets one
   rewrite, then is dropped. The deterministic report stands without it.

## Alternatives considered
- **Let the model choose finance-relevant groups or techniques**: not reproducible and not
  reviewable; the sector judgment stays in a file a person signs off.
- **Keyword match on descriptions ("financ", "bank")**: catches "financially motivated"
  groups that never targeted finance; the rule needs sector targeting.
- **Software -> technique and campaign -> technique inheritance**: more techniques, but
  attribution through shared software is weaker; direct group relationships only.
- **KEV vendor / product heuristics for finance**: no source says which products banks run.

## Consequences
- The ranking reflects what ATT&CK has recorded about these groups, which over-weights
  well-documented groups and older reporting.
- Weighting (2 / 1) is a judgment; the JSON output keeps the group list per technique so
  other weightings can be computed.
- "Covered" means a DaC rule maps the technique, not that it is deployed, active for a
  customer, or detects every procedure of that technique.
- No model has written a brief yet (no LLM spend in this PR).

## Amendment (2026-11-25): web evidence for every profile group
At the owner's request, a group's inclusion now rests on public reporting of its victims,
not only on its ATT&CK description.
- **Rule**: a group is included when a fetched public report (vendor research, government
  advisory or indictment, or a news report of one) names financial-sector organisations
  among its victims or targets. An ATT&CK sentence alone is not enough. The tier definitions
  are unchanged.
- **Record**: each group carries `web_evidence`: a status (`confirmed`, `weak`, `not_found`
  or `not_finance`) and sources with publisher, URL, publication date, fetch date and a
  quote. `check_profile` requires `confirmed` or `weak` and complete sources for every
  included group. A group added from reporting may have no ATT&CK sentence; when it has
  one, the sentence is still checked against the bundle.
- **Result** (31 groups checked, 2026-11-25): 25 included (6 primary, 19 listed).
  - Added: Lazarus Group, AppleJeus and FIN4.
  - Removed: RTM (its victims are businesses that use remote banking), MirrorFace and
    Moses Staff (no fetched report names a finance victim).
  - Still excluded: admin@338, FIN5 and FIN6.
  - APT41 is `weak`: finance appears only as a figure label in Mandiant's 2019 report.
- **Limits**: quotes came through a fetch tool that summarises pages with a model, so they
  are not checked byte-for-byte. Five sources are news reports of vendor research, not the
  vendor's own page. Lazarus Group overlaps APT38 and Andariel in ATT&CK, so techniques
  they share are counted for each. Status stays `proposed` until the owner signs it off.

## Amendment (2026-11-25): profile approved; gap handoff file
- **Approval**: the owner approved the web-checked profile on 2026-11-25. The profile file
  records it under `approval` (by, date, basis). `check_profile` accepts only `proposed`
  or `approved`, and an `approved` profile must have that record. Any change to the
  groups returns the status to `proposed` until the owner approves again.
- **Handoff**: `analyse` writes `build/intel/finance_gaps.json` (schema
  `opssoc.finance-gaps/1`) whenever detection_As_Code rules are loaded. The file holds the
  top-25 gaps, the partly covered techniques with their related rules, and the
  pre-compromise techniques, each with its groups, plus the ATT&CK, KEV and DaC versions.
  It has no timestamp, so it is reproducible. This is the contract the detection agent
  will read. It does not decide which rules get built.
- **Check command**: `python -m opssoc.agents.threat_intel check` runs `check_profile` on
  the pinned bundle and exits 1 on any problem. CI runs it before `analyse`.
