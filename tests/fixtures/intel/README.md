# Intel fixtures

Extracts of the pinned snapshots (`opssoc/intel/snapshots.json`), recorded, not edited
except to drop fields the code does not read:

- `attack_subset.json`: from MITRE ATT&CK Enterprise v20.1
  (mitre-attack/attack-stix-data a8db2f5, SHA-256 539a843a...): the collection object
  (contents list emptied), groups G0080, G0082, G0049, G0032, techniques T1059,
  T1059.001, T1059.003, T1566.001, T1588.002, T1547.001 and the groups' "uses"
  relationships to them, plus the relationships whose descriptions name CVE-2017-11882 or
  CVE-2017-11774 and their targets. `x_mitre_detection` removed. ATT&CK terms of use
  apply (attack.mitre.org/resources/legal-and-branding/terms-of-use).
- `kev_subset.json`: from CISA KEV catalog 2026.11.23 (cisagov/kev-data 6192ecd,
  SHA-256 ac8f0c4e...): the catalog header and the entries for CVE-2017-11882 and
  CVE-2017-11774. The header's `count` still says 1,792.

Extracted 2026-11-24.
