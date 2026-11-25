# Test fixtures

- `otrf_empire_launcher_vbs_extract.jsonl`: **recorded**. 8 events copied unchanged
  from OTRF Security-Datasets `datasets/atomic/windows/execution/host/empire_launcher_vbs.zip`
  (commit d9d40ef, file `empire_launcher_vbs_2020-09-04160940.json`, MIT licence): Sysmon 1
  for wscript.exe, powershell.exe and whoami.exe; the first Sysmon 3, 11, 12 and 13 events
  of that process chain; and one Security-channel event, which the mapping must skip.
- Graph and Kusto responses in the tests are **written from the vendor reference pages**
  (Graph runHuntingQuery example, Kusto v2 frame format), not recorded.
