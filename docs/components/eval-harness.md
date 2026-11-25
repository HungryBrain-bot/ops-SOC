# Eval harness

Code: `opssoc/eval/` (cases, eval rules, scoring, CLI). Decision: ADR 007.

## What it does
Measures the investigation agent on labelled replay alerts: does it reach the expected
verdict, does it state the key facts, are those facts in the evidence it cites, are its
citations valid, does it pass the factor and decision checks (ADR 009,
`factor_checks_valid`, with the record's `factor_tally`), and what did it cost.

## How
```
python -m opssoc.replay seed --eval-rules       # DaC rules + eval rules -> 12 alerts
python -m opssoc.eval cases                     # every case matched to one alert; no LLM
python -m opssoc.eval run --provider anthropic  # prints the worst-case cost
python -m opssoc.eval run --provider anthropic --yes [--only <case>]
python -m opssoc.eval score build/eval/<run>    # re-score saved records
```
A run writes `build/eval/<provider>-<time>/<case>.investigation.json` and `score.json`.

| Case | Alert from | Expected | Label |
|---|---|---|---|
| tp-a1-vbs-launcher | DaC A1, launcher-vbs | true_positive | OTRF SDWIN-190518182022 |
| tp-a1-runkey-execution | DaC A1, runkey-standard-user | true_positive | OTRF SDWIN-190319023812 |
| tp-a2-runkey-standard | DaC A2, runkey-standard-user | true_positive | OTRF SDWIN-190319023812 |
| tp-a2-runkey-elevated | DaC A2, runkey-elevated-user | true_positive | OTRF SDWIN-200722001847 |
| tp-a3-reg-save-sam | DaC A3, reg-dump-sam | true_positive | OTRF SDWIN-190625133822 |
| tp-a3-esentutl-vss | DaC A3, sam-copy-esentutl | true_positive | OTRF SDWIN-201019002900 |
| tp-a4-bitsadmin | DaC A4, bitsadmin-download | true_positive | OTRF SDWIN-201023023651 |
| tp-e1-reg-save-sam | eval e1, reg-dump-sam | true_positive | OTRF SDWIN-190625133822 |
| tp-e2-runkey-standard | eval e2, runkey-standard-user | true_positive | OTRF SDWIN-190319023812 |
| tp-e2-runkey-elevated | eval e2, runkey-elevated-user | true_positive | OTRF SDWIN-200722001847 |
| bn-e1-network-watcher-diagnostics | eval e1, runkey-standard-user | benign | ops-SOC judgment |
| bn-e2-defender-run-key | eval e2, runkey-standard-user | benign | ops-SOC judgment |

Benign basis (recorded in the runkey-standard-user dataset; both labels approved by the owner on 2026-11-25):
- **Network Watcher**: `NetworkWatcherAgent.exe` (Azure Network Watcher VM extension under
  `C:\Packages\Plugins\`) runs `netsh trace`; netsh starts `cscript gatherNetworkInfo.vbs`
  as the machine account, which runs `cmd /c reg export` of network and credential-provider
  keys. Minutes from the Empire persistence on the same host.
- **Defender Run value**: `C:\Program Files\Windows Defender\MsMpEng.exe` sets Run value
  `WindowsDefender`.

## Why this method
Every case is a recorded event and every label names its source, so a score can be traced
back to data. Deterministic checks say exactly what they test; there is no model grading
another model. Strict alert coverage keeps the eval in step with the rules and datasets.

## What it does not do
- It does not judge reasoning quality beyond verdict and key facts, or check that a cited
  row says what a finding claims.
- 12 cases, 10 of them true positives, several sharing the same activity: a smoke test,
  not a benchmark. No variance across runs unless you run it several times.
- No cases from Defender-native or Sentinel-native alerts, identity or cloud data.
- Two labels are this project's judgment.
- It has not been run with a real model yet.
