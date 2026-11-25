"""python -m opssoc.agents.investigation [--alert ID] ...

    no --alert            list the backend's alerts (no LLM call)
    --alert ID            investigate it; writes build/investigations/<case>.json and the
                          case report, and optionally hands the report to the SOAR writer
    --backend replay|graph            replay (default): Kusto emulator + seeded alerts
    --provider anthropic|openai       credentials from the environment only
    --soar xsoar|secops --soar-mode dry-run|test   never live from here

An investigation calls the LLM provider and spends money (ledger data/llm/spend.jsonl,
monthly cap in opssoc/llm/settings.py).
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from opssoc.agents.investigation.agent import InvestigationAgent, to_case_report
from opssoc.connectors import GraphSecurityConnector, ReplayConnector
from opssoc.llm import get_provider


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.agents.investigation")
    parser.add_argument("--alert")
    parser.add_argument("--backend", choices=["replay", "graph"], default="replay")
    parser.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic")
    parser.add_argument("--out", default="build/investigations")
    parser.add_argument("--soar", choices=["xsoar", "secops"])
    parser.add_argument("--soar-mode", choices=["dry-run", "test"], default="dry-run")
    args = parser.parse_args(argv)

    connector = ReplayConnector() if args.backend == "replay" else GraphSecurityConnector()
    if not args.alert:
        for alert in connector.list_alerts(top=100):
            print(f"{alert['id']}  {alert.get('severity', '?'):<8} "
                  f"{alert.get('firstActivityDateTime', '')}  {alert.get('title', '')}")
        return 0

    alert = connector.get_alert(args.alert)
    inv = InvestigationAgent(connector, get_provider(args.provider)).run(args.alert)
    report = to_case_report(inv, alert)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{report.case_id}.investigation.json").write_text(
        json.dumps(inv.to_json(), indent=2, default=str), encoding="utf-8")
    report_path = out / f"{report.case_id}.case.json"
    report_path.write_text(json.dumps(asdict(report), indent=2, default=str), encoding="utf-8")
    print(json.dumps({"status": inv.status, "verdict": report.verdict.value,
                      "evidence": len(inv.evidence), "queries": inv.queries,
                      "llm_turns": inv.llm_turns, "cost_usd": round(inv.usage.cost_usd, 4),
                      "models": inv.models, "case_report": str(report_path)}, indent=2))
    if args.soar:
        from opssoc.soar.__main__ import main as soar_main

        return soar_main(["write", "--target", args.soar, "--report", str(report_path),
                          "--mode", args.soar_mode])
    return 0


if __name__ == "__main__":
    sys.exit(main())
