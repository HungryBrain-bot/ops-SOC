"""python -m opssoc.eval cases | run | score

    cases                 match ground truth to data/replay/alerts.json; no LLM call
    run --provider P --yes [--only CASE] [--out DIR]
                          run the investigation agent on every case (spends money; the
                          monthly cap applies), write one record per case, then score
    score DIR             score existing records

Seed first with `python -m opssoc.replay seed --eval-rules`. The agent receives only
the alert ID; it never reads ground_truth.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from opssoc.eval.cases import load_cases, match
from opssoc.eval.score import score_dir


def _alerts(path: Path) -> list[dict]:
    if not path.is_file():
        raise SystemExit(f"{path} missing: run `python -m opssoc.replay seed --eval-rules`")
    return json.loads(path.read_text(encoding="utf-8"))["alerts"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.eval")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("cases")
    c.add_argument("--alerts", default="data/replay/alerts.json")
    r = sub.add_parser("run")
    r.add_argument("--provider", choices=["anthropic", "openai"], required=True)
    r.add_argument("--alerts", default="data/replay/alerts.json")
    r.add_argument("--only")
    r.add_argument("--out")
    r.add_argument("--yes", action="store_true", help="confirm the LLM spend")
    s = sub.add_parser("score")
    s.add_argument("dir")
    args = parser.parse_args(argv)

    cases = load_cases()
    if args.command == "score":
        print(json.dumps(score_dir(cases, Path(args.dir)), indent=2))
        return 0

    matching = match(cases, _alerts(Path(args.alerts)))
    if args.command == "cases":
        for case in cases:
            alert = matching.pairs.get(case.id)
            print(f"{case.id:<36} {case.expected_verdict:<14} {case.label['kind']:<18} "
                  f"{alert['id'] if alert else '-'}")
        for problem in matching.problems:
            print(f"PROBLEM {problem}")
        for alert in matching.unlabelled:
            print(f"UNLABELLED {alert['id']} {alert['title']}")
        return 1 if matching.problems or matching.unlabelled else 0

    from opssoc.agents import load_definition
    from opssoc.agents.investigation import InvestigationAgent
    from opssoc.agents.investigation.agent import DEFINITION
    from opssoc.connectors import ReplayConnector
    from opssoc.llm import get_provider

    if matching.problems:
        raise SystemExit("\n".join(matching.problems))
    chosen = [c for c in cases if not args.only or c.id == args.only]
    if not chosen:
        raise SystemExit(f"no case {args.only}")
    worst = len(chosen) * load_definition(DEFINITION).number("max_case_usd", 3.0)
    if not args.yes:
        raise SystemExit(f"{len(chosen)} investigations, up to USD {worst:.2f} "
                         "(per-case budget). Re-run with --yes to spend it.")
    from opssoc.eval.hiding import HiddenTablesConnector

    replay, provider = ReplayConnector(), get_provider(args.provider)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = Path(args.out or f"build/eval/{args.provider}-{stamp}")
    out.mkdir(parents=True, exist_ok=True)
    for case in chosen:
        connector = HiddenTablesConnector(replay, case.hide_tables) if case.hide_tables \
            else replay
        record = InvestigationAgent(connector, provider).run(matching.pairs[case.id]["id"])
        (out / f"{case.id}.investigation.json").write_text(
            json.dumps(record.to_json(), indent=2, default=str), encoding="utf-8")
        print(f"{case.id}: {record.status} "
              f"{(record.verdict or {}).get('verdict', '-')} USD {record.usage.cost_usd:.3f}")
    scored = score_dir(chosen, out)
    (out / "score.json").write_text(json.dumps(scored, indent=2), encoding="utf-8")
    print(json.dumps(scored["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
