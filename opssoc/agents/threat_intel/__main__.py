"""python -m opssoc.agents.threat_intel fetch | check | analyse

    fetch                       download the pinned ATT&CK and KEV snapshots (SHA-256 checked)
    check [--profile PATH]      check the finance profile against the pinned ATT&CK bundle
                                (groups active, sentences verbatim, web evidence complete,
                                status / approval); exit 1 on any problem
    analyse [--out build/intel] [--brief --provider anthropic|openai]
                                priorities, coverage against detection_As_Code (when
                                OPSSOC_DAC_PATH is set) and KEV links; --brief adds a
                                model-written brief (spends money)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from opssoc.agents.threat_intel.agent import write_brief, write_outputs
from opssoc.intel import finance, snapshots
from opssoc.intel.attack import Attack
from opssoc.intel.kev import Kev


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.agents.threat_intel")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch")
    c = sub.add_parser("check")
    c.add_argument("--profile", default=str(finance.PROFILE))
    a = sub.add_parser("analyse")
    a.add_argument("--out", default="build/intel")
    a.add_argument("--profile", default=str(finance.PROFILE))
    a.add_argument("--brief", action="store_true")
    a.add_argument("--provider", choices=["anthropic", "openai"], default="anthropic")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        for name in snapshots.PINS:
            print(f"{name}: {snapshots.fetch(name)}")
        return 0

    attack = Attack.from_bundle(snapshots.load("attack-enterprise"))
    kev = Kev.from_catalog(snapshots.load("cisa-kev"))
    profile = finance.load_profile(Path(args.profile))
    problems = finance.check_profile(profile, attack)
    if args.command == "check":
        for p in problems:
            print(p)
        print(f"{len(profile['groups'])} groups, status {profile.get('status')}: "
              f"{len(problems)} problem(s)")
        return 1 if problems else 0
    if problems:
        raise SystemExit("finance profile does not match ATT&CK:\n" + "\n".join(problems))
    from opssoc.replay import dac_bridge

    rules = dac_bridge.load_rules() if dac_bridge.available() else None
    analysis = finance.analyse(profile, attack, kev, rules)
    brief = None
    if args.brief:
        from opssoc.llm import get_provider

        brief = write_brief(get_provider(args.provider), analysis)
    handoff = finance.gap_handoff(analysis,
                                  dac_bridge.DAC_COMMIT if rules is not None else None)
    js, md = write_outputs(Path(args.out), analysis, brief, handoff)
    print(json.dumps({"counts": analysis["counts"],
                      "gaps": None if analysis["gaps"] is None else
                      [t["id"] for t in analysis["gaps"]],
                      "brief": None if brief is None else brief.status,
                      "json": str(js), "markdown": str(md),
                      "gaps_file": None if handoff is None
                      else str(js.parent / "finance_gaps.json")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
