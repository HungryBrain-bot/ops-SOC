"""python -m opssoc.soar write | stub

    write --target xsoar|secops --report case.json [--mode dry-run|test|live]
        dry-run (default): requests to build/soar/<target>/<case>.json
        test: starts a local stub SOAR, pushes over HTTP, prints what it received
        live: needs the target's credential env vars (ADR 002)
    stub [--port 8765]: run the stub server in the foreground
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from opssoc.case import CaseReport
from opssoc.soar import WRITERS
from opssoc.soar.stub_server import StubSoar


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.soar")
    sub = parser.add_subparsers(dest="command", required=True)
    write = sub.add_parser("write")
    write.add_argument("--target", choices=sorted(WRITERS), required=True)
    write.add_argument("--report", required=True)
    write.add_argument("--mode", choices=["dry-run", "test", "live"], default="dry-run")
    write.add_argument("--out", default="build/soar")
    stub = sub.add_parser("stub")
    stub.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)

    if args.command == "stub":
        server = StubSoar(port=args.port).start()
        print(f"stub SOAR on {server.base_url} (Ctrl-C to stop)")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            server.stop()
        return 0

    report = CaseReport.load(args.report)
    writer_cls = WRITERS[args.target]
    if args.mode == "test":
        with StubSoar(secops_cases={report.secops_case_id or "4242"}) as server:
            result = writer_cls(base_url=server.base_url).write(report, "test", out_dir=args.out)
            received = server.received
    else:
        result = writer_cls().write(report, args.mode, out_dir=args.out)
        received = None
    print(json.dumps({"target": result.target, "mode": result.mode.value,
                      "outcome": result.outcome, "reference": result.reference,
                      "statuses": result.statuses}, indent=2))
    if received is not None:
        print(f"stub received {len(received)} request(s): "
              + ", ".join(item["endpoint"] for item in received))
    return 0


if __name__ == "__main__":
    sys.exit(main())
