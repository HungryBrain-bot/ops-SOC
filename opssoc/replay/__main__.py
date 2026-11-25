"""python -m opssoc.replay fetch | map | load

    fetch [--only NAME]   download the pinned OTRF datasets into data/datasets/, verify SHA-256
    map --out DIR         map every fetched dataset to Defender rows (JSONL per table), offline
    load [--kusto-url]    create the Device* tables in the Kusto emulator and ingest the rows
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

from opssoc.replay.kusto import KustoClient
from opssoc.replay.sysmon_to_defender import TABLES, SysmonToDefender, read_events, schema

PINS = json.loads((Path(__file__).resolve().parent / "datasets.json").read_text())
DATA = Path("data/datasets")


def fetch(only: str | None = None) -> list[Path]:
    paths = []
    for name, pin in PINS["datasets"].items():
        if only and name != only:
            continue
        target = DATA / name
        if not any(target.glob("*.json")):
            url = f"{PINS['base_url']}/{PINS['commit']}/{pin['path']}"
            raw = urllib.request.urlopen(url, timeout=120).read()  # noqa: S310 (pinned URL)
            digest = hashlib.sha256(raw).hexdigest()
            if digest != pin["sha256"]:
                raise SystemExit(f"{name}: SHA-256 {digest} != pinned {pin['sha256']}")
            target.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for member in archive.namelist():
                    if member.endswith(".json") and "/" not in member.strip("/"):
                        (target / member).write_bytes(archive.read(member))
        paths += sorted(target.glob("*.json"))
        print(f"{name}: {', '.join(p.name for p in target.glob('*.json'))}")
    return paths


def mapped() -> tuple[dict[str, list[dict]], dict]:
    rows: dict[str, list[dict]] = {t: [] for t in TABLES}
    report = {}
    for name in PINS["datasets"]:
        for path in sorted((DATA / name).glob("*.json")):
            result = SysmonToDefender().map(read_events(path))
            for table, items in result.rows.items():
                rows[table] += items
            report[name] = {"rows": result.counts(), "skipped": sum(result.skipped.values())}
    return rows, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.replay")
    sub = parser.add_subparsers(dest="command", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--only")
    m = sub.add_parser("map")
    m.add_argument("--out", default="build/replay")
    lo = sub.add_parser("load")
    lo.add_argument("--kusto-url")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        fetch(args.only)
        return 0
    rows, report = mapped()
    if args.command == "map":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for table, items in rows.items():
            with open(out / f"{table}.jsonl", "w", encoding="utf-8") as handle:
                handle.writelines(json.dumps(item) + "\n" for item in items)
    else:
        kusto = KustoClient(args.kusto_url)
        for table in TABLES:
            kusto.create_table(table, schema(table))
            kusto.ingest(table, rows[table])
        report["engine"] = kusto.version()
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
