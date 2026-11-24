"""python -m opssoc.replay fetch | map | load | seed

    fetch [--only NAME]   download the pinned OTRF datasets into data/datasets/, verify SHA-256
    map --out DIR         map every fetched dataset to Defender rows (JSONL per table), offline
    load [--kusto-url]    create the Device* tables (and SecurityEvent / Event when a
                          detection_As_Code checkout is set in OPSSOC_DAC_PATH) in the Kusto
                          emulator and ingest every dataset
    seed [--kusto-url] [--eval-rules]
                          run the detection_As_Code rules (and with --eval-rules the eval
                          rules, ADR 007) over each dataset, write data/replay/alerts.json,
                          then load all datasets (ADR 004)
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

from opssoc.replay import dac_bridge
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


def dataset_events(name: str) -> list[dict]:
    paths = sorted((DATA / name).glob("*.json"))
    if not paths:
        raise SystemExit(f"{name}: not fetched; run `python -m opssoc.replay fetch`")
    return [event for path in paths for event in read_events(path)]


def dataset_rows(name: str, with_sentinel: bool) -> tuple[dict[str, list[dict]], dict]:
    """All replay tables' rows for one dataset, and a count report."""
    events = dataset_events(name)
    result = SysmonToDefender().map(events)
    rows = dict(result.rows)
    report = {"rows": result.counts(), "skipped_by_defender_mapping": sum(result.skipped.values())}
    if with_sentinel:
        sentinel = dac_bridge.sentinel_rows(events)
        rows.update(sentinel)
        report["rows"].update({t: len(r) for t, r in sentinel.items()})
    return rows, report


def mapped(with_sentinel: bool = False) -> tuple[dict[str, list[dict]], dict]:
    rows: dict[str, list[dict]] = {}
    report = {}
    for name in PINS["datasets"]:
        one, report[name] = dataset_rows(name, with_sentinel)
        for table, items in one.items():
            rows.setdefault(table, []).extend(items)
    return rows, report


def table_schemas(with_sentinel: bool) -> dict[str, dict[str, str]]:
    schemas = {t: schema(t) for t in TABLES}
    if with_sentinel:
        schemas.update({t: dac_bridge.schema(t) for t in dac_bridge.SENTINEL_TABLES})
    return schemas


def load(kusto: KustoClient, rows: dict[str, list[dict]], schemas: dict[str, dict]) -> None:
    for table, columns in schemas.items():
        kusto.create_table(table, columns)
        kusto.ingest(table, rows.get(table, []))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m opssoc.replay")
    sub = parser.add_subparsers(dest="command", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--only")
    m = sub.add_parser("map")
    m.add_argument("--out", default="build/replay")
    lo = sub.add_parser("load")
    lo.add_argument("--kusto-url")
    se = sub.add_parser("seed")
    se.add_argument("--kusto-url")
    se.add_argument("--out", default="data/replay/alerts.json")
    se.add_argument("--eval-rules", action="store_true",
                    help="also run the eval rules in opssoc/eval/rules.json (ADR 007)")
    args = parser.parse_args(argv)

    if args.command == "fetch":
        fetch(args.only)
        return 0
    if args.command == "seed":
        from opssoc.replay.seed import PROBE_KIND, seed

        extra = []
        if args.eval_rules:
            from opssoc.eval.cases import load_eval_rules

            extra = [(rule, PROBE_KIND) for rule in load_eval_rules()]
        print(json.dumps(seed(KustoClient(args.kusto_url), Path(args.out), extra_rules=extra),
                         indent=2))
        return 0
    with_sentinel = args.command == "load" and dac_bridge.available()
    rows, report = mapped(with_sentinel)
    if args.command == "map":
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for table, items in rows.items():
            with open(out / f"{table}.jsonl", "w", encoding="utf-8") as handle:
                handle.writelines(json.dumps(item) + "\n" for item in items)
    else:
        kusto = KustoClient(args.kusto_url)
        load(kusto, rows, table_schemas(with_sentinel))
        report["engine"] = kusto.version()
        report["sentinel_tables"] = with_sentinel
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
