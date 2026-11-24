"""Use a detection_As_Code (DaC) checkout as a library (ADR 001 point 2, ADR 004).

ops-SOC does not copy DaC's rules or its OTRF -> Sentinel mapping. It imports
them from a DaC checkout named by OPSSOC_DAC_PATH (CI checks out a pinned
commit, see DAC_COMMIT). What is used:

- ``harness.mapping.to_sentinel``: OTRF event -> Sentinel ``SecurityEvent``
  (Security channel) or ``Event`` (Sysmon channel) row. DaC's mapping; its
  docstring lists what it approximates.
- ``dac.rules.load_reference_schema``: those tables' columns and types.
- ``harness.engines.coerce`` / ``TYPED_COLUMNS``: value coercion on ingest.
- ``dac.rules.load_rules``: every rule and its Sentinel query.

DaC needs PyYAML (``pip install -e .[seed]``).
"""

from __future__ import annotations

import os
import sys
from functools import cache
from pathlib import Path

# The detection_As_Code commit CI checks out. Bump deliberately (ADR 001, Consequences).
DAC_COMMIT = "51080aa733242325215be64f75a83926c4ac35ef"
SENTINEL_TABLES = ("SecurityEvent", "Event")
MAPPING_LABEL = ("mapped by detection_As_Code harness from OTRF (NXLog JSON) to the Sentinel "
                 "table shape; event content recorded")


class DacUnavailable(RuntimeError):
    pass


@cache
def dac_path() -> Path:
    raw = os.environ.get("OPSSOC_DAC_PATH")
    if not raw:
        raise DacUnavailable("set OPSSOC_DAC_PATH to a detection_As_Code checkout")
    path = Path(raw).resolve()
    if not (path / "dac" / "rules.py").is_file() or not (path / "harness" / "mapping.py").is_file():
        raise DacUnavailable(f"{path} is not a detection_As_Code checkout")
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    return path


def available() -> bool:
    try:
        dac_path()
    except DacUnavailable:
        return False
    return True


def _modules():
    dac_path()
    from dac import rules  # noqa: PLC0415 (imported from the checkout)
    from harness import engines, mapping  # noqa: PLC0415

    return rules, engines, mapping


def schema(table: str) -> dict[str, str]:
    rules, engines, _ = _modules()
    ref = rules.load_reference_schema("sentinel", table)
    if ref is None:
        raise DacUnavailable(f"no DaC reference schema for {table}")
    fields = ref["fields"]
    return ref.get("types") or {f: engines.TYPED_COLUMNS.get(f, "string") for f in fields}


def sentinel_rows(events: list[dict]) -> dict[str, list[dict]]:
    """SecurityEvent / Event rows for the events DaC maps to those tables; columns not in the
    schema are dropped and values coerced as DaC's engine does."""
    _, engines, mapping = _modules()
    out: dict[str, list[dict]] = {t: [] for t in SENTINEL_TABLES}
    types = {t: schema(t) for t in SENTINEL_TABLES}
    for event in events:
        table, row = mapping.to_sentinel(event)
        if table in out:
            out[table].append({k: engines.coerce(v, types[table][k]) for k, v in row.items()
                               if k in types[table]})
    return out


def load_rules():
    rules, _, _ = _modules()
    return rules.load_rules()
