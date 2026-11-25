"""Telemetry coverage probe (ADR 009 point 2).

Before the model's first turn the code asks, for every table the factor set reads:
does the table exist, does it have the columns the probe and the factors need, and does
it hold rows for the alert's host in a window around the alert? The answer is one
evidence record of kind ``coverage``. A factor marked ``unknown_no_telemetry`` must cite
a coverage record that shows a gap in one of the factor's tables.

States per table:
- ``missing_table``: the table cannot be read (schema query failed);
- ``missing_column``: the host, time or a key column is not in the schema;
- ``not_probed``: no usable host name or alert time, so rows were not counted;
- ``no_rows_for_host``: no rows for the host in the window;
- ``stops_before_alert``: rows in the window, none from the alert time onwards, and the
  last one more than ``stale_minutes`` before the alert (the source went quiet before
  the alert). Rows that stop within ``stale_minutes`` of the alert count as present: a
  recording or an ingestion delay can end there;
- ``key_column_empty``: rows exist, but a key column is empty in every one of them;
- ``present``: rows before and after the alert time, every key column filled somewhere.

What it does not test: event loss inside a window that has rows, a sensor that drops one
event type within a table, data that is late rather than absent, tables the factor set
does not list, and whether a row says what a factor needs.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from opssoc.agents.investigation.factors import FactorSet
from opssoc.connectors.base import SecurityConnector

PRESENT = "present"
GAP_STATES = ("missing_table", "missing_column", "not_probed", "no_rows_for_host",
              "stops_before_alert", "key_column_empty")
HOST_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
NAME = r"([A-Za-z_][A-Za-z0-9_]*)"
# Where a KQL query names a table: its first word, `union` lists, `join` operands.
TABLE_REFS = (re.compile(r"^\s*" + NAME + r"\s*(\||$)"),
              re.compile(r"\bunion\s+(?:kind\s*=\s*\w+\s+)?([A-Za-z0-9_,\s]+?)(?=\||$)", re.S),
              re.compile(r"\bjoin\s+(?:kind\s*=\s*\w+\s+)?\(?\s*" + NAME))
KQL_WORDS = {"let", "print", "datatable", "range", "union", "search", "find", "kind",
             "withsource", "isfuzzy"}


def alert_host(alert: dict) -> str | None:
    """The alert's device name, only if it is a plain host name. Alert text is attacker
    influenced, so anything that could break out of a KQL string is refused."""
    for e in alert.get("evidence") or []:
        name = e.get("deviceDnsName") or e.get("hostName")
        if name:
            return name if HOST_OK.match(name) else None
    return None


def alert_time(alert: dict) -> datetime | None:
    value = alert.get("firstActivityDateTime") or alert.get("createdDateTime")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def probe(connector: SecurityConnector, fset: FactorSet, alert: dict,
          before_hours: float = 24, after_hours: float = 1,
          stale_minutes: float = 15) -> list[dict]:
    """One row per table of the factor set, in the set's order."""
    host, when = alert_host(alert), alert_time(alert)
    rows = []
    for table, spec in fset.tables.items():
        row = {"table": table, "host": host, "factors": [f.id for f in fset.factors
                                                           if table in f.tables]}
        rows.append(row)
        try:
            schema = connector.hunt(f"{table} | getschema | project ColumnName")
        except (ValueError, RuntimeError) as exc:
            row.update(state="missing_table", detail=str(exc)[:300])
            continue
        columns = {r.get("ColumnName") for r in schema.rows}
        hcol, tcol, keys = spec["host_column"], spec["time_column"], spec["key_columns"]
        missing = [c for c in [hcol, tcol, *keys] if c not in columns]
        if missing:
            row.update(state="missing_column", detail=f"not in schema: {missing}")
            continue
        if host is None or when is None:
            row.update(state="not_probed",
                       detail="no usable host name or alert time in the alert")
            continue
        start, end = when - timedelta(hours=before_hours), when + timedelta(hours=after_hours)
        empties = ", ".join(f"empty_{k} = countif(isempty(tostring({k})))" for k in keys)
        kql = (f"{table} | where {hcol} =~ '{host}' | where {tcol} between "
               f"(datetime({_iso(start)}) .. datetime({_iso(end)})) | summarize "
               f"rows = count(), before = countif({tcol} < datetime({_iso(when)})), "
               f"first_seen = min({tcol}), last_seen = max({tcol}), {empties}")
        row["window"] = [_iso(start), _iso(end)]
        try:
            result = connector.hunt(kql)
        except (ValueError, RuntimeError) as exc:
            row.update(state="missing_column", detail=f"count failed: {str(exc)[:300]}")
            continue
        r = result.rows[0] if result.rows else {}
        total, before = int(r.get("rows") or 0), int(r.get("before") or 0)
        row.update(rows=total, rows_before=before, rows_from_alert=total - before,
                   first_seen=r.get("first_seen"), last_seen=r.get("last_seen"))
        empty = [k for k in keys if total and int(r.get(f"empty_{k}") or 0) == total]
        if total == 0:
            row["state"] = "no_rows_for_host"
        elif total == before and (_parse(r.get("last_seen")) or when) < when - timedelta(
                minutes=stale_minutes):
            row.update(state="stops_before_alert",
                       detail=f"last row more than {stale_minutes:g} minutes before the alert")
        elif empty:
            row.update(state="key_column_empty", detail=f"empty in every row: {empty}")
        else:
            row["state"] = PRESENT
    return rows


def table_refs(kql: str) -> list[str]:
    """Names a query uses as tables: its first word, `union` lists and `join` operands.
    A heuristic, not a KQL parser: `let` statements, functions and sub-queries are not
    followed."""
    names: list[str] = []
    m = TABLE_REFS[0].match(kql)
    if m:
        names.append(m.group(1))
    for m in TABLE_REFS[1].finditer(kql):
        names += [n.strip() for n in m.group(1).split(",")]
    names += [m.group(1) for m in TABLE_REFS[2].finditer(kql)]
    out = []
    for n in names:
        if re.fullmatch(NAME, n) and n.lower() not in KQL_WORDS and n not in out:
            out.append(n)
    return out[:5]


def unreadable_tables(connector: SecurityConnector, kql: str) -> list[str]:
    """After a query failed: which of the tables it names cannot be read (schema query
    fails). The engine's error text is not used. The emulator answers a missing table
    with a bare HTTP 400 that does not name it, and Graph's wording is not verified."""
    missing = []
    for name in table_refs(kql):
        try:
            connector.hunt(f"{name} | getschema | project ColumnName")
        except (ValueError, RuntimeError):
            missing.append(name)
    return missing


def gaps(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r.get("state") != PRESENT]
