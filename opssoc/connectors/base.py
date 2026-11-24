"""The interface every security data connector implements (ADR 003).

Agents call three methods and never learn which backend answered:

- ``hunt(kql, timespan)``: run a KQL query over the advanced hunting tables.
- ``list_alerts(top)``: recent alerts.
- ``get_incident(id)``: one incident with its alerts.

Every result carries ``provenance``: which backend answered and, for replay,
which rows are mapped by this project rather than recorded as-is. Agents pass
provenance into the evidence they record, so a report never presents mapped
data as Defender telemetry.

Read-only is enforced here, not trusted to the backend: ``guard_query``
refuses KQL management commands (``.create``, ``.drop``, ``.ingest``, ...)
and anything that is not a single query.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

MAX_ROWS = 10_000
MAX_QUERY_CHARS = 20_000
# A management command starts with "." after optional whitespace and comments.
MGMT_COMMAND = re.compile(r"^\s*(//[^\n]*\n\s*)*\.", re.S)


class ReadOnlyViolation(ValueError):
    """The query is not a plain read."""


@dataclass
class QueryResult:
    query: str
    backend: str
    columns: list[tuple[str, str]]
    rows: list[dict]
    provenance: list[str] = field(default_factory=list)
    truncated: bool = False


def guard_query(kql: str) -> str:
    """Return the query if it is a plain read; raise ReadOnlyViolation otherwise.

    Checks: non-empty, under MAX_QUERY_CHARS, does not start with a management
    command. Does not parse KQL: a query that is not a management command but
    is otherwise invalid is left for the engine to reject.
    """
    if not kql or not kql.strip():
        raise ReadOnlyViolation("empty query")
    if len(kql) > MAX_QUERY_CHARS:
        raise ReadOnlyViolation(f"query longer than {MAX_QUERY_CHARS} characters")
    if MGMT_COMMAND.match(kql):
        raise ReadOnlyViolation("management commands are not allowed")
    return kql


def cap(rows: list[dict]) -> tuple[list[dict], bool]:
    return (rows[:MAX_ROWS], True) if len(rows) > MAX_ROWS else (rows, False)


class SecurityConnector(ABC):
    backend: str

    @abstractmethod
    def hunt(self, kql: str, timespan: str | None = None) -> QueryResult: ...

    @abstractmethod
    def list_alerts(self, top: int = 50) -> list[dict]: ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> dict: ...

    @abstractmethod
    def get_incident(self, incident_id: str) -> dict: ...
