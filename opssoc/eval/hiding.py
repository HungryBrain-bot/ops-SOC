"""A connector wrapper that hides tables, for eval cases on missing telemetry (ADR 009).

Any query that names a hidden table fails the way the Kusto emulator fails on a table
that does not exist: a bare HTTP 400 that does not name the table. The agent cannot tell
a hidden table from a missing one, which is the point: the case tests what the agent does
when telemetry is not there. Eval only; never used outside `opssoc.eval`.
"""

from __future__ import annotations

import re

from opssoc.connectors.base import QueryResult, SecurityConnector

EMULATOR_400 = ("/v2/rest/query: HTTP 400 General_BadRequest: Request is invalid and cannot "
                "be executed.")


class HiddenTablesConnector(SecurityConnector):
    def __init__(self, inner: SecurityConnector, hidden: list[str] | tuple[str, ...]) -> None:
        self.inner = inner
        self.hidden = tuple(hidden)
        self.backend = inner.backend
        self._names = re.compile(r"\b(" + "|".join(map(re.escape, self.hidden)) + r")\b") \
            if self.hidden else None

    def hunt(self, kql: str, timespan: str | None = None) -> QueryResult:
        if self._names and self._names.search(kql):
            raise RuntimeError(EMULATOR_400)
        return self.inner.hunt(kql, timespan)

    def list_alerts(self, top: int = 50) -> list[dict]:
        return self.inner.list_alerts(top)

    def get_alert(self, alert_id: str) -> dict:
        return self.inner.get_alert(alert_id)

    def get_incident(self, incident_id: str) -> dict:
        return self.inner.get_incident(incident_id)
