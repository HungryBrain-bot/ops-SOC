"""Replay connector: the same interface as Graph, answered from recorded data (ADR 003).

Hunting queries run in the Kusto emulator over OTRF data loaded by
``python -m opssoc.replay load`` or ``seed``. Results that read a Device* table
are labelled as mapped by this project (opssoc/replay/sysmon_to_defender.py);
results that read SecurityEvent or Event as mapped by detection_As_Code.

Alerts and incidents come from ``data/replay/alerts.json``, written by
``python -m opssoc.replay seed`` (detection_As_Code rules run over each
dataset, ADR 004). Without that file there are no replay alerts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from opssoc.connectors.base import QueryResult, SecurityConnector, cap, guard_query
from opssoc.replay import dac_bridge
from opssoc.replay.kusto import KustoClient
from opssoc.replay.sysmon_to_defender import MAPPING_LABEL, TABLES

DEVICE_TABLE = re.compile(r"\b(" + "|".join(TABLES) + r")\b")
SENTINEL_TABLE = re.compile(r"\b(" + "|".join(dac_bridge.SENTINEL_TABLES) + r")\b")


class ReplayConnector(SecurityConnector):
    backend = "replay (Kusto emulator, ADX engine; recorded OTRF data, not a tenant)"

    def __init__(self, kusto: KustoClient | None = None,
                 alerts_path: Path | str = Path("data/replay/alerts.json")) -> None:
        self.kusto = kusto or KustoClient()
        self.alerts_path = Path(alerts_path)

    def hunt(self, kql: str, timespan: str | None = None) -> QueryResult:
        guard_query(kql)
        provenance = [self.backend]
        if timespan:
            provenance.append(f"timespan {timespan} ignored: replay data is from the "
                              "recording dates")
        tables = sorted(set(DEVICE_TABLE.findall(kql)))
        if tables:
            provenance.append(f"{', '.join(tables)}: {MAPPING_LABEL}")
        sentinel = sorted(set(SENTINEL_TABLE.findall(kql)))
        if sentinel:
            provenance.append(f"{', '.join(sentinel)}: {dac_bridge.MAPPING_LABEL}")
        columns, rows = self.kusto.query(kql)
        rows, truncated = cap(rows)
        return QueryResult(kql, self.backend, columns, rows, provenance, truncated)

    def _alerts(self) -> list[dict]:
        if not self.alerts_path.is_file():
            return []
        return json.loads(self.alerts_path.read_text(encoding="utf-8")).get("alerts", [])

    def list_alerts(self, top: int = 50) -> list[dict]:
        alerts = sorted(self._alerts(), key=lambda a: a.get("createdDateTime", ""), reverse=True)
        return alerts[:top]

    def get_alert(self, alert_id: str) -> dict:
        for alert in self._alerts():
            if alert.get("id") == alert_id:
                return alert
        raise KeyError(f"no replay alert {alert_id}")

    def get_incident(self, incident_id: str) -> dict:
        alerts = [a for a in self._alerts() if a.get("incidentId") == incident_id]
        if not alerts:
            raise KeyError(f"no replay incident {incident_id}")
        return {"id": incident_id, "alerts": alerts}
