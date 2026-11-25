"""Client for the Azure Data Explorer emulator (Kustainer) used as the replay engine.

Kustainer runs the ADX engine, not Log Analytics or Defender advanced hunting.
They share KQL, but a function that exists only in Log Analytics / Defender
fails here, visibly. Same approach and image as detection_As_Code
(docs/components/engine-tests.md there).

Endpoints (Kusto REST API, plain HTTP, no auth on the local emulator):
``POST /v1/rest/mgmt`` for management commands, ``POST /v2/rest/query`` for
queries, body ``{"db": ..., "csl": ...}``.
"""

from __future__ import annotations

import json
import os

from opssoc.http import Request, Transport

INGEST_CHUNK = 2000


class KustoError(RuntimeError):
    pass


class KustoClient:
    def __init__(self, url: str | None = None, database: str = "NetDefaultDB",
                 transport: Transport | None = None) -> None:
        self.url = (url or os.environ.get("OPSSOC_KUSTO_URL", "http://localhost:8080")).rstrip("/")
        self.database = database
        self.transport = transport or Transport(timeout=120)

    def _call(self, path: str, csl: str):
        response = self.transport.send(
            Request("POST", self.url + path, body={"db": self.database, "csl": csl}))
        if response.status != 200:
            raise KustoError(f"{path}: HTTP {response.status} {json.dumps(response.body)[:500]}")
        return response.body.get("data", response.body)

    def mgmt(self, csl: str):
        return self._call("/v1/rest/mgmt", csl)

    def query(self, kql: str) -> tuple[list[tuple[str, str]], list[dict]]:
        frames = self._call("/v2/rest/query", kql)
        for frame in frames:
            if frame.get("FrameType") == "DataSetCompletion" and frame.get("HasErrors"):
                raise KustoError(json.dumps(frame.get("OneApiErrors"))[:1000])
        for frame in frames:
            if frame.get("FrameType") == "DataTable" and frame.get("TableKind") == "PrimaryResult":
                columns = [(c["ColumnName"], c["ColumnType"]) for c in frame["Columns"]]
                names = [name for name, _ in columns]
                return columns, [dict(zip(names, row, strict=True)) for row in frame["Rows"]]
        return [], []

    def create_table(self, table: str, columns: dict[str, str]) -> None:
        cols = ", ".join(f"['{name}']:{kind}" for name, kind in columns.items())
        self.mgmt(f".drop table ['{table}'] ifexists")
        self.mgmt(f".create table ['{table}'] ({cols})")

    def ingest(self, table: str, rows: list[dict]) -> None:
        for start in range(0, len(rows), INGEST_CHUNK):
            lines = "\n".join(json.dumps(row) for row in rows[start:start + INGEST_CHUNK])
            self.mgmt(f".ingest inline into table ['{table}'] with (format='multijson') <|\n"
                      f"{lines}")

    def version(self) -> str:
        rows = self.mgmt(".show version")["Tables"][0]["Rows"]
        return f"Kustainer (ADX engine) {rows[0][0]}"
