"""Microsoft Graph security API connector: live Defender + Sentinel (ADR 003).

From the Graph v1.0 reference (fetched 2026-11-24):

- ``POST https://graph.microsoft.com/v1.0/security/runHuntingQuery`` with
  ``{"Query": kql, "Timespan": iso8601}`` (Timespan optional, default 30 days).
  Response: ``{"schema": [{"name", "type"}], "results": [{...}]}``.
  Permission: ThreatHunting.Read.All (application).
- ``GET .../security/alerts_v2`` and ``GET .../security/incidents/{id}``
  (``$expand=alerts``). Sentinel alerts and incidents appear here once the
  workspace is onboarded to the Defender portal.

Auth: OAuth 2.0 client credentials against
``https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` with scope
``https://graph.microsoft.com/.default``. Credentials only from environment
variables: GRAPH_TENANT_ID, GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET.

Not verified against a live tenant: every request here is built from the
reference pages; the response fixtures in tests are written from the same
pages, not recorded. The permissions for alerts_v2 / incidents
(SecurityAlert.Read.All, SecurityIncident.Read.All) are not checked yet.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from urllib.parse import quote, urlencode

from opssoc.connectors.base import QueryResult, SecurityConnector, cap, guard_query
from opssoc.http import MissingCredentials, Request, Transport

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
SCOPE = "https://graph.microsoft.com/.default"
# Without it, Graph returns "unknownFutureValue" for enum members added after the enum was
# published, e.g. newer serviceSource / detectionSource values (Graph alert docs).
PREFER = {"Prefer": "include-unknown-enum-members"}


class GraphError(RuntimeError):
    pass


class GraphSecurityConnector(SecurityConnector):
    backend = "graph (live Microsoft Graph security API)"
    credential_env_vars = ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET")

    def __init__(self, env: Mapping[str, str] | None = None,
                 transport: Transport | None = None) -> None:
        self.env = dict(os.environ if env is None else env)
        self.transport = transport or Transport()
        self._token: str | None = None
        self._token_expires = 0.0

    # -- requests (pure) ----------------------------------------------------

    def token_request(self) -> Request:
        return Request(
            "POST", f"{LOGIN}/{self.env.get('GRAPH_TENANT_ID', '<GRAPH_TENANT_ID>')}"
                    "/oauth2/v2.0/token",
            body={"grant_type": "client_credentials",
                  "client_id": self.env.get("GRAPH_CLIENT_ID", "<GRAPH_CLIENT_ID>"),
                  "client_secret": self.env.get("GRAPH_CLIENT_SECRET", "<GRAPH_CLIENT_SECRET>"),
                  "scope": SCOPE},
            form_encoded=True)

    def hunt_request(self, kql: str, timespan: str | None = None) -> Request:
        body = {"Query": guard_query(kql)}
        if timespan:
            body["Timespan"] = timespan
        return Request("POST", f"{GRAPH}/security/runHuntingQuery", self._auth(), body)

    def alerts_request(self, top: int = 50) -> Request:
        query = urlencode({"$top": top, "$orderby": "createdDateTime desc"})
        return Request("GET", f"{GRAPH}/security/alerts_v2?{query}", self._auth(PREFER))

    def incident_request(self, incident_id: str) -> Request:
        return Request("GET", f"{GRAPH}/security/incidents/{quote(incident_id, safe='')}"
                              "?$expand=alerts", self._auth(PREFER))

    # -- calls --------------------------------------------------------------

    def hunt(self, kql: str, timespan: str | None = None) -> QueryResult:
        body = self._send(self.hunt_request(kql, timespan))
        rows, truncated = cap(body.get("results", []))
        return QueryResult(
            query=kql, backend=self.backend,
            columns=[(c.get("name"), c.get("type")) for c in body.get("schema", [])],
            rows=rows, provenance=["live: Microsoft Graph runHuntingQuery"], truncated=truncated)

    def list_alerts(self, top: int = 50) -> list[dict]:
        return self._send(self.alerts_request(top)).get("value", [])

    def get_incident(self, incident_id: str) -> dict:
        return self._send(self.incident_request(incident_id))

    # -- auth ---------------------------------------------------------------

    def _auth(self, extra: dict | None = None) -> dict:
        return {"Authorization": f"Bearer {self._token or '<token>'}", **(extra or {})}

    def _ensure_token(self) -> None:
        missing = [k for k in self.credential_env_vars if not self.env.get(k)]
        if missing:
            raise MissingCredentials(f"graph: unset {', '.join(missing)}")
        if self._token and time.time() < self._token_expires - 60:
            return
        response = self.transport.send(self.token_request())
        token = response.body.get("access_token")
        if response.status != 200 or not token:
            raise GraphError(f"token request failed: HTTP {response.status}")
        self._token = token
        self._token_expires = time.time() + float(response.body.get("expires_in", 3600))

    def _send(self, request: Request) -> dict:
        self._ensure_token()
        request.headers = {**request.headers, **self._auth()}
        response = self.transport.send(request)
        if response.status != 200:
            error = response.body.get("error", {})
            message = error.get("message") if isinstance(error, dict) else error
            raise GraphError(f"{request.method} {request.url.split('?')[0]}: "
                             f"HTTP {response.status} {message or ''}".strip())
        return response.body
