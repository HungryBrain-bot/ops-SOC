"""Local stub SOAR server for test mode (ADR 002).

Implements the three endpoints the writers call, as read from the vendor
references, and checks what a real server would reject: method and path,
auth headers, required body fields. It answers with the documented status
codes and keeps everything it accepted in ``received`` so tests can assert
on it.

It is a stand-in for our reading of the docs, not for the products: a
request it accepts may still be refused by a real XSOAR or SecOps.

    with StubSoar() as stub:
        XsoarWriter(base_url=stub.base_url).write(report, "test")
"""

from __future__ import annotations

import itertools
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opssoc.soar.secops import SecOpsSoarWriter
from opssoc.soar.xsoar import ENTRY_PATH, INCIDENT_PATH, XsoarWriter

SECOPS_COMMENTS = re.compile(
    r"^/v1/projects/(?P<project>[^/]+)/locations/(?P<loc>[^/]+)/instances/(?P<inst>[^/]+)"
    r"/cases/(?P<case>[^/]+)/caseComments$")


class StubSoar:
    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 secops_cases: set[str] | None = None, block_marker: str = "BLOCK-ME") -> None:
        self.received: list[dict] = []
        self.incidents: dict[str, dict] = {}
        self.closed_investigations: set[str] = set()
        self.secops_cases = set(secops_cases or {"4242"})
        self.block_marker = block_marker  # incident names containing it get "200, not created"
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self.server = ThreadingHTTPServer((host, port), self._handler())
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> StubSoar:
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> StubSoar:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- request handling ---------------------------------------------------

    def _handler(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:  # keep test output quiet
                pass

            def do_POST(self) -> None:  # noqa: N802 (http.server API)
                length = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(length) or b"{}")
                except json.JSONDecodeError:
                    return self._reply(400, {"error": "body is not JSON"})
                status, payload = stub.handle(self.path, dict(self.headers), body)
                self._reply(status, payload)

            def _reply(self, status: int, payload: dict) -> None:
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        return Handler

    def handle(self, path: str, headers: dict, body: dict) -> tuple[int, dict]:
        headers = {k.lower(): v for k, v in headers.items()}
        with self._lock:
            if path == INCIDENT_PATH:
                return self._xsoar_incident(headers, body)
            if path == ENTRY_PATH:
                return self._xsoar_entry(headers, body)
            match = SECOPS_COMMENTS.match(path)
            if match:
                return self._secops_comment(headers, body, match)
            return 404, {"error": f"no such endpoint {path}"}

    def _xsoar_auth(self, headers: dict) -> bool:
        creds = XsoarWriter.test_credentials
        return (headers.get("authorization") == creds["XSOAR_API_KEY"]
                and headers.get("x-xdr-auth-id") == creds["XSOAR_API_KEY_ID"])

    def _xsoar_incident(self, headers: dict, body: dict) -> tuple[int, dict]:
        if not self._xsoar_auth(headers):
            return 401, {"error": "invalid API key or key ID"}
        if not isinstance(body.get("name"), str) or not body["name"]:
            return 400, {"error": "name is required"}
        severity = body.get("severity", 0)
        if not isinstance(severity, int | float) or not 0 <= severity <= 4:
            return 400, {"error": "severity must be 0-4"}
        if self.block_marker in body["name"]:
            return 200, {}
        incident_id = str(next(self._ids))
        incident = {**body, "id": incident_id}
        self.incidents[incident_id] = incident
        self.received.append({"endpoint": "xsoar.incident", "body": body})
        return 201, incident

    def _xsoar_entry(self, headers: dict, body: dict) -> tuple[int, dict]:
        if not self._xsoar_auth(headers):
            return 401, {"error": "invalid API key or key ID"}
        investigation = str(body.get("investigationId") or "")
        if investigation not in self.incidents:
            return 400, {"error": f"unknown investigationId {investigation!r}"}
        if investigation in self.closed_investigations:
            return 412, {"error": "investigation is closed"}
        if not isinstance(body.get("data"), str) or not body["data"]:
            return 400, {"error": "data is required"}
        self.received.append({"endpoint": "xsoar.entry", "body": body})
        return 200, {"id": f"{investigation}@{next(self._ids)}", "investigationId": investigation}

    def _secops_comment(self, headers: dict, body: dict, match: re.Match) -> tuple[int, dict]:
        token = SecOpsSoarWriter.test_credentials["SECOPS_ACCESS_TOKEN"]
        if headers.get("authorization") != f"Bearer {token}":
            return 401, {"error": "invalid bearer token"}
        if match["case"] not in self.secops_cases:
            return 404, {"error": f"case {match['case']} not found"}
        if not isinstance(body.get("comment"), str) or not body["comment"]:
            return 400, {"error": "comment is required"}
        name = (f"projects/{match['project']}/locations/{match['loc']}/instances/{match['inst']}"
                f"/cases/{match['case']}/caseComments/{next(self._ids)}")
        self.received.append({"endpoint": "secops.caseComment", "body": body})
        return 200, {"name": name, "comment": body["comment"]}
