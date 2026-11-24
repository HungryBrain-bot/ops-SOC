"""Cortex XSOAR 8 writer (ADR 002).

Two calls, from the Cortex XSOAR 8 API reference (fetched 2026-11-24):

1. ``POST {base}/xsoar/public/v1/incident`` creates the incident. ``name`` is
   required. 201 = created (body is the incident, ``id`` used below); 200 =
   accepted but no incident created, usually a pre-processing rule.
2. ``POST {base}/xsoar/public/v1/entry`` adds the report as a Markdown War
   Room entry: ``investigationId`` + ``data``. 412 = investigation closed.

Auth headers: ``Authorization: <API key>`` and ``x-xdr-auth-id: <key ID>``.
Base URL: ``https://api-<fqdn>`` (XSOAR_API_URL).

Assumed, not verified against a live tenant: the incident ID returned by
step 1 is the investigation ID step 2 needs (``createInvestigation: true``
starts the investigation with the incident).
"""

from __future__ import annotations

from collections.abc import Mapping

from opssoc.case import CaseReport, Severity
from opssoc.http import Request, Response
from opssoc.soar.base import SoarWriter, Steps, expect
from opssoc.soar.render import to_markdown

# XSOAR severity scale: 0 unknown, 0.5 informational, 1 low, 2 medium, 3 high, 4 critical.
SEVERITY = {
    Severity.INFORMATIONAL: 0.5,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
INCIDENT_PATH = "/xsoar/public/v1/incident"
ENTRY_PATH = "/xsoar/public/v1/entry"
CASE_LABEL = "ops-soc-case"


class XsoarWriter(SoarWriter):
    name = "xsoar"
    credential_env_vars = ("XSOAR_API_URL", "XSOAR_API_KEY", "XSOAR_API_KEY_ID")
    test_credentials = {
        "XSOAR_API_KEY": "stub-api-key",
        "XSOAR_API_KEY_ID": "1",
    }

    def base_url(self) -> str:
        return self.env.get("XSOAR_API_URL") or "https://api-<XSOAR_FQDN>"

    def incident_body(self, report: CaseReport) -> dict:
        body = {
            "name": f"[ops-SOC] {report.title}"[:250],
            "severity": SEVERITY[report.severity],
            "details": report.summary,
            "labels": [
                {"type": CASE_LABEL, "value": report.case_id},
                {"type": "ops-soc-source-alert", "value": report.source_alert_id},
                {"type": "ops-soc-verdict", "value": report.verdict.value},
            ],
            "createInvestigation": True,
        }
        incident_type = self.env.get("XSOAR_INCIDENT_TYPE")
        if incident_type:
            body["type"] = incident_type
        return body

    def steps(self, report: CaseReport, base_url: str, creds: Mapping[str, str]) -> Steps:
        headers = {
            "Authorization": creds["XSOAR_API_KEY"],
            "x-xdr-auth-id": creds["XSOAR_API_KEY_ID"],
        }
        created = yield Request("POST", base_url + INCIDENT_PATH, headers,
                                self.incident_body(report))
        expect(created, {200, 201}, "xsoar create incident")
        if created.status == 200:
            return "blocked-by-preprocessing"
        incident_id = str(created.body.get("id") or "")
        if not incident_id:
            raise ValueError("xsoar create incident: 201 without an incident id")
        self._reference = incident_id
        entry = yield Request("POST", base_url + ENTRY_PATH, headers,
                              {"investigationId": incident_id, "data": to_markdown(report)})
        if entry.status == 412:
            return "incident-created-entry-refused-investigation-closed"
        expect(entry, {200, 201}, "xsoar add entry")
        return "written"

    def placeholder_response(self, request: Request) -> Response:
        if request.url.endswith(INCIDENT_PATH):
            return Response(201, {"id": "<incident id from step 1>"})
        return Response(200, {})
