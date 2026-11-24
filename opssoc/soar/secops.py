"""Google SecOps SOAR writer (ADR 002).

Google SecOps v1 has no method that creates a case: cases come from alerts
SecOps ingests (methods listed on ``projects.locations.instances.cases``,
fetched 2026-11-24). So this writer adds one comment to the case that already
holds the source alert, through ``caseComments.create``.

UNVERIFIED: the reference page for ``caseComments.create`` did not render
through the fetch tool. The URL below follows Google's standard REST pattern
for ``create`` on a child collection
(``POST https://{region}-chronicle.googleapis.com/v1/{parent}/caseComments``),
and the body field ``comment`` is a guess. Check both against the rendered
reference before the first live call.

Auth: a short-lived OAuth access token in SECOPS_ACCESS_TOKEN, the same
variable set detection_As_Code uses for SecOps.
"""

from __future__ import annotations

from collections.abc import Mapping

from opssoc.case import CaseReport
from opssoc.http import Request, Response
from opssoc.soar.base import SoarWriter, Steps, expect
from opssoc.soar.render import to_markdown


class NoCaseToWriteTo(ValueError):
    """The report names no SecOps case, and this API cannot create one."""


class SecOpsSoarWriter(SoarWriter):
    name = "secops"
    credential_env_vars = ("SECOPS_PROJECT", "SECOPS_REGION", "SECOPS_INSTANCE",
                           "SECOPS_ACCESS_TOKEN")
    test_credentials = {
        "SECOPS_PROJECT": "stub-project",
        "SECOPS_REGION": "us",
        "SECOPS_INSTANCE": "stub-instance",
        "SECOPS_ACCESS_TOKEN": "stub-token",
    }

    def base_url(self) -> str:
        region = self.env.get("SECOPS_REGION", "<SECOPS_REGION>")
        return f"https://{region}-chronicle.googleapis.com"

    @staticmethod
    def comments_path(creds: Mapping[str, str], case_id: str) -> str:
        return (f"/v1/projects/{creds['SECOPS_PROJECT']}/locations/{creds['SECOPS_REGION']}"
                f"/instances/{creds['SECOPS_INSTANCE']}/cases/{case_id}/caseComments")

    def steps(self, report: CaseReport, base_url: str, creds: Mapping[str, str]) -> Steps:
        if not report.secops_case_id:
            raise NoCaseToWriteTo(
                f"case {report.case_id}: no secops_case_id; the source alert must be "
                "ingested into Google SecOps first")
        headers = {"Authorization": f"Bearer {creds['SECOPS_ACCESS_TOKEN']}"}
        response = yield Request(
            "POST", base_url + self.comments_path(creds, report.secops_case_id), headers,
            {"comment": to_markdown(report)})
        expect(response, {200, 201}, "secops create case comment")
        self._reference = response.body.get("name")
        return "written"

    def placeholder_response(self, request: Request) -> Response:
        return Response(200, {})
