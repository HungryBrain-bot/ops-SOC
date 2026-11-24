import json
from pathlib import Path

import pytest

from opssoc.case import CaseReport
from opssoc.http import MissingCredentials, Response
from opssoc.soar import SecOpsSoarWriter, XsoarWriter
from opssoc.soar.__main__ import main
from opssoc.soar.base import AlreadyWritten, WriteError
from opssoc.soar.secops import NoCaseToWriteTo
from opssoc.soar.stub_server import StubSoar

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "case_report.json"
XSOAR_ENV = {"XSOAR_API_URL": "https://api-x.example", "XSOAR_API_KEY": "k",
             "XSOAR_API_KEY_ID": "7"}
SECOPS_ENV = {"SECOPS_PROJECT": "p", "SECOPS_REGION": "eu", "SECOPS_INSTANCE": "i",
              "SECOPS_ACCESS_TOKEN": "t"}


@pytest.fixture
def report() -> CaseReport:
    return CaseReport.load(EXAMPLE)


@pytest.fixture
def stub():
    with StubSoar() as server:
        yield server


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []

    def send(self, request):
        self.sent.append(request)
        return self.responses.pop(0)


# -- dry-run -------------------------------------------------------------------


def test_xsoar_dry_run_writes_redacted_requests(report, tmp_path):
    result = XsoarWriter(env=XSOAR_ENV).write(report, "dry-run", out_dir=tmp_path)
    saved = json.loads((tmp_path / "xsoar" / "CASE-EXAMPLE-0001.json").read_text())
    assert result.outcome == "dry-run" and saved == result.requests
    assert [r["url"] for r in saved] == ["https://api-x.example/xsoar/public/v1/incident",
                                         "https://api-x.example/xsoar/public/v1/entry"]
    assert saved[0]["headers"] == {"Authorization": "<redacted>", "x-xdr-auth-id": "<redacted>"}
    assert saved[0]["body"]["severity"] == 3
    assert {"type": "ops-soc-case", "value": "CASE-EXAMPLE-0001"} in saved[0]["body"]["labels"]
    assert saved[1]["body"]["investigationId"] == "<incident id from step 1>"
    assert "EV-1" in saved[1]["body"]["data"]


def test_dry_run_needs_no_credentials(report, tmp_path):
    result = SecOpsSoarWriter(env={}).write(report, "dry-run", out_dir=tmp_path)
    assert result.requests[0]["url"].startswith("https://<SECOPS_REGION>-chronicle")


def test_secops_dry_run_path(report, tmp_path):
    result = SecOpsSoarWriter(env=SECOPS_ENV).write(report, "dry-run", out_dir=tmp_path)
    assert result.requests[0]["url"] == (
        "https://eu-chronicle.googleapis.com/v1/projects/p/locations/eu/instances/i"
        "/cases/4242/caseComments")
    assert result.requests[0]["headers"]["Authorization"] == "<redacted>"


# -- test mode: real HTTP to the stub ---------------------------------------------


def test_xsoar_test_push_end_to_end(report, stub, tmp_path):
    result = XsoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)
    assert result.outcome == "written" and result.statuses == [201, 200]
    assert [r["endpoint"] for r in stub.received] == ["xsoar.incident", "xsoar.entry"]
    assert stub.received[1]["body"]["investigationId"] == result.reference
    assert stub.received[1]["body"]["data"].startswith("## ops-SOC investigation CASE-EXAMPLE")


def test_secops_test_push_end_to_end(report, stub, tmp_path):
    result = SecOpsSoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)
    assert result.outcome == "written" and result.statuses == [200]
    assert result.reference.endswith("/cases/4242/caseComments/1")


def test_xsoar_preprocessing_block_is_reported(report, stub, tmp_path):
    report.title = "BLOCK-ME duplicate"
    result = XsoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)
    assert result.outcome == "blocked-by-preprocessing" and result.statuses == [200]


def test_xsoar_closed_investigation(report, stub, tmp_path):
    stub.closed_investigations.add("1")
    result = XsoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)
    assert result.outcome == "incident-created-entry-refused-investigation-closed"


def test_secops_unknown_case_is_an_error(report, stub, tmp_path):
    report.secops_case_id = "999"
    with pytest.raises(WriteError, match="HTTP 404"):
        SecOpsSoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)


def test_secops_without_case_id_stops(report, stub, tmp_path):
    report.secops_case_id = None
    with pytest.raises(NoCaseToWriteTo):
        SecOpsSoarWriter(base_url=stub.base_url).write(report, "test", out_dir=tmp_path)


def test_stub_rejects_bad_auth(stub):
    status, _ = stub.handle("/xsoar/public/v1/incident", {"Authorization": "wrong"},
                            {"name": "x"})
    assert status == 401


def test_stub_rejects_missing_name(stub):
    headers = {"Authorization": "stub-api-key", "x-xdr-auth-id": "1"}
    assert stub.handle("/xsoar/public/v1/incident", headers, {})[0] == 400


def test_test_mode_refuses_remote_url(report, tmp_path):
    with pytest.raises(ValueError, match="loopback"):
        XsoarWriter(base_url="https://api-real.example").write(report, "test", out_dir=tmp_path)


# -- live mode ------------------------------------------------------------------


def test_live_needs_every_credential(report, tmp_path):
    with pytest.raises(MissingCredentials, match="XSOAR_API_KEY_ID"):
        XsoarWriter(env={"XSOAR_API_URL": "u", "XSOAR_API_KEY": "k"}).write(
            report, "live", out_dir=tmp_path)


def test_live_sends_real_credentials_and_refuses_a_second_write(report, tmp_path):
    transport = FakeTransport([Response(201, {"id": "55"}), Response(200, {})])
    result = XsoarWriter(env=XSOAR_ENV).write(report, "live", transport=transport,
                                              out_dir=tmp_path)
    assert result.outcome == "written" and result.reference == "55"
    assert transport.sent[0].headers == {"Authorization": "k", "x-xdr-auth-id": "7"}
    assert "CASE-EXAMPLE-0001" in json.loads((tmp_path / "ledger.json").read_text())["xsoar"]
    with pytest.raises(AlreadyWritten):
        XsoarWriter(env=XSOAR_ENV).write(report, "live", transport=FakeTransport([]),
                                         out_dir=tmp_path)


def test_live_error_status_raises_and_is_not_ledgered(report, tmp_path):
    transport = FakeTransport([Response(500, {"error": "boom"})])
    with pytest.raises(WriteError, match="HTTP 500"):
        XsoarWriter(env=XSOAR_ENV).write(report, "live", transport=transport, out_dir=tmp_path)
    assert not (tmp_path / "ledger.json").exists()


# -- report and CLI -------------------------------------------------------------


def test_case_id_cannot_escape_build_dir():
    with pytest.raises(ValueError):
        CaseReport(case_id="../x", title="t", verdict="benign", severity="low", summary="s",
                   source_alert_id="a")


def test_cli_test_mode(capsys, tmp_path):
    assert main(["write", "--target", "xsoar", "--report", str(EXAMPLE), "--mode", "test",
                 "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert '"outcome": "written"' in out and "xsoar.incident, xsoar.entry" in out
