import json

import pytest

from opssoc.connectors import GraphSecurityConnector, ReadOnlyViolation, ReplayConnector
from opssoc.connectors.base import MAX_ROWS, guard_query
from opssoc.connectors.graph import GraphError
from opssoc.http import MissingCredentials, Response
from opssoc.replay.kusto import KustoClient

ENV = {"GRAPH_TENANT_ID": "tid", "GRAPH_CLIENT_ID": "cid", "GRAPH_CLIENT_SECRET": "sec"}
# Shape from the Graph runHuntingQuery reference example (written from docs, not recorded).
HUNT_BODY = {"schema": [{"name": "Timestamp", "type": "DateTime"},
                        {"name": "FileName", "type": "String"}],
             "results": [{"Timestamp": "2024-03-26T09:39:50.7688641Z", "FileName": "cmd.exe"}]}


class FakeTransport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []

    def send(self, request):
        self.sent.append(request)
        return self.responses.pop(0)


def token():
    return Response(200, {"access_token": "tok", "expires_in": 3600})


# -- read-only guard ------------------------------------------------------------


@pytest.mark.parametrize("kql", [".drop table X", "  .ingest inline into table X <| a",
                                 "// comment\n.create table T (a:string)", "", "   "])
def test_guard_refuses_management_and_empty(kql):
    with pytest.raises(ReadOnlyViolation):
        guard_query(kql)


def test_guard_allows_plain_queries():
    assert guard_query("DeviceProcessEvents | take 1")


# -- Graph ----------------------------------------------------------------------


def test_graph_hunt_request_and_result():
    transport = FakeTransport(token(), Response(200, HUNT_BODY))
    result = GraphSecurityConnector(ENV, transport).hunt("DeviceProcessEvents | take 1", "P7D")
    token_req, hunt_req = transport.sent
    assert token_req.url == "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
    assert token_req.form_encoded and token_req.body["scope"] == "https://graph.microsoft.com/.default"
    assert token_req.redacted()["body"]["client_secret"] == "<redacted>"
    assert hunt_req.url == "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
    assert hunt_req.body == {"Query": "DeviceProcessEvents | take 1", "Timespan": "P7D"}
    assert hunt_req.headers == {"Authorization": "Bearer tok"}
    assert result.columns == [("Timestamp", "DateTime"), ("FileName", "String")]
    assert result.rows[0]["FileName"] == "cmd.exe"
    assert result.provenance == ["live: Microsoft Graph runHuntingQuery"]


def test_graph_token_is_reused():
    transport = FakeTransport(token(), Response(200, {"value": []}), Response(200, {"value": []}))
    connector = GraphSecurityConnector(ENV, transport)
    connector.list_alerts()
    connector.list_alerts(5)
    assert len(transport.sent) == 3
    assert transport.sent[2].url.startswith(
        "https://graph.microsoft.com/v1.0/security/alerts_v2?%24top=5")


def test_graph_incident_request_escapes_id():
    transport = FakeTransport(token(), Response(200, {"id": "1/2"}))
    GraphSecurityConnector(ENV, transport).get_incident("1/2")
    assert transport.sent[1].url == (
        "https://graph.microsoft.com/v1.0/security/incidents/1%2F2?$expand=alerts")


def test_graph_refuses_management_before_any_call():
    transport = FakeTransport()
    with pytest.raises(ReadOnlyViolation):
        GraphSecurityConnector(ENV, transport).hunt(".drop table DeviceProcessEvents")
    assert transport.sent == []


def test_graph_needs_credentials():
    with pytest.raises(MissingCredentials, match="GRAPH_CLIENT_SECRET"):
        GraphSecurityConnector({"GRAPH_TENANT_ID": "t", "GRAPH_CLIENT_ID": "c"},
                               FakeTransport()).list_alerts()


def test_graph_error_status():
    transport = FakeTransport(token(), Response(403, {"error": {"message": "Forbidden"}}))
    with pytest.raises(GraphError, match="HTTP 403 Forbidden"):
        GraphSecurityConnector(ENV, transport).hunt("DeviceInfo | take 1")


def test_graph_caps_rows():
    body = {"schema": [], "results": [{"i": i} for i in range(MAX_ROWS + 5)]}
    result = GraphSecurityConnector(ENV, FakeTransport(token(), Response(200, body))).hunt("X")
    assert len(result.rows) == MAX_ROWS and result.truncated


# -- Replay ---------------------------------------------------------------------


def frames(columns, rows):
    """Kusto v2 response frames (format from the Kusto REST API docs, not recorded)."""
    return {"data": [
        {"FrameType": "DataSetHeader"},
        {"FrameType": "DataTable", "TableKind": "PrimaryResult",
         "Columns": [{"ColumnName": n, "ColumnType": t} for n, t in columns], "Rows": rows},
        {"FrameType": "DataSetCompletion", "HasErrors": False}]}


def test_replay_hunt_labels_mapped_tables():
    transport = FakeTransport(Response(200, frames([("FileName", "string")], [["reg.exe"]])))
    connector = ReplayConnector(KustoClient("http://kusto:8080", transport=transport))
    result = connector.hunt("DeviceProcessEvents | where FileName == 'reg.exe'", "P1D")
    assert result.rows == [{"FileName": "reg.exe"}]
    assert transport.sent[0].url == "http://kusto:8080/v2/rest/query"
    assert transport.sent[0].body["csl"].startswith("DeviceProcessEvents")
    assert any("not Defender telemetry" in p for p in result.provenance)
    assert any("timespan P1D ignored" in p for p in result.provenance)


def test_replay_refuses_management():
    with pytest.raises(ReadOnlyViolation):
        ReplayConnector(KustoClient(transport=FakeTransport())).hunt(".drop table DeviceInfo")


def test_replay_alerts_from_file(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps({"alerts": [
        {"id": "a1", "incidentId": "i1", "createdDateTime": "2020-09-04T20:10:00Z"},
        {"id": "a2", "incidentId": "i1", "createdDateTime": "2020-09-04T20:11:00Z"}]}))
    connector = ReplayConnector(KustoClient(transport=FakeTransport()), path)
    assert [a["id"] for a in connector.list_alerts()] == ["a2", "a1"]
    assert len(connector.get_incident("i1")["alerts"]) == 2
    with pytest.raises(KeyError):
        connector.get_incident("nope")


def test_replay_without_alerts_file(tmp_path):
    connector = ReplayConnector(KustoClient(transport=FakeTransport()), tmp_path / "none.json")
    assert connector.list_alerts() == []
