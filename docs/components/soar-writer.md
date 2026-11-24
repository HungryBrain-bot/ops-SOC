# SOAR writer

Decision: [ADR 002](../decisions/002-soar-writer.md). Code: `opssoc/soar/`.

## What it does

Takes a case report (`opssoc/case.py`) and writes it to a SOAR:

| Target | Calls | Result in the SOAR |
|---|---|---|
| Cortex XSOAR 8 (`xsoar`) | `POST /xsoar/public/v1/incident`, then `POST /xsoar/public/v1/entry` | New incident labelled `ops-soc-case:<case id>`, report as a Markdown War Room entry |
| Google SecOps SOAR (`secops`) | `POST /v1/projects/{p}/locations/{r}/instances/{i}/cases/{case}/caseComments` | Comment on the existing case that holds the source alert |

## How it works

Each writer is a generator of HTTP requests: it yields a request and gets the response
back, so XSOAR's second call can use the incident ID from the first. One driver
(`opssoc/soar/base.py`) runs that generator in three modes:

| Mode | Where requests go | Needs | Use |
|---|---|---|---|
| `dry-run` (default) | `build/soar/<target>/<case id>.json`, auth redacted | nothing | review what would be sent |
| `test` | local stub server over real HTTP (loopback only) | nothing | prove the write path works end to end |
| `live` | the real SOAR | every credential env var | production |

```
python -m opssoc.soar write --target xsoar  --report examples/case_report.json --mode test
python -m opssoc.soar write --target secops --report examples/case_report.json            # dry-run
python -m opssoc.soar stub --port 8765                                                    # stub in foreground
```

Credentials (live only), from environment variables:

- XSOAR: `XSOAR_API_URL` (`https://api-<fqdn>`), `XSOAR_API_KEY`, `XSOAR_API_KEY_ID`;
  optional `XSOAR_INCIDENT_TYPE`.
- SecOps: `SECOPS_PROJECT`, `SECOPS_REGION`, `SECOPS_INSTANCE`, `SECOPS_ACCESS_TOKEN`
  (short-lived OAuth token).

The stub server (`opssoc/soar/stub_server.py`) checks method, path, auth headers and
required body fields, and answers with the documented codes: XSOAR 201 (created),
200 (pre-processing rule blocked it; triggered by `BLOCK-ME` in the name), 412
(investigation closed), 401, 400; SecOps 200, 401, 404 (unknown case), 400.

Live mode keeps `build/soar/ledger.json` and refuses to write the same case to the same
target twice.

## Why this method

- A stub server over real HTTP exercises serialisation, headers and status handling,
  which a fake transport object skips. The fake transport is still used for live-mode
  unit tests, where no socket is wanted.
- Building every request before sending it makes dry-run and live identical up to the
  transport, so what was reviewed in dry-run is what goes out.
- No vendor SDKs: three calls do not justify two dependency trees, and SDKs hide the
  requests.

## What it does not do

- It does not prove a real XSOAR or SecOps accepts the requests. The stub encodes our
  reading of the docs. Live behaviour is not verified until a logged live call.
- Google SecOps `caseComments.create`: URL pattern and the `comment` body field are
  **unverified** (the reference page did not render through the fetch tool).
- XSOAR: assumes the created incident's `id` is the `investigationId` for the entry.
  Does not search XSOAR for an existing incident with the same label before creating.
- It never changes status, severity, owner, or closes anything, and never creates a
  SecOps case (the v1 API has no method for it).
- The Markdown is a fixed template; LLM-written summaries come with the investigation
  agent.
