"""The one interface both SOAR writers implement (ADR 002).

A writer turns a ``CaseReport`` into a short sequence of HTTP requests. The
sequence is written as a generator: it yields a ``Request`` and receives the
``Response``, so a later request can use an ID from an earlier response
(XSOAR's entry needs the incident ID). The same generator runs in all modes:

- ``dry-run``: responses are synthetic placeholders; requests are written to
  ``build/soar/<target>/<case id>.json`` with auth redacted. No network.
- ``test``: requests go over real HTTP to a local stub server
  (``opssoc.soar.stub_server``). Refused for any non-loopback URL.
- ``live``: requests go to the real SOAR. Needs every credential env var;
  refuses to write the same case to the same target twice (local ledger).
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from collections.abc import Generator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlparse

from opssoc.case import CaseReport
from opssoc.http import MissingCredentials, Request, Response, Transport

Steps = Generator[Request, Response, str]


class Mode(StrEnum):
    DRY_RUN = "dry-run"
    TEST = "test"
    LIVE = "live"


class WriteError(RuntimeError):
    """The SOAR answered with a status the writer does not accept."""


class AlreadyWritten(RuntimeError):
    """Live mode: the ledger shows this case was already written to this target."""


@dataclass
class WriteResult:
    target: str
    mode: Mode
    case_id: str
    outcome: str  # e.g. "written", "blocked-by-preprocessing", "dry-run"
    reference: str | None = None  # incident ID / comment name in the SOAR
    requests: list[dict] = field(default_factory=list)  # redacted
    statuses: list[int] = field(default_factory=list)


class SoarWriter(ABC):
    #: target key used on the CLI and in build/ paths
    name: str
    #: every variable live mode needs
    credential_env_vars: tuple[str, ...]
    #: credentials the stub server accepts in test mode (not secrets)
    test_credentials: Mapping[str, str]

    def __init__(self, env: Mapping[str, str] | None = None, base_url: str | None = None) -> None:
        self.env = dict(os.environ if env is None else env)
        self.base_url_override = base_url

    # -- subclass API -------------------------------------------------------

    @abstractmethod
    def base_url(self) -> str:
        """Live base URL from env (placeholder when a variable is unset)."""

    @abstractmethod
    def steps(self, report: CaseReport, base_url: str, creds: Mapping[str, str]) -> Steps:
        """Yield each request, receive its response, return the outcome string."""

    @abstractmethod
    def placeholder_response(self, request: Request) -> Response:
        """Synthetic response used in dry-run so later steps can be built."""

    def reference(self) -> str | None:
        """ID of what was written, set by steps() when known."""
        return getattr(self, "_reference", None)

    # -- shared driver ------------------------------------------------------

    def write(
        self,
        report: CaseReport,
        mode: Mode | str = Mode.DRY_RUN,
        transport: Transport | None = None,
        out_dir: Path | str = Path("build/soar"),
    ) -> WriteResult:
        mode = Mode(mode)
        out_dir = Path(out_dir)
        self._reference = None
        if mode is Mode.DRY_RUN:
            base = self.base_url_override or self.base_url()
            creds = {k: self.env.get(k, f"<{k}>") for k in self.credential_env_vars}
            return self._run(report, mode, base, creds, None, out_dir)
        if mode is Mode.TEST:
            base = self.base_url_override
            if not base or urlparse(base).hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("test mode only sends to a local stub server (loopback URL)")
            return self._run(report, mode, base, dict(self.test_credentials),
                             transport or Transport(timeout=5), out_dir)
        missing = [k for k in self.credential_env_vars if not self.env.get(k)]
        if missing:
            raise MissingCredentials(f"{self.name}: unset {', '.join(missing)}")
        ledger = _Ledger(out_dir / "ledger.json")
        if ledger.has(self.name, report.case_id):
            raise AlreadyWritten(f"{self.name}: case {report.case_id} was already written")
        creds = {k: self.env[k] for k in self.credential_env_vars}
        result = self._run(report, mode, self.base_url_override or self.base_url(), creds,
                           transport or Transport(), out_dir)
        if result.outcome == "written":
            ledger.add(self.name, report.case_id, result.reference)
        return result

    def _run(self, report, mode, base, creds, transport, out_dir) -> WriteResult:
        result = WriteResult(self.name, mode, report.case_id, outcome="dry-run")
        gen = self.steps(report, base.rstrip("/"), creds)
        response = None
        try:
            request = next(gen)
            while True:
                result.requests.append(request.redacted())
                if transport is None:
                    response = self.placeholder_response(request)
                else:
                    response = transport.send(request)
                    result.statuses.append(response.status)
                request = gen.send(response)
        except StopIteration as stop:
            if transport is not None:
                result.outcome = stop.value
        result.reference = self.reference()
        if mode is Mode.DRY_RUN:
            path = out_dir / self.name / f"{report.case_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result.requests, indent=2) + "\n", encoding="utf-8")
        return result


def expect(response: Response, accepted: set[int], what: str) -> None:
    if response.status not in accepted:
        raise WriteError(f"{what}: HTTP {response.status} {json.dumps(response.body)[:300]}")


class _Ledger:
    """Which cases live mode has written to which target. Local file, append-only."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = json.loads(path.read_text()) if path.is_file() else {}

    def has(self, target: str, case_id: str) -> bool:
        return case_id in self.data.get(target, {})

    def add(self, target: str, case_id: str, reference: str | None) -> None:
        self.data.setdefault(target, {})[case_id] = {
            "reference": reference,
            "written_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")
