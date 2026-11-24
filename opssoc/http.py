"""Request, response and transport shared by connectors and the SOAR writer.

Every outbound call is built as a ``Request`` first (pure data, printable with
auth redacted) and sent through a ``Transport``. Tests swap the transport or
point it at a local stub server; nothing else changes between modes.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

AUTH_HEADERS = {"authorization", "x-xdr-auth-id"}


class MissingCredentials(RuntimeError):
    """Live mode was asked for but a credential environment variable is unset."""


@dataclass
class Request:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    body: dict | None = None

    def redacted(self) -> dict:
        """Printable form: auth header values are never shown."""
        headers = {
            k: ("<redacted>" if k.lower() in AUTH_HEADERS else v) for k, v in self.headers.items()
        }
        return {"method": self.method, "url": self.url, "headers": headers, "body": self.body}


@dataclass
class Response:
    status: int
    body: dict


class Transport:
    """Minimal stdlib HTTP client (JSON in, JSON out)."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout

    def send(self, request: Request) -> Response:
        data = json.dumps(request.body).encode() if request.body is not None else None
        req = urllib.request.Request(
            request.url,
            data=data,
            method=request.method,
            headers={**request.headers, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return Response(resp.status, _parse(resp.read().decode()))
        except urllib.error.HTTPError as exc:
            return Response(exc.code, _parse(exc.read().decode()))


def _parse(raw: str) -> dict:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}
    return parsed if isinstance(parsed, dict) else {"data": parsed}
