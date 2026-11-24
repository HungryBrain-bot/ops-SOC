"""Download and verify the pinned ATT&CK and KEV snapshots (ADR 008)."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

PINS = json.loads((Path(__file__).resolve().parent / "snapshots.json").read_text())["snapshots"]
DATA = Path("data/intel")


class SnapshotError(RuntimeError):
    pass


def path(name: str, data_dir: Path = DATA) -> Path:
    return data_dir / PINS[name]["file"]


def fetch(name: str, data_dir: Path = DATA) -> Path:
    pin = PINS[name]
    target = path(name, data_dir)
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == pin["sha256"]:
        return target
    raw = urllib.request.urlopen(pin["url"], timeout=300).read()  # noqa: S310 (pinned URL)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != pin["sha256"]:
        raise SnapshotError(f"{name}: SHA-256 {digest} != pinned {pin['sha256']}")
    data_dir.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return target


def load(name: str, data_dir: Path = DATA) -> dict:
    target = path(name, data_dir)
    if not target.is_file():
        raise SnapshotError(f"{target} missing: run `python -m opssoc.agents.threat_intel fetch`")
    return json.loads(target.read_text(encoding="utf-8"))
