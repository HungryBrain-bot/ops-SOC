"""ops-SOC agents (ADR 001). Each agent has a definition file (agent.md: settings in
front matter, system prompt in the body) next to its code; the prompt is versioned with
the code that depends on it."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentDefinition:
    name: str
    version: str
    settings: dict[str, str]
    prompt: str

    def number(self, key: str, default: float) -> float:
        return float(self.settings.get(key, default))


def load_definition(path: Path) -> AgentDefinition:
    """Front matter is flat ``key: value`` lines between ``---`` markers (no YAML needed)."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: no front matter")
    head, _, body = text[4:].partition("\n---\n")
    settings = {}
    for line in head.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, _, value = line.partition(":")
            settings[key.strip()] = value.strip()
    return AgentDefinition(settings.pop("name"), settings.pop("version"), settings,
                           body.strip())
