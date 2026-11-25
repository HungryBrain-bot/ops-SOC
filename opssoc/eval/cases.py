"""Ground truth cases and the replay alerts they label (ADR 007).

A case names one seeded alert by rule ID, replay dataset and substrings of the
matched row. ``match`` pairs every case with exactly one alert and reports alerts
no case labels, so a change to the rules or datasets that adds, drops or splits an
alert fails loudly instead of silently shifting the eval.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
GROUND_TRUTH = HERE / "ground_truth.json"
EVAL_RULES = HERE / "rules.json"


@dataclass(frozen=True)
class Case:
    id: str
    rule: str
    dataset: str
    row: dict
    expected_verdict: str
    label: dict
    key_facts: list

    def matches(self, alert: dict) -> bool:
        extra = alert.get("additionalData") or {}
        rule = extra.get("dacRule") or extra.get("evalRule")
        if rule != self.rule or extra.get("replayDataset") != self.dataset:
            return False
        row = alert.get("customDetails") or {}
        return all(needle.lower() in str(row.get(col, "")).lower()
                   for col, needle in self.row.items())


def load_cases(path: Path = GROUND_TRUTH) -> list[Case]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Case(**c) for c in data["cases"]]


def load_sources(path: Path = GROUND_TRUTH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["sources"]


@dataclass(frozen=True)
class Matching:
    pairs: dict[str, dict]        # case id -> alert
    problems: list[str]           # cases with 0 or >1 alerts
    unlabelled: list[dict]        # alerts no case matches


def match(cases: list[Case], alerts: list[dict]) -> Matching:
    pairs, problems, used = {}, [], set()
    for case in cases:
        hits = [a for a in alerts if case.matches(a)]
        if len(hits) != 1:
            problems.append(f"{case.id}: {len(hits)} alerts match (need exactly 1)")
            continue
        pairs[case.id] = hits[0]
        used.add(hits[0]["id"])
    unlabelled = [a for a in alerts if a["id"] not in used]
    return Matching(pairs, problems, unlabelled)


class EvalRule:
    """An eval rule in the shape seeding expects from a DaC rule."""

    def __init__(self, data: dict) -> None:
        self.data = data
        self.id = data["id"]
        self.folder = Path(data["id"])

    def required_fields(self, siem: str) -> dict:
        return self.data.get(siem, {}).get("required_fields", {})


def load_eval_rules(path: Path = EVAL_RULES) -> list[EvalRule]:
    return [EvalRule(r) for r in json.loads(path.read_text(encoding="utf-8"))["rules"]]
