"""The case report the investigation agent produces and the SOAR writer sends.

Only the fields the SOAR writer needs are defined here; the full case model
comes with the investigation agent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EvidenceItem:
    id: str
    source: str  # connector + table, e.g. "graph:DeviceProcessEvents"
    finding: str
    query: str | None = None
    provenance: str = "recorded"  # recorded | mapped | hand-written (CLAUDE.md conventions)


@dataclass
class CaseReport:
    case_id: str
    title: str
    verdict: Verdict
    severity: Severity
    summary: str
    source_alert_id: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    secops_case_id: str | None = None  # Google SecOps case holding the source alert

    def __post_init__(self) -> None:
        self.verdict = Verdict(self.verdict)
        self.severity = Severity(self.severity)
        self.evidence = [
            item if isinstance(item, EvidenceItem) else EvidenceItem(**item)
            for item in self.evidence
        ]
        if not self.case_id or "/" in self.case_id or self.case_id.startswith("."):
            raise ValueError(f"invalid case_id {self.case_id!r}")

    @classmethod
    def load(cls, path: Path | str) -> CaseReport:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(**{k: v for k, v in data.items() if not k.startswith("_")})
