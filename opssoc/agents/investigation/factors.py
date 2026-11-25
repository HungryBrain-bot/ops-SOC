"""Factor checklist and decision rules for the investigation agent (ADR 009 point 1).

The factor file (``factors.json``) lists, per alert class, the questions every
investigation must answer. The model answers each factor with a state and cited
evidence in ``submit_verdict``; this module checks those answers and applies the
decision rules. It tests the *form* of the answers (complete, cited, the right kind of
evidence for the state) and that the verdict is allowed by them. It does not test that a
factor answer is true of the rows it cites.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

FACTORS_FILE = Path(__file__).with_name("factors.json")
WEIGHTS = ("high", "medium", "low")
ANSWERED_BY = ("logs", "analyst", "both")

MALICIOUS = "malicious_indicator"
BENIGN = "benign_indicator"
NEUTRAL = "neutral"
NO_TELEMETRY = "unknown_no_telemetry"
NOT_CHECKED = "unknown_not_checked"
STATES = (MALICIOUS, BENIGN, NEUTRAL, NO_TELEMETRY, NOT_CHECKED)
UNKNOWN = (NO_TELEMETRY, NOT_CHECKED)
EXPLANATIONS = ("malicious", "benign")

# Evidence kinds. 'coverage' (telemetry probe) and 'analyst' (analyst answers) are added
# by ADR 009 points 2 and 4; until they are built no record of those kinds exists, so
# `unknown_no_telemetry` and analyst-only factors cannot be answered yet.
ALERT_KINDS = ("alert", "incident")
COVERAGE = "coverage"
ANALYST = "analyst"
# Factors whose benign answer can support a benign verdict.
BENIGN_DECIDING = ("F1", "F8")


@dataclass(frozen=True)
class Factor:
    id: str
    name: str
    weight: str
    answered_by: str
    question: str
    tables: tuple[str, ...]


@dataclass(frozen=True)
class FactorSet:
    id: str
    version: int
    applies_to: str
    tables: dict
    factors: tuple[Factor, ...]

    @property
    def label(self) -> str:
        return f"{self.id} v{self.version}"

    def get(self, factor_id: str) -> Factor | None:
        return next((f for f in self.factors if f.id == factor_id), None)

    def render(self) -> str:
        """The checklist as the model sees it (trusted text, not fenced)."""
        lines = [f"Factor checklist {self.label}. Answer every factor in submit_verdict:"]
        for f in self.factors:
            lines.append(f"- {f.id} {f.name} (weight {f.weight}, answered by {f.answered_by}): "
                         f"{f.question}")
        return "\n".join(lines)


def load_sets(path: Path = FACTORS_FILE) -> list[FactorSet]:
    data = json.loads(path.read_text(encoding="utf-8"))
    sets = []
    for s in data["sets"]:
        factors = []
        for f in s["factors"]:
            if f["weight"] not in WEIGHTS or f["answered_by"] not in ANSWERED_BY:
                raise ValueError(f"{s['id']} {f['id']}: bad weight or answered_by")
            unknown = [t for t in f["tables"] if t not in s["tables"]]
            if unknown:
                raise ValueError(f"{s['id']} {f['id']}: tables not defined in the set {unknown}")
            factors.append(Factor(f["id"], f["name"], f["weight"], f["answered_by"],
                                  f["question"], tuple(f["tables"])))
        ids = [f.id for f in factors]
        if len(set(ids)) != len(ids):
            raise ValueError(f"{s['id']}: duplicate factor IDs")
        missing = [i for i in BENIGN_DECIDING if i not in ids]
        if missing:
            raise ValueError(f"{s['id']}: decision rules need factors {missing}")
        sets.append(FactorSet(s["id"], int(s["version"]), s["applies_to"], s["tables"],
                              tuple(factors)))
    return sets


def for_alert(alert: dict, sets: list[FactorSet] | None = None) -> FactorSet:
    """v1 has one class, endpoint-process, used for every alert."""
    sets = sets or load_sets()
    return next(s for s in sets if s.id == "endpoint-process")


def _kinds(ids: list[str], evidence: dict) -> set[str]:
    return {evidence[i].kind for i in ids if i in evidence}


def check_factors(verdict: dict, evidence: dict, fset: FactorSet) -> list[str]:
    """Every factor answered once; a known state cites evidence; `unknown_no_telemetry`
    cites a coverage record; an analyst-only factor in a known state cites an analyst
    record; two or more hypotheses with at least one benign explanation."""
    problems = []
    answers = verdict.get("factors") or []
    seen: dict[str, int] = {}
    for n, a in enumerate(answers):
        fid, state = a.get("factor"), a.get("state")
        ids = a.get("evidence_ids") or []
        name = f"factors[{n}] ({fid})"
        factor = fset.get(str(fid))
        if factor is None:
            problems.append(f"{name}: not a factor of {fset.label}")
            continue
        seen[factor.id] = seen.get(factor.id, 0) + 1
        if state not in STATES:
            problems.append(f"{name}: state must be one of {STATES}")
            continue
        kinds = _kinds(ids, evidence)
        if state in (MALICIOUS, BENIGN, NEUTRAL) and not ids:
            problems.append(f"{name}: state {state} cites no evidence")
        if state == NO_TELEMETRY and COVERAGE not in kinds:
            problems.append(f"{name}: unknown_no_telemetry must cite a coverage record "
                            "that shows the gap")
        if (factor.answered_by == "analyst" and state in (MALICIOUS, BENIGN, NEUTRAL)
                and ANALYST not in kinds):
            problems.append(f"{name}: only the analyst can answer {factor.id}; cite an "
                            "analyst record or leave it unknown_not_checked")
    for f in fset.factors:
        if f.id not in seen:
            problems.append(f"factor {f.id} ({f.name}) is not answered")
        elif seen[f.id] > 1:
            problems.append(f"factor {f.id} ({f.name}) is answered {seen[f.id]} times")
    hyps = verdict.get("hypotheses") or []
    if len(hyps) < 2:
        problems.append("give at least two competing hypotheses")
    if not any(h.get("explanation") == "benign" for h in hyps):
        problems.append("at least one hypothesis must be a benign explanation")
    for n, h in enumerate(hyps):
        if h.get("explanation") not in EXPLANATIONS:
            problems.append(f"hypotheses[{n}]: explanation must be one of {EXPLANATIONS}")
    return problems


def _answers(verdict: dict, fset: FactorSet) -> list[tuple[Factor, dict]]:
    out = []
    for a in verdict.get("factors") or []:
        factor = fset.get(str(a.get("factor")))
        if factor is not None:
            out.append((factor, a))
    return out


def check_decision(verdict: dict, evidence: dict, fset: FactorSet) -> list[str]:
    """The verdict is allowed by the factor answers:
    - true_positive: a high-weight factor is a malicious indicator citing evidence other
      than the alert or incident records (the alert alone is not enough);
    - benign: F1 or F8 is a benign indicator, and no high-weight factor is
      unknown_no_telemetry (missing data blocks clearing an alert);
    - confidence high: no high-weight factor is unknown.
    Missing data does not block a true positive."""
    problems = []
    answers = _answers(verdict, fset)
    high = [(f, a) for f, a in answers if f.weight == "high"]
    v = verdict.get("verdict")
    if v == "true_positive":
        backed = [f.id for f, a in high if a.get("state") == MALICIOUS
                  and _kinds(a.get("evidence_ids") or [], evidence) - set(ALERT_KINDS)]
        if not backed:
            problems.append("true_positive needs a high-weight factor marked "
                            "malicious_indicator that cites evidence beyond the alert "
                            "(query the telemetry; the alert alone is not enough)")
    if v == "benign":
        if not any(f.id in BENIGN_DECIDING and a.get("state") == BENIGN for f, a in answers):
            problems.append(f"benign needs {' or '.join(BENIGN_DECIDING)} marked "
                            "benign_indicator (evidence for the benign explanation)")
        gaps = [f.id for f, a in high if a.get("state") == NO_TELEMETRY]
        if gaps:
            problems.append(f"benign is not allowed while high-weight factors lack "
                            f"telemetry: {gaps}")
    if verdict.get("confidence") == "high":
        unknown = [f.id for f, a in high if a.get("state") in UNKNOWN]
        if unknown:
            problems.append(f"confidence high is not allowed while high-weight factors "
                            f"are unknown: {unknown}")
    return problems


def tally(verdict: dict, fset: FactorSet) -> dict:
    """Counts of factor states by weight, computed by code. A report for the analyst,
    not a score that sets the verdict (ADR 009: weights are uncalibrated)."""
    counts = {state: dict.fromkeys(WEIGHTS, 0) for state in STATES}
    factors = {}
    for f, a in _answers(verdict, fset):
        state = a.get("state")
        if state in counts:
            counts[state][f.weight] += 1
        factors[f.id] = {"name": f.name, "weight": f.weight, "state": state,
                         "evidence_ids": list(a.get("evidence_ids") or [])}
    return {"factor_set": fset.label, "by_state": counts, "factors": factors}
