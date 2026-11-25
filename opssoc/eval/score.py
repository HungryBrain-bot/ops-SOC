"""Score investigation records against ground truth (ADR 007).

Per case:
- ``verdict_correct``: the accepted verdict equals the expected one. No verdict, or
  ``inconclusive``, is not correct; both are counted separately.
- ``key_fact_recall``: share of the case's key facts that appear in the verdict text
  (summary, hypotheses, timeline, findings), case-insensitive.
- ``grounded_fact_recall``: share of key facts that appear in the verdict text **and** in
  the rows of evidence the verdict cites. A fact stated without citing evidence that
  holds it does not count here.
- ``citations_valid``: the stored verdict passes the agent's citation checks again, re-run
  on the stored evidence (catches a record edited after the run or a check that changed).
- ``factor_checks_valid``: it also passes the factor and decision checks of ADR 009
  (False for records from agent v1, which had no factor answers).
- ``factor_tally``: the record's factor state counts (None before ADR 009).
- cost, model turns, queries, rejected verdicts.

What it does not measure: whether the reasoning is sound beyond these facts, whether a
cited row says what the finding claims, analyst usefulness, or variance between runs
(run the eval more than once for that).
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from opssoc.agents.investigation.agent import Evidence, check_citations, check_verdict
from opssoc.eval.cases import Case


def _norm(text: str) -> str:
    return text.replace("\\\\", "\\").lower()


def _verdict_text(verdict: dict) -> str:
    parts = [verdict.get("summary", "")]
    for section, key in (("hypotheses", "hypothesis"), ("timeline", "event"),
                         ("findings", "statement")):
        parts += [str(item.get(key, "")) for item in verdict.get(section) or []]
    return _norm(" ".join(parts))


def _evidence(record: dict) -> dict[str, Evidence]:
    out = {}
    for e in record.get("evidence") or []:
        fields = {k: e[k] for k in ("id", "kind", "source", "query", "purpose", "provenance",
                                    "columns", "rows", "truncated", "sha256")}
        out[e["id"]] = Evidence(**fields)
    return out


def score_case(case: Case, record: dict) -> dict:
    verdict = record.get("verdict") if record.get("status") == "verdict" else None
    result = {"case": case.id, "expected": case.expected_verdict,
              "label_kind": case.label.get("kind"),
              "status": record.get("status"),
              "verdict": verdict.get("verdict") if verdict else None,
              "confidence": verdict.get("confidence") if verdict else None,
              "cost_usd": round(float((record.get("usage") or {}).get("cost_usd", 0)), 6),
              "llm_turns": record.get("llm_turns", 0), "queries": record.get("queries", 0),
              "rejected_verdicts": len(record.get("rejected_verdicts") or []),
              "models": record.get("models", [])}
    facts = [_norm(f) for f in case.key_facts]
    if verdict is None:
        result.update(verdict_correct=False, key_fact_recall=0.0, grounded_fact_recall=0.0,
                      citations_valid=None, factor_checks_valid=None, factor_tally=None,
                      facts_missing=case.key_facts)
        return result
    evidence = _evidence(record)
    text = _verdict_text(verdict)
    cited = {i for s in ("timeline", "findings", "hypotheses")
             for item in verdict.get(s) or [] for i in item.get("evidence_ids") or []}
    cited_text = _norm(" ".join(evidence[i].text() for i in cited if i in evidence))
    stated = [f for f in facts if f in text]
    grounded = [f for f in stated if f in cited_text]
    result.update(
        verdict_correct=verdict.get("verdict") == case.expected_verdict,
        key_fact_recall=round(len(stated) / len(facts), 3) if facts else 1.0,
        grounded_fact_recall=round(len(grounded) / len(facts), 3) if facts else 1.0,
        citations_valid=not check_citations(verdict, evidence),
        factor_checks_valid=not check_verdict(verdict, evidence),
        factor_tally=record.get("factor_tally"),
        facts_missing=[f for f, n in zip(case.key_facts, facts, strict=True) if n not in stated])
    return result


def summarise(results: list[dict]) -> dict:
    n = len(results)
    if not n:
        return {"cases": 0}
    confusion = Counter((r["expected"], r["verdict"] or "no verdict") for r in results)
    by_label = {}
    for kind in sorted({r["label_kind"] for r in results}):
        sub = [r for r in results if r["label_kind"] == kind]
        by_label[kind] = {"cases": len(sub),
                          "verdict_accuracy": round(sum(r["verdict_correct"] for r in sub)
                                                    / len(sub), 3)}
    return {
        "cases": n,
        "verdict_accuracy": round(sum(r["verdict_correct"] for r in results) / n, 3),
        "inconclusive_or_none": sum(r["verdict"] in (None, "inconclusive") for r in results),
        "budget_stops": sum("budget" in str(r["status"]) for r in results),
        "mean_key_fact_recall": round(sum(r["key_fact_recall"] for r in results) / n, 3),
        "mean_grounded_fact_recall": round(sum(r["grounded_fact_recall"] for r in results)
                                           / n, 3),
        "citations_invalid": sum(r["citations_valid"] is False for r in results),
        "factor_checks_invalid": sum(r["factor_checks_valid"] is False for r in results),
        "rejected_verdicts": sum(r["rejected_verdicts"] for r in results),
        "confusion": {f"{e} -> {v}": c for (e, v), c in sorted(confusion.items())},
        "by_label_kind": by_label,
        "cost_usd": round(sum(r["cost_usd"] for r in results), 4),
        "mean_llm_turns": round(sum(r["llm_turns"] for r in results) / n, 2),
        "mean_queries": round(sum(r["queries"] for r in results) / n, 2),
        "models": sorted({m for r in results for m in r["models"]}),
    }


def score_dir(cases: list[Case], records_dir: Path) -> dict:
    results, missing = [], []
    for case in cases:
        path = records_dir / f"{case.id}.investigation.json"
        if not path.is_file():
            missing.append(case.id)
            continue
        results.append(score_case(case, json.loads(path.read_text(encoding="utf-8"))))
    return {"summary": summarise(results), "missing_records": missing, "cases": results}
