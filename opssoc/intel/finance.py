"""Finance-sector priorities from the curated profile, ATT&CK and KEV (ADR 008).

Deterministic: the same snapshots and profile give the same output. Produces

- priority techniques: ATT&CK techniques the profile's groups use, scored by the sum of
  group tier weights (primary 2, listed 1), with the groups behind each score;
- KEV entries: CVEs that ATT&CK names in a profile group's description or "uses"
  relationships and that are in KEV, with the sentence that names them;
- coverage: each priority technique against the detection_As_Code rules' ATT&CK mapping
  (exact; partial when a rule maps the parent technique or one of the technique's
  sub-techniques; or none), and the gap list. Techniques whose only tactics are
  reconnaissance or resource development are listed apart: no log a SIEM rule reads
  records them.

It does not say which groups target a given organisation, how likely an attack is, or
whether a rule is deployed and active for a customer (DaC's gate decides that).
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

from opssoc.intel.attack import Attack
from opssoc.intel.kev import Kev

PROFILE = Path("intel/finance_profile.json")
# Tactics that happen before an attacker touches the network: no endpoint, identity or cloud
# log records them, so a technique with only these tactics is reported apart from the gaps.
PRE_COMPROMISE = {"reconnaissance", "resource-development"}


@dataclass
class ProfileGroup:
    id: str
    name: str
    tier: str
    source_sentence: str | None       # ATT&CK sentence, when the group was chosen from it
    web_evidence: dict = field(default_factory=dict)


EVIDENCE_OK = {"confirmed", "weak"}
SOURCE_KEYS = ("publisher", "url", "fetched", "quote")


def load_profile(path: Path = PROFILE) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data["groups"] = [ProfileGroup(**g) for g in data["groups"]]
    return data


def check_profile(profile: dict, attack: Attack) -> list[str]:
    """Each group exists and is active in the bundle; its ATT&CK sentence, when it has one,
    is in the group's description verbatim (links and citations removed); and it carries
    web evidence (status confirmed or weak, each source with publisher, URL, fetch date and
    quote). It does not check that a quote is on the page: pages are not fetched here."""
    problems = []
    for g in profile["groups"]:
        group = attack.groups.get(g.id)
        if group is None:
            problems.append(f"{g.id}: not an active group in ATT&CK {attack.version}")
        elif g.source_sentence is not None and g.source_sentence not in group.description:
            problems.append(f"{g.id}: source sentence not in its ATT&CK description")
        ev = g.web_evidence or {}
        if ev.get("status") not in EVIDENCE_OK:
            problems.append(f"{g.id}: web evidence status {ev.get('status')!r}, "
                            f"needs one of {sorted(EVIDENCE_OK)}")
        if not ev.get("sources"):
            problems.append(f"{g.id}: no web evidence source")
        for src in ev.get("sources", []):
            missing = [k for k in SOURCE_KEYS if not src.get(k)]
            if missing:
                problems.append(f"{g.id}: web source missing {', '.join(missing)}")
        if g.tier not in profile["tier_weights"]:
            problems.append(f"{g.id}: unknown tier {g.tier}")
    if profile.get("status") not in {"proposed", "approved"}:
        problems.append(f"profile status {profile.get('status')!r}, needs proposed or approved")
    if profile.get("status") == "approved":
        approval = profile.get("approval") or {}
        missing = [k for k in ("by", "date", "basis") if not approval.get(k)]
        if missing:
            problems.append(f"approved profile has no approval {', '.join(missing)}")
    for e in profile.get("excluded", []):
        if e["id"] in {g.id for g in profile["groups"]}:
            problems.append(f"{e['id']}: both included and excluded")
    return problems


@dataclass
class TechniquePriority:
    id: str
    name: str
    tactics: list[str]
    score: int
    groups: list[str]
    coverage: str = "none"            # exact | partial | none
    rules: list[str] = field(default_factory=list)


def priorities(profile: dict, attack: Attack) -> list[TechniquePriority]:
    weights = profile["tier_weights"]
    by_tech: dict[str, list[ProfileGroup]] = defaultdict(list)
    for g in profile["groups"]:
        for t in attack.techniques_of(g.id):
            by_tech[t].append(g)
    out = [TechniquePriority(t, attack.techniques[t].name, attack.techniques[t].tactics,
                             sum(weights[g.tier] for g in gs), sorted(g.id for g in gs))
           for t, gs in by_tech.items()]
    return sorted(out, key=lambda p: (-p.score, -len(p.groups), p.id))


def kev_links(profile: dict, attack: Attack, kev: Kev) -> list[dict]:
    found: dict[str, dict] = {}
    for g in profile["groups"]:
        for cve, sentence in attack.cve_mentions(g.id):
            entry = found.setdefault(cve, {"cve": cve, "in_kev": cve in kev.entries,
                                           "groups": [], "attack_sentences": []})
            if g.id not in entry["groups"]:
                entry["groups"].append(g.id)
            if sentence not in entry["attack_sentences"]:
                entry["attack_sentences"].append(sentence)
    for cve, entry in found.items():
        if entry["in_kev"]:
            k = kev.entries[cve]
            entry.update(vendor=k.vendor, product=k.product, name=k.name,
                         date_added=k.date_added, ransomware=k.ransomware)
    return sorted(found.values(), key=lambda e: (not e["in_kev"], -len(e["groups"]), e["cve"]))


def rule_techniques(rules) -> dict[str, list[str]]:
    """technique -> DaC rule folders that map it (non-experimental rules only)."""
    out: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        if rule.data.get("status") == "experimental":
            continue
        for t in (rule.data.get("mapping", {}).get("attack", {}) or {}).get("techniques", []):
            out[t].append(rule.folder.name)
    return out


def apply_coverage(prios: list[TechniquePriority], covered: dict[str, list[str]]) -> None:
    for p in prios:
        if p.id in covered:
            p.coverage, p.rules = "exact", sorted(covered[p.id])
            continue
        # Partial: a rule maps the parent of this sub-technique, or this is a parent and a
        # rule maps one of its sub-techniques. A sibling sub-technique is not coverage.
        parent = p.id.split(".")[0] if "." in p.id else None
        related = sorted({r for t, rs in covered.items()
                          if t == parent or ("." in t and t.split(".")[0] == p.id)
                          for r in rs})
        if related:
            p.coverage, p.rules = "partial", related


def analyse(profile: dict, attack: Attack, kev: Kev, rules=None, top: int = 25) -> dict:
    prios = priorities(profile, attack)
    if rules is not None:
        apply_coverage(prios, rule_techniques(rules))
    kev_rows = kev_links(profile, attack, kev)
    head = prios[:top]
    return {
        "attack_version": attack.version, "kev_version": kev.version,
        "profile_status": profile.get("status"),
        "groups": [asdict(g) for g in profile["groups"]],
        "priority_techniques": [asdict(p) for p in prios],
        "top": top,
        "gaps": ([asdict(p) for p in head if p.coverage == "none"
                  and not set(p.tactics) <= PRE_COMPROMISE] if rules is not None else None),
        "pre_compromise": [asdict(p) for p in head if set(p.tactics) <= PRE_COMPROMISE],
        "kev": kev_rows,
        "counts": {"groups": len(profile["groups"]), "techniques": len(prios),
                   "cves_named": len(kev_rows),
                   "cves_in_kev": sum(e["in_kev"] for e in kev_rows),
                   "kev_ransomware_known": sum(e.get("ransomware") == "Known"
                                               for e in kev_rows)},
    }


HANDOFF_SCHEMA = "opssoc.finance-gaps/1"


def gap_handoff(analysis: dict, dac_commit: str | None) -> dict | None:
    """The detection agent's input: the top techniques with no detection_As_Code rule, and
    those only partly covered, with the profile groups behind each. Deterministic (no
    timestamp), so the same snapshots, profile and rules give the same file. None when no
    rules were loaded: without them there is no coverage to hand off."""
    if analysis.get("gaps") is None:
        return None
    groups = {g["id"]: {"id": g["id"], "name": g["name"], "tier": g["tier"]}
              for g in analysis["groups"]}

    def row(t: dict) -> dict:
        return {"technique": t["id"], "name": t["name"], "tactics": t["tactics"],
                "score": t["score"], "coverage": t["coverage"], "related_rules": t["rules"],
                "groups": [groups[g] for g in t["groups"]]}

    head = analysis["priority_techniques"][:analysis["top"]]
    return {
        "schema": HANDOFF_SCHEMA,
        "attack_version": analysis["attack_version"], "kev_version": analysis["kev_version"],
        "dac_commit": dac_commit, "profile_status": analysis["profile_status"],
        "top": analysis["top"],
        "gaps": [row(t) for t in analysis["gaps"]],
        "partial": [row(t) for t in head if t["coverage"] == "partial"],
        "pre_compromise": [t["id"] for t in analysis["pre_compromise"]],
        "note": "A gap means no non-experimental detection_As_Code rule maps the technique "
                "or its parent / sub-techniques. It is not a request to build a rule: new "
                "rules follow detection_As_Code's scope and the owner's approval.",
    }

