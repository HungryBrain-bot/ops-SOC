"""MITRE ATT&CK Enterprise STIX 2.1 bundle, read-only (ADR 008).

Only what the finance analysis needs: active groups (intrusion-set), active techniques
(attack-pattern) with their tactics, and the group -> technique and group -> software
"uses" relationships with their descriptions. Revoked and deprecated objects and
relationships are left out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

LINK = re.compile(r"\[([^\]]+)\]\(https?://[^)]*\)")
CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def plain(text: str) -> str:
    """ATT&CK description text without markdown links or (Citation: ...) markers."""
    return " ".join(CITATION.sub("", LINK.sub(r"\1", text or "")).split())


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


@dataclass
class Group:
    id: str
    name: str
    description: str
    aliases: list[str]


@dataclass
class Technique:
    id: str
    name: str
    tactics: list[str]
    is_subtechnique: bool


@dataclass
class Use:
    group: str
    target: str          # technique or software ATT&CK ID
    target_type: str     # attack-pattern | malware | tool
    description: str


@dataclass
class Attack:
    version: str
    groups: dict[str, Group] = field(default_factory=dict)
    techniques: dict[str, Technique] = field(default_factory=dict)
    uses: list[Use] = field(default_factory=list)

    @classmethod
    def from_bundle(cls, bundle: dict) -> Attack:
        objects = bundle["objects"]
        by_ref = {o["id"]: o for o in objects}
        version = next((o.get("x_mitre_version", "") for o in objects
                        if o["type"] == "x-mitre-collection"), "")
        attack = cls(f"ATT&CK Enterprise v{version}" if version else "ATT&CK (version unknown)")
        for o in objects:
            if not _active(o) or not _attack_id(o):
                continue
            if o["type"] == "intrusion-set":
                attack.groups[_attack_id(o)] = Group(_attack_id(o), o["name"],
                                                     plain(o.get("description", "")),
                                                     list(o.get("aliases") or []))
            elif o["type"] == "attack-pattern":
                attack.techniques[_attack_id(o)] = Technique(
                    _attack_id(o), o["name"],
                    [p["phase_name"] for p in o.get("kill_chain_phases") or []
                     if p.get("kill_chain_name") == "mitre-attack"],
                    bool(o.get("x_mitre_is_subtechnique")))
        for r in objects:
            if r["type"] != "relationship" or r.get("relationship_type") != "uses" \
                    or not _active(r):
                continue
            src, dst = by_ref.get(r["source_ref"]), by_ref.get(r["target_ref"])
            if not src or not dst or src["type"] != "intrusion-set" or not _active(src) \
                    or not _active(dst) or dst["type"] not in ("attack-pattern", "malware",
                                                               "tool"):
                continue
            attack.uses.append(Use(_attack_id(src), _attack_id(dst), dst["type"],
                                   plain(r.get("description", ""))))
        return attack

    def techniques_of(self, group: str) -> set[str]:
        return {u.target for u in self.uses if u.group == group
                and u.target_type == "attack-pattern" and u.target in self.techniques}

    def cve_mentions(self, group: str) -> list[tuple[str, str]]:
        """(CVE, sentence) for each CVE named in the group's description or its "uses"
        relationship descriptions."""
        texts = [self.groups[group].description] + [u.description for u in self.uses
                                                    if u.group == group]
        out = []
        for text in texts:
            for sentence in re.split(r"(?<=\.)\s+", text):
                out += [(cve, sentence) for cve in CVE.findall(sentence)]
        return out
