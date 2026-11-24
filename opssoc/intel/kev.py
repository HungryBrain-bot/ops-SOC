"""CISA Known Exploited Vulnerabilities catalog, read-only (ADR 008). KEV has no sector or
actor field; entries are linked to groups only through CVEs ATT&CK names (finance.py)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    ransomware: str          # "Known" | "Unknown"
    short_description: str


@dataclass
class Kev:
    version: str
    released: str
    entries: dict[str, KevEntry]

    @classmethod
    def from_catalog(cls, catalog: dict) -> Kev:
        entries = {}
        for v in catalog["vulnerabilities"]:
            entries[v["cveID"]] = KevEntry(v["cveID"], v.get("vendorProject", ""),
                                           v.get("product", ""), v.get("vulnerabilityName", ""),
                                           v.get("dateAdded", ""),
                                           v.get("knownRansomwareCampaignUse", ""),
                                           v.get("shortDescription", ""))
        return cls(catalog.get("catalogVersion", ""), catalog.get("dateReleased", ""), entries)
