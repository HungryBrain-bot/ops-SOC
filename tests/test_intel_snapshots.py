"""The finance analysis on the real pinned snapshots. Skipped unless they were fetched
(`python -m opssoc.agents.threat_intel fetch`; CI job `intel`)."""

import pytest

from opssoc.intel import finance, snapshots
from opssoc.intel.attack import Attack
from opssoc.intel.kev import Kev

pytestmark = pytest.mark.skipif(
    not all(snapshots.path(n).is_file() for n in snapshots.PINS),
    reason="pinned ATT&CK / KEV snapshots not fetched")


@pytest.fixture(scope="module")
def data():
    return (Attack.from_bundle(snapshots.load("attack-enterprise")),
            Kev.from_catalog(snapshots.load("cisa-kev")))


def test_snapshot_versions(data):
    attack, kev = data
    assert attack.version == "ATT&CK Enterprise v20.1" and len(attack.groups) == 178
    assert kev.version == "2026.11.23" and len(kev.entries) == 1792


def test_profile_sentences_are_in_attack(data):
    attack, _ = data
    assert finance.check_profile(finance.load_profile(), attack) == []


def test_analysis_counts(data):
    attack, kev = data
    result = finance.analyse(finance.load_profile(), attack, kev, None)
    assert result["counts"] == {"groups": 25, "techniques": 269, "cves_named": 30,
                                "cves_in_kev": 27, "kev_ransomware_known": 14}
    top = [t["id"] for t in result["priority_techniques"][:5]]
    assert top == ["T1588.002", "T1059.001", "T1566.001", "T1204.002", "T1105"]
