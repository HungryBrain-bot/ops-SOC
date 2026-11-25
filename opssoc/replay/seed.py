"""Seed replay alerts: run detection_As_Code rules over recorded OTRF data (ADR 004).

OTRF datasets are recorded attacks with no alerts. To give the agents
something to investigate, each dataset is loaded alone into the Kusto
emulator and every DaC rule whose Sentinel tables are loaded is run over it.
Each matched row becomes one alert in the shape of a Graph ``alerts_v2``
alert, written to ``data/replay/alerts.json``. Finally all datasets are
loaded together so hunting queries see everything.

What an alert carries and what it does not:

- Taken from the rule: title, description, severity, mitreTechniques,
  categories (ATT&CK tactics), the rule id and version.
- Taken from the matched row: times, device, user, process / registry
  evidence, and the whole row in ``customDetails``.
- Set to "not yet triaged": status ``new``, classification and determination
  ``unknown``. No alert is pre-labelled true or false positive; that is the
  investigation agent's job and the eval harness's ground truth (ADR 004).
- ``additionalData.provenance`` says how the alert was made. Nothing here is
  a Defender or Sentinel alert.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from opssoc.replay import dac_bridge

SEED_LABEL = ("seeded by ops-SOC: detection_As_Code rule {rule} run over recorded OTRF dataset "
              "{dataset} in the Kusto emulator (not a Defender or Sentinel alert)")
SEVERITIES = {"informational", "low", "medium", "high"}


def _id(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode()).hexdigest()[:12]


def _split_account(account: str) -> tuple[str, str]:
    domain, _, name = account.rpartition("\\")
    return name, domain


def _file(path: str) -> dict:
    return {"fileName": path.replace("/", "\\").rsplit("\\", 1)[-1], "filePath": path}


def _tactic(name: str) -> str:
    """ATT&CK tactic short name -> the CamelCase form used in categories, e.g.
    credential-access -> CredentialAccess. The exact Graph value set is not documented
    on the alert page (fetched 2026-11-24), so this form is an assumption (ADR 004)."""
    return "".join(word.capitalize() for word in name.split("-"))


def evidence(row: dict) -> list[dict]:
    """Graph alertEvidence items for the columns a DaC endpoint rule projects."""
    items: list[dict] = []
    computer = row.get("Computer")
    if computer:
        host, _, domain = computer.partition(".")
        device = {"@odata.type": "#microsoft.graph.security.deviceEvidence",
                  "deviceDnsName": computer, "hostName": host}
        if domain:
            device["dnsDomain"] = domain
        items.append(device)
    account = row.get("Account") or row.get("UserName")
    user = None
    if account:
        name, domain = _split_account(account)
        user = {"accountName": name}
        if domain:
            user["domainName"] = domain
        items.append({"@odata.type": "#microsoft.graph.security.userEvidence",
                      "userAccount": user})
    image = row.get("NewProcessName") or row.get("Image")
    if image:
        process = {"@odata.type": "#microsoft.graph.security.processEvidence",
                   "imageFile": _file(image)}
        if row.get("CommandLine"):
            process["processCommandLine"] = row["CommandLine"]
        if row.get("ParentProcessName"):
            process["parentProcessImageFile"] = _file(row["ParentProcessName"])
        if user:
            process["userAccount"] = user
        items.append(process)
    if row.get("TargetObject"):
        hive, _, rest = row["TargetObject"].partition("\\")
        key, _, value_name = rest.rpartition("\\")
        items.append({"@odata.type": "#microsoft.graph.security.registryValueEvidence",
                      "registryHive": hive, "registryKey": key,
                      "registryValueName": value_name, "registryValue": row.get("Details")})
    return items


def to_alert(rule_data: dict, row: dict, dataset: str, created: str) -> dict:
    """One matched row -> one Graph-alerts_v2-shaped alert."""
    rule_label = f"{rule_data['id']} v{rule_data.get('version', 1)} ({rule_data['name']})"
    when = str(row.get("TimeGenerated") or created)
    computer = row.get("Computer") or "unknown-host"
    severity = str(rule_data.get("severity", "")).lower()
    attack = rule_data.get("mapping", {}).get("attack", {})
    row_key = json.dumps(row, sort_keys=True, default=str)
    return {
        "id": "rpl-" + _id(rule_data["id"], dataset, row_key),
        "providerAlertId": rule_data["id"],
        "incidentId": "rpl-inc-" + _id(dataset, computer.lower()),
        "title": rule_data["name"],
        "description": " ".join(str(rule_data.get("description", "")).split()),
        "severity": severity if severity in SEVERITIES else "unknown",
        "status": "new",
        "classification": "unknown",
        "determination": "unknown",
        "categories": [_tactic(t) for t in attack.get("tactics", [])],
        "mitreTechniques": list(attack.get("techniques", [])),
        "detectionSource": "scheduledAlerts",
        "serviceSource": "microsoftSentinel",
        "productName": "ops-SOC replay",
        "createdDateTime": created,
        "firstActivityDateTime": when,
        "lastActivityDateTime": when,
        "evidence": evidence(row),
        "customDetails": row,
        "additionalData": {
            "provenance": SEED_LABEL.format(rule=rule_label, dataset=dataset),
            "replayDataset": dataset,
            "dacRule": rule_data["id"],
            "dacRuleVersion": rule_data.get("version", 1),
            "dacCommit": dac_bridge.DAC_COMMIT,
        },
    }


def runnable(rules, loaded: set[str]) -> list:
    """Rules with a Sentinel query whose required tables are all loaded. Experimental rules
    are skipped: DaC deploys them disabled, so a workspace would not alert on them."""
    out = []
    for rule in rules:
        if rule.data.get("status") == "experimental":
            continue
        query = (rule.data.get("sentinel") or {}).get("query")
        tables = set(rule.required_fields("sentinel"))
        if query and tables and tables <= loaded:
            out.append(rule)
    return out


def seed(kusto, out_path: Path, created: str | None = None) -> dict:
    from opssoc.replay.__main__ import PINS, dataset_rows, load, table_schemas  # noqa: PLC0415

    created = created or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    schemas = table_schemas(with_sentinel=True)
    rules = runnable(dac_bridge.load_rules(), set(schemas))
    alerts: list[dict] = []
    summary: dict = {"engine": kusto.version(), "dac_commit": dac_bridge.DAC_COMMIT,
                     "rules_run": sorted(r.id for r in rules), "per_dataset": {}}
    combined: dict[str, list[dict]] = {}
    for name in PINS["datasets"]:
        rows, _ = dataset_rows(name, with_sentinel=True)
        for table, items in rows.items():
            combined.setdefault(table, []).extend(items)
        load(kusto, rows, schemas)
        hits = {}
        for rule in rules:
            _, matched = kusto.query(rule.data["sentinel"]["query"])
            alerts += [to_alert(rule.data, row, name, created) for row in matched]
            if matched:
                hits[rule.folder.name] = len(matched)
        summary["per_dataset"][name] = hits
    load(kusto, combined, schemas)
    alerts.sort(key=lambda a: (a["firstActivityDateTime"], a["id"]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"_provenance": "see each alert's additionalData.provenance",
                                    "alerts": alerts}, indent=2, default=str) + "\n",
                        encoding="utf-8")
    summary["alerts"] = len(alerts)
    return summary
