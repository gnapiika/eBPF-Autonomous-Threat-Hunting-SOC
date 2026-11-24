"""
MITRE ATT&CK mapping module for the eBPF Autonomous Threat Hunting SOC.

Maps detection rules to ATT&CK tactics and techniques.
This is a starter mapping for defensive security analysis.
"""

from typing import Any, Dict, List, Optional


TACTIC_NAMES_BY_ID = {
    "TA0002": "Execution",
    "TA0006": "Credential Access",
    "TA0011": "Command and Control",
}
TACTIC_IDS_BY_NAME = {
    name.casefold(): identifier
    for identifier, name in TACTIC_NAMES_BY_ID.items()
}
TECHNIQUE_NAMES_BY_ID = {
    "T1059": "Command and Scripting Interpreter",
    "T1110": "Brute Force",
    "T1571": "Non-Standard Port",
}
TECHNIQUE_IDS_BY_NAME = {
    name.casefold(): identifier
    for identifier, name in TECHNIQUE_NAMES_BY_ID.items()
}


def canonical_mitre(
    tactics: List[Any],
    techniques: List[Any],
    mitre: Optional[Dict[str, Any]] = None,
) -> Dict[str, List[Dict[str, Optional[str]]]]:
    """Return canonical ATT&CK entries while preserving old flat arrays."""
    supplied = mitre or {}
    return {
        "tactics": _canonical_entries(
            supplied.get("tactics", []),
            tactics,
            TACTIC_NAMES_BY_ID,
            TACTIC_IDS_BY_NAME,
        ),
        "techniques": _canonical_entries(
            supplied.get("techniques", []),
            techniques,
            TECHNIQUE_NAMES_BY_ID,
            TECHNIQUE_IDS_BY_NAME,
        ),
    }


def _canonical_entries(
    canonical_values: list[Any],
    legacy_values: list[Any],
    names_by_id: Dict[str, str],
    ids_by_name: Dict[str, str],
) -> List[Dict[str, Optional[str]]]:
    values = canonical_values or legacy_values
    entries = []
    seen = set()

    for value in values:
        if isinstance(value, dict):
            identifier = value.get("id")
            name = value.get("name")
        else:
            text = str(value)
            if text in names_by_id:
                identifier = text
                name = names_by_id[text]
            else:
                identifier = ids_by_name.get(text.casefold())
                name = text

        entry = {"id": identifier, "name": name}
        key = (identifier, name)
        if key not in seen:
            entries.append(entry)
            seen.add(key)

    return entries


ATTACK_MAPPINGS: dict[str, dict[str, Any]] = {
    "DET-001": {
        "name": "Suspicious Shell Execution",
        "tactics": ["Execution"],
        "techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "url": "https://attack.mitre.org/techniques/T1059/",
            }
        ],
    },
    "DET-002": {
        "name": "Script Interpreter Execution",
        "tactics": ["Execution"],
        "techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "url": "https://attack.mitre.org/techniques/T1059/",
            }
        ],
    },
    "DET-003": {
        "name": "Connection to Unusual Network Port",
        "tactics": ["Command and Control"],
        "techniques": [
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "url": "https://attack.mitre.org/techniques/T1571/",
            }
        ],
    },
}


def get_attack_mapping(rule_id: str) -> dict[str, Any]:
    """Return the ATT&CK mapping for a detection rule."""
    mapping = ATTACK_MAPPINGS.get(rule_id)

    if mapping is None:
        return {
            "name": "Unknown Detection Rule",
            "tactics": [],
            "techniques": [],
            "mitre": {"tactics": [], "techniques": []},
        }

    tactics = list(mapping["tactics"])
    techniques = [dict(technique) for technique in mapping["techniques"]]
    # Return a copy so callers cannot accidentally modify the
    # original mapping through the returned dictionary.
    return {
        "name": mapping["name"],
        "tactics": tactics,
        "techniques": techniques,
        "mitre": canonical_mitre(
            tactics,
            [technique["id"] for technique in techniques],
        ),
    }


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Add ATT&CK metadata to an alert dictionary."""
    enriched_alert = dict(alert)
    rule_id = enriched_alert.get("rule_id", "")

    mapping = get_attack_mapping(rule_id)

    enriched_alert["mitre_tactics"] = mapping["tactics"]
    enriched_alert["mitre_techniques"] = mapping["techniques"]
    enriched_alert["mitre"] = mapping["mitre"]

    return enriched_alert


if __name__ == "__main__":
    example_alert = {
        "alert_id": "ALERT-001",
        "rule_id": "DET-001",
        "title": "Suspicious shell command detected",
        "severity": "medium",
    }

    print(enrich_alert(example_alert))
