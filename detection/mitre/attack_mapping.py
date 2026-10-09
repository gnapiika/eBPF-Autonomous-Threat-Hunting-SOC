"""
MITRE ATT&CK mapping module for the eBPF Autonomous Threat Hunting SOC.

Maps detection rules to ATT&CK tactics and techniques.
This is a starter mapping for defensive security analysis.
"""

from typing import Any


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
        }

    # Return a copy so callers cannot accidentally modify the
    # original mapping through the returned dictionary.
    return {
        "name": mapping["name"],
        "tactics": list(mapping["tactics"]),
        "techniques": [
            dict(technique) for technique in mapping["techniques"]
        ],
    }


def enrich_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Add ATT&CK metadata to an alert dictionary."""
    enriched_alert = dict(alert)
    rule_id = enriched_alert.get("rule_id", "")

    mapping = get_attack_mapping(rule_id)

    enriched_alert["mitre_tactics"] = mapping["tactics"]
    enriched_alert["mitre_techniques"] = mapping["techniques"]

    return enriched_alert


if __name__ == "__main__":
    example_alert = {
        "alert_id": "ALERT-001",
        "rule_id": "DET-001",
        "title": "Suspicious shell command detected",
        "severity": "medium",
    }

    print(enrich_alert(example_alert))
