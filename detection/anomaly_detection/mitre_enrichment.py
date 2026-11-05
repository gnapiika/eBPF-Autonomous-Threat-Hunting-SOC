
"""MITRE ATT&CK enrichment for anomaly detection findings."""

from typing import Any, Dict


ANOMALY_ATTACK_MAPPINGS = {
    "ANOM-001": {
        "mitre_tactics": ["TA0002"],
        "mitre_techniques": ["T1059"],
        "technique_names": ["Command and Scripting Interpreter"],
        "note": (
            "High event volume alone does not prove this technique. "
            "Validate the underlying events before confirming the mapping."
        ),
    }
}


def enrich_anomaly_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of an anomaly finding enriched with MITRE metadata."""

    enriched = dict(finding)
    mapping = ANOMALY_ATTACK_MAPPINGS.get(enriched.get("rule_id"))

    if not mapping:
        enriched.setdefault("mitre_tactics", [])
        enriched.setdefault("mitre_techniques", [])
        enriched.setdefault("technique_names", [])
        return enriched

    enriched["mitre_tactics"] = list(mapping["mitre_tactics"])
    enriched["mitre_techniques"] = list(mapping["mitre_techniques"])
    enriched["technique_names"] = list(mapping["technique_names"])
    enriched["mitre_mapping_note"] = mapping["note"]

    return enriched