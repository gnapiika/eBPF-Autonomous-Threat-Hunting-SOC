from detection.mitre.attack_mapping import (
    get_attack_mapping,
    enrich_alert,
)


def test_known_rule_returns_correct_mapping():
    mapping = get_attack_mapping("DET-001")

    assert mapping["name"] == "Suspicious Shell Execution"
    assert "Execution" in mapping["tactics"]
    assert mapping["techniques"][0]["id"] == "T1059"
    assert mapping["mitre"]["tactics"] == [
        {"id": "TA0002", "name": "Execution"}
    ]
    assert mapping["mitre"]["techniques"] == [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
        }
    ]


def test_unknown_rule_returns_empty_mapping():
    mapping = get_attack_mapping("DET-999")

    assert mapping["name"] == "Unknown Detection Rule"
    assert mapping["tactics"] == []
    assert mapping["techniques"] == []
    assert mapping["mitre"] == {"tactics": [], "techniques": []}


def test_enrich_alert_preserves_original_fields():
    alert = {
        "alert_id": "ALERT-001",
        "rule_id": "DET-001",
        "severity": "medium",
    }

    enriched = enrich_alert(alert)

    assert enriched["alert_id"] == "ALERT-001"
    assert enriched["severity"] == "medium"
    assert enriched["mitre_tactics"] == ["Execution"]
    assert enriched["mitre_techniques"][0]["id"] == "T1059"

    # Enrichment should not modify the original alert.
    assert "mitre_tactics" not in alert