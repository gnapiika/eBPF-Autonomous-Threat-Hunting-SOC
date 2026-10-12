
from detection.anomaly_detection.mitre_enrichment import (
    enrich_anomaly_finding,
)


def test_enriches_known_anomaly_rule():
    finding = {
        "rule_id": "ANOM-001",
        "host": "server-01",
        "event_count": 8,
    }

    result = enrich_anomaly_finding(finding)

    assert result["mitre_tactics"] == ["TA0002"]
    assert result["mitre_techniques"] == ["T1059"]
    assert "mitre_mapping_note" in result
    assert "mitre_tactics" not in finding


def test_unknown_rule_receives_empty_mitre_metadata():
    result = enrich_anomaly_finding({"rule_id": "UNKNOWN-001"})

    assert result["mitre_tactics"] == []
    assert result["mitre_techniques"] == []
    assert result["technique_names"] == []


def test_preserves_existing_finding_fields():
    finding = {
        "rule_id": "ANOM-001",
        "severity": "medium",
    }

    result = enrich_anomaly_finding(finding)

    assert result["severity"] == "medium"
    assert result["rule_id"] == "ANOM-001"