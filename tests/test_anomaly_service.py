
from detection.anomaly_detection.anomaly_service import (
    AnomalyDetectionService,
)
from detection.anomaly_detection.anomaly_detector import AnomalyDetector
from detection.event_schema import SecurityEvent


def make_event(host):
    return SecurityEvent(
        event_type="process_execution",
        source="test",
        host=host,
    )


def test_service_returns_mitre_enriched_anomaly_findings():
    events = (
        [make_event("server-01") for _ in range(8)]
        + [make_event("server-02") for _ in range(2)]
    )

    service = AnomalyDetectionService(
        detector=AnomalyDetector(
            minimum_events=5,
            threshold_multiplier=1.5,
        )
    )

    findings = service.analyze(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "ANOM-001"
    assert findings[0]["host"] == "server-01"
    assert findings[0]["mitre_tactics"] == ["TA0002"]
    assert findings[0]["mitre_techniques"] == ["T1059"]


def test_service_returns_empty_list_when_no_anomalies_exist():
    events = [
        make_event("server-01"),
        make_event("server-01"),
        make_event("server-02"),
        make_event("server-02"),
    ]

    service = AnomalyDetectionService()

    assert service.analyze(events) == []


def test_service_handles_empty_input():
    service = AnomalyDetectionService()

    assert service.analyze([]) == []