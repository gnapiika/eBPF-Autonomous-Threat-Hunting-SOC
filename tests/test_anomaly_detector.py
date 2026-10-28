
import pytest

from detection.anomaly_detection.anomaly_detector import AnomalyDetector
from detection.event_schema import SecurityEvent


def make_event(host):
    return SecurityEvent(
        event_type="process_execution",
        source="test",
        host=host,
    )


def test_detects_unusually_high_event_volume():
    events = (
        [make_event("server-01") for _ in range(8)]
        + [make_event("server-02") for _ in range(2)]
    )

    findings = AnomalyDetector(
        minimum_events=5,
        threshold_multiplier=1.5,
    ).detect_event_bursts(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "ANOM-001"
    assert findings[0]["host"] == "server-01"
    assert findings[0]["event_count"] == 8
    assert len(findings[0]["event_ids"]) == 8


def test_returns_no_findings_for_empty_input():
    assert AnomalyDetector().detect_event_bursts([]) == []


def test_does_not_flag_hosts_below_minimum_threshold():
    events = [
        make_event("server-01"),
        make_event("server-01"),
        make_event("server-02"),
        make_event("server-02"),
    ]

    findings = AnomalyDetector().detect_event_bursts(events)

    assert findings == []


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        AnomalyDetector(minimum_events=0)

    with pytest.raises(ValueError):
        AnomalyDetector(threshold_multiplier=0)