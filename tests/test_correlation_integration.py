
from detection.correlation.correlation_engine import CorrelationEngine
from detection.event_schema import NetworkInfo, SecurityEvent, UserInfo
from detection.detection_engine import DetectionAlert


def make_auth_event(timestamp, outcome):
    return SecurityEvent(
        event_type="authentication",
        source="test",
        host="test-host",
        timestamp=timestamp,
        user=UserInfo(username="admin"),
        network=NetworkInfo(source_ip="192.168.1.50"),
        raw_event={"outcome": outcome},
    )


def test_correlation_finding_contains_alert_fields():
    events = [
        make_auth_event("2026-10-10T09:00:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:01:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:02:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:03:00+00:00", "success"),
    ]

    findings = CorrelationEngine().detect_login_brute_force(events)

    assert len(findings) == 1

    finding = findings[0]
    assert finding["rule_id"] == "COR-001"
    assert finding["severity"] == "high"
    assert finding["host"] == "test-host"
    assert finding["username"] == "admin"
    assert finding["mitre_techniques"] == ["T1110"]


def test_correlation_finding_can_be_converted_to_detection_alert():
    events = [
        make_auth_event("2026-10-10T09:00:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:01:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:02:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:03:00+00:00", "success"),
    ]

    finding = CorrelationEngine().detect_login_brute_force(events)[0]
    success_event = events[-1]

    alert = DetectionAlert(
        rule_id=finding["rule_id"],
        rule_name=finding["rule_name"],
        severity=finding["severity"],
        description=finding["description"],
        event_id=success_event.event_id,
        event_type=success_event.event_type,
        source=success_event.source,
        host=finding["host"],
        timestamp=success_event.timestamp,
        mitre_tactics=finding["mitre_tactics"],
        mitre_techniques=finding["mitre_techniques"],
        evidence={
            "username": finding["username"],
            "source_ip": finding["source_ip"],
            "failure_count": finding["failure_count"],
            "correlated_event_ids": finding["event_ids"],
        },
    )

    result = alert.to_dict()

    assert result["rule_id"] == "COR-001"
    assert result["severity"] == "high"
    assert result["evidence"]["failure_count"] == 3
    assert result["mitre_techniques"] == ["T1110"]