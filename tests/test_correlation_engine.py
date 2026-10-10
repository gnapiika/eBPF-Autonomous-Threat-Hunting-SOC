
import pytest

from detection.correlation.correlation_engine import CorrelationEngine
from detection.event_schema import NetworkInfo, SecurityEvent, UserInfo


def make_auth_event(
    timestamp,
    outcome,
    username="admin",
    source_ip="192.168.1.50",
):
    return SecurityEvent(
        event_type="authentication",
        source="test",
        host="test-host",
        timestamp=timestamp,
        user=UserInfo(username=username),
        network=NetworkInfo(source_ip=source_ip),
        raw_event={"outcome": outcome},
    )


def test_detects_repeated_failures_followed_by_success():
    events = [
        make_auth_event("2026-10-10T09:00:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:02:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:04:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:05:00+00:00", "success"),
    ]

    findings = CorrelationEngine().detect_login_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "COR-001"
    assert findings[0]["severity"] == "high"
    assert findings[0]["failure_count"] == 3
    assert findings[0]["username"] == "admin"
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert len(findings[0]["event_ids"]) == 4


def test_ignores_success_without_enough_failures():
    events = [
        make_auth_event("2026-10-10T09:00:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:02:00+00:00", "success"),
    ]

    findings = CorrelationEngine().detect_login_brute_force(events)

    assert findings == []


def test_ignores_failures_outside_time_window():
    events = [
        make_auth_event("2026-10-10T08:00:00+00:00", "failure"),
        make_auth_event("2026-10-10T08:01:00+00:00", "failure"),
        make_auth_event("2026-10-10T08:02:00+00:00", "failure"),
        make_auth_event("2026-10-10T09:00:00+00:00", "success"),
    ]

    findings = CorrelationEngine().detect_login_brute_force(events)

    assert findings == []


def test_does_not_correlate_different_source_ips():
    events = [
        make_auth_event(
            "2026-10-10T09:00:00+00:00",
            "failure",
            source_ip="10.0.0.1",
        ),
        make_auth_event(
            "2026-10-10T09:01:00+00:00",
            "failure",
            source_ip="10.0.0.1",
        ),
        make_auth_event(
            "2026-10-10T09:02:00+00:00",
            "failure",
            source_ip="10.0.0.1",
        ),
        make_auth_event(
            "2026-10-10T09:03:00+00:00",
            "success",
            source_ip="10.0.0.2",
        ),
    ]

    findings = CorrelationEngine().detect_login_brute_force(events)

    assert findings == []


def test_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        CorrelationEngine(failure_threshold=0)

    with pytest.raises(ValueError):
        CorrelationEngine(window_minutes=0)