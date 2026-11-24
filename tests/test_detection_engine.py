
from detection.detection_engine import DetectionEngine
from detection.event_schema import (
    NetworkInfo,
    ProcessInfo,
    SecurityEvent,
)


def make_process_event(
    name="bash",
    command_line="bash -c whoami",
):
    return SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-server",
        process=ProcessInfo(
            pid=1234,
            name=name,
            executable=f"/usr/bin/{name}",
            command_line=command_line,
            parent_name="sshd",
        ),
    )


def test_suspicious_shell_execution_generates_alert():
    engine = DetectionEngine()
    event = make_process_event(
        name="bash",
        command_line="bash -c whoami",
    )

    alerts = engine.evaluate(event)

    assert any(alert.rule_id == "DET-001" for alert in alerts)


def test_alert_contains_event_context():
    engine = DetectionEngine()
    event = make_process_event()

    alerts = engine.evaluate(event)
    alert = next(
        alert for alert in alerts if alert.rule_id == "DET-001"
    )

    assert alert.host == "test-server"
    assert alert.source == "tetragon"
    assert alert.evidence["process"]["name"] == "bash"
    assert alert.mitre_techniques == ["T1059"]


def test_normal_shell_without_suspicious_pattern_does_not_match_shell_rule():
    engine = DetectionEngine()
    event = make_process_event(
        name="bash",
        command_line="bash",
    )

    alerts = engine.evaluate(event)

    assert not any(alert.rule_id == "DET-001" for alert in alerts)


def test_unusual_network_port_generates_alert():
    engine = DetectionEngine()

    event = SecurityEvent(
        event_type="network_connection",
        source="ebpf",
        host="test-server",
        network=NetworkInfo(
            source_ip="10.0.0.10",
            destination_ip="10.0.0.20",
            destination_port=4444,
            protocol="TCP",
        ),
    )

    alerts = engine.evaluate(event)

    assert any(alert.rule_id == "DET-003" for alert in alerts)


def test_unrelated_event_does_not_trigger_default_rules():
    engine = DetectionEngine()

    event = SecurityEvent(
        event_type="authentication",
        source="custom_source",
        host="test-server",
    )

    alerts = engine.evaluate(event)

    assert alerts == []


def test_evaluate_many_processes_multiple_events():
    engine = DetectionEngine()

    events = [
        make_process_event(
            name="bash",
            command_line="bash -c whoami",
        ),
        SecurityEvent(
            event_type="authentication",
            source="custom_source",
            host="test-server",
        ),
    ]

    alerts = engine.evaluate_many(events)

    assert any(alert.rule_id == "DET-001" for alert in alerts)


def test_alert_serializes_to_dictionary():
    engine = DetectionEngine()
    event = make_process_event()

    alerts = engine.evaluate(event)
    alert = next(
        alert for alert in alerts if alert.rule_id == "DET-001"
    )

    result = alert.to_dict()

    assert result["rule_id"] == "DET-001"
    assert result["severity"] == "medium"
    assert result["alert_id"]
    assert result["@timestamp"] == result["timestamp"] == alert.timestamp
    assert result["timestamp_source"] == "ingest"
    assert result["process"]["name"] == result["process_name"] == "bash"
    assert result["mitre"] == {
        "tactics": [{"id": "TA0002", "name": "Execution"}],
        "techniques": [
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
            }
        ],
    }


def test_alert_normalizes_timestamp_and_severity_aliases():
    event = SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-server",
        timestamp="2026-03-01T10:00:00+02:00",
        process=ProcessInfo(
            name="bash",
            command_line="bash -c whoami",
        ),
    )
    alert = DetectionEngine().evaluate(event)[0]
    alert.severity = "Warning"

    result = alert.to_dict()

    assert result["@timestamp"] == "2026-03-01T08:00:00.000Z"
    assert result["timestamp"] == result["@timestamp"]
    assert result["timestamp_source"] == "event"
    assert result["severity"] == "medium"