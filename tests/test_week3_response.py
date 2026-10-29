import pytest

from detection.detection_engine import DetectionAlert, DetectionEngine
from detection.event_schema import (
    FileInfo,
    NetworkInfo,
    ProcessInfo,
    SecurityEvent,
)
from forensic.evidence_collection.collector import ForensicEvidenceCollector
from soar.response.week3_workflow import Week3ResponseWorkflow


def make_event(
    event_id,
    pid,
    ppid=None,
    event_type="process_execution",
    raw_event=None,
):
    return SecurityEvent(
        event_id=event_id,
        event_type=event_type,
        source="test",
        host="lab-host",
        timestamp=f"2026-10-26T10:00:0{pid % 10}+00:00",
        process=ProcessInfo(
            pid=pid,
            ppid=ppid,
            name=f"process-{pid}",
            executable=f"/usr/bin/process-{pid}",
            command_line=f"process-{pid} --test",
            parent_name=f"process-{ppid}" if ppid else None,
        ),
        network=NetworkInfo(
            source_ip="192.0.2.10",
            source_port=50000,
            destination_ip="198.51.100.20",
            destination_port=443,
            protocol="TCP",
        ),
        file=FileInfo(
            path="/tmp/test-artifact",
            operation="write",
            hash_sha256="a" * 64,
        ),
        raw_event=raw_event or {},
    )


def make_alert():
    return DetectionAlert(
        alert_id="alert-123",
        rule_id="DET-001",
        rule_name="Suspicious Shell Execution",
        severity="high",
        description="Test alert",
        event_id="event-child",
        event_type="process_execution",
        source="test",
        host="lab-host",
        timestamp="2026-10-26T10:00:03+00:00",
        evidence={
            "process": {"pid": 123, "name": "process-123"},
            "network": {"destination_ip": "198.51.100.20"},
        },
    )


def test_collector_captures_requested_evidence_and_process_tree():
    events = [
        make_event("event-parent", 100),
        make_event(
            "event-child",
            123,
            ppid=100,
            raw_event={"message": "process observed", "timestamp": "source-time"},
        ),
    ]

    bundle = ForensicEvidenceCollector().collect(events, alert=make_alert())

    assert bundle["host"] == "lab-host"
    assert bundle["alert"]["alert_id"] == "alert-123"
    assert bundle["event_ids"] == ["event-parent", "event-child"]
    assert bundle["timestamps"][1]["timestamp"] == events[1].timestamp
    assert bundle["process_information"][1]["pid"] == 123
    assert bundle["network_connections"][0]["destination_ip"] == "198.51.100.20"
    assert bundle["file_information"][0]["hash_sha256"] == "a" * 64
    assert bundle["relevant_logs"][0]["raw_event"]["message"] == "process observed"

    parent = next(node for node in bundle["process_tree"] if node["pid"] == 100)
    child = next(node for node in bundle["process_tree"] if node["pid"] == 123)
    assert parent["child_pids"] == [123]
    assert child["ppid"] == parent["pid"]
    assert bundle["coverage"]["process_tree_node_count"] == 2


def test_response_workflow_plans_but_never_executes_containment():
    result = Week3ResponseWorkflow().process_alert(
        make_alert(),
        [make_event("event-child", 123, ppid=100)],
    )

    plan = result["response_plan"]
    assert result["response_status"] == "simulated"
    assert plan["mode"] == "dry_run"
    assert plan["approval_required"] is True
    assert plan["execution_performed"] is False
    assert [action["action"] for action in plan["actions"]] == [
        "process_isolation",
        "network_containment",
    ]
    assert plan["actions"][0]["target"] == {"host": "lab-host", "pid": 123}
    assert plan["actions"][1]["target"]["destination_ip"] == "198.51.100.20"


def test_response_planner_omits_actions_without_valid_targets():
    alert = make_alert()
    alert.evidence = {
        "process": {"pid": -1},
        "network": {"destination_ip": "not-an-ip"},
    }

    plan = Week3ResponseWorkflow._plan_containment(alert)

    assert plan["actions"] == []
    assert plan["execution_performed"] is False


def test_process_events_connects_detection_to_evidence_and_response():
    event = make_event("suspicious-shell", 123, ppid=100)
    event.process.name = "bash"
    event.process.command_line = "bash -c whoami"

    packages = Week3ResponseWorkflow().process_events(
        DetectionEngine(),
        [event],
    )

    assert len(packages) == 1
    assert packages[0]["evidence"]["alert"]["rule_id"] == "DET-001"
    assert packages[0]["evidence"]["event_ids"] == ["suspicious-shell"]
    assert packages[0]["response_plan"]["execution_performed"] is False
    assert packages[0]["response_plan"]["actions"][0]["action"] == (
        "process_isolation"
    )


def test_collector_requires_events():
    with pytest.raises(ValueError, match="at least one"):
        ForensicEvidenceCollector().collect([])


def test_collector_rejects_non_security_events():
    with pytest.raises(TypeError, match="SecurityEvent"):
        ForensicEvidenceCollector().collect([{"event_type": "test"}])


def test_collector_reports_missing_telemetry_without_fabricating_values():
    event = SecurityEvent(
        event_id="sparse-event",
        event_type="authentication",
        source="test",
        host="lab-host",
        timestamp="2026-10-26T10:00:00+00:00",
    )

    bundle = ForensicEvidenceCollector().collect([event])

    assert bundle["process_information"] == []
    assert bundle["process_tree"] == []
    assert bundle["network_connections"] == []
    assert bundle["file_information"] == []
    assert bundle["relevant_logs"] == []
    assert bundle["timestamps"][0]["timestamp"] == event.timestamp
    assert bundle["coverage"] == {
        "event_count": 1,
        "process_event_count": 0,
        "network_event_count": 0,
        "file_event_count": 0,
        "log_context_event_count": 0,
        "process_tree_node_count": 0,
    }


def test_collector_rejects_mixed_host_events():
    first = make_event("host-one-event", 100)
    second = make_event("host-two-event", 101)
    second.host = "other-host"

    with pytest.raises(ValueError, match="one host"):
        ForensicEvidenceCollector().collect([first, second])
