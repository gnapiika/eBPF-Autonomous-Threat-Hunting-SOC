from unittest.mock import Mock

from detection.detection_engine import DetectionEngine
from detection.event_schema import ProcessInfo, SecurityEvent
from soar.detection_integration import DetectionSoarIntegration


def make_suspicious_event():
    return SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-server",
        process=ProcessInfo(
            name="bash",
            command_line="bash -c whoami",
        ),
    )


def test_process_events_forwards_detection_alerts_to_soar():
    webhook_client = Mock()
    webhook_client.send_alerts.return_value = [200]
    integration = DetectionSoarIntegration(
        detection_engine=DetectionEngine(),
        webhook_client=webhook_client,
    )

    alerts = integration.process_events([make_suspicious_event()])

    assert len(alerts) == 1
    assert alerts[0].rule_id == "DET-001"
    webhook_client.send_alerts.assert_called_once_with(alerts)


def test_process_events_does_not_create_alerts_for_benign_events():
    webhook_client = Mock()
    integration = DetectionSoarIntegration(
        detection_engine=DetectionEngine(),
        webhook_client=webhook_client,
    )
    benign_event = SecurityEvent(
        event_type="authentication",
        source="test",
        host="test-server",
    )

    assert integration.process_events([benign_event]) == []
    webhook_client.send_alerts.assert_called_once_with([])
