import pytest
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
    webhook_client.send_alerts.assert_called_once()
    sent_alerts = webhook_client.send_alerts.call_args.args[0]
    response_packages = webhook_client.send_alerts.call_args.kwargs[
        "response_packages"
    ]
    assert sent_alerts == alerts
    assert response_packages[0]["alert_id"] == alerts[0].alert_id
    assert response_packages[0]["response_status"] == "simulated"
    assert response_packages[0]["evidence"]["alert"]["alert_id"] == (
        alerts[0].alert_id
    )
    assert response_packages[0]["response_plan"]["execution_performed"] is False


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
    webhook_client.send_alerts.assert_called_once_with(
        [],
        response_packages=[],
    )


def test_forward_alerts_reuses_prebuilt_response_packages():
    webhook_client = Mock()
    response_workflow = Mock()
    integration = DetectionSoarIntegration(
        detection_engine=DetectionEngine(),
        webhook_client=webhook_client,
        response_workflow=response_workflow,
    )
    event = make_suspicious_event()
    alert = DetectionEngine().evaluate(event)[0]
    response_package = {
        "alert_id": alert.alert_id,
        "response_status": "simulated",
    }

    integration.forward_alerts(
        [alert],
        [event],
        response_packages=[response_package],
    )

    response_workflow.process_alert.assert_not_called()
    webhook_client.send_alerts.assert_called_once_with(
        [alert],
        response_packages=[response_package],
    )


def test_forward_alerts_rejects_mismatched_response_packages():
    integration = DetectionSoarIntegration(
        detection_engine=DetectionEngine(),
        webhook_client=Mock(),
    )
    alert = DetectionEngine().evaluate(make_suspicious_event())[0]

    with pytest.raises(ValueError, match="match the alerts length"):
        integration.forward_alerts(
            [alert],
            response_packages=[],
        )
