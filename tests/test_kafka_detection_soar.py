import json
from unittest.mock import MagicMock, Mock, patch
from urllib.error import URLError

import pytest

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer
from detection.event_schema import ProcessInfo, SecurityEvent
from soar.detection_integration import DetectionSoarIntegration
from soar.n8n_webhook import N8nWebhookClient
from telemetry import kafka_detection_consumer as consumer


def suspicious_tetragon_event():
    return {
        "source": "tetragon",
        "host": "lab-host",
        "type": "process_exec",
        "time": "2026-11-13T10:00:00Z",
        "process": {
            "pid": 4242,
            "name": "bash",
            "binary": "/bin/bash",
            "arguments": "bash -c whoami",
            "parent": {
                "pid": 1000,
                "name": "sshd",
                "binary": "/usr/sbin/sshd",
            },
        },
    }


def make_suspicious_event():
    return SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="lab-host",
        process=ProcessInfo(
            pid=4242,
            name="bash",
            executable="/bin/bash",
            command_line="bash -c whoami",
            parent_name="sshd",
        ),
    )


def test_kafka_detection_alert_is_logged_and_forwarded_once(
    monkeypatch,
    tmp_path,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    integration = Mock()
    ledger_path = str(tmp_path / "forwarded.sqlite3")

    for _ in range(2):
        ledger = consumer.ForwardedAlertLedger(ledger_path)
        assert consumer.process_message(
            suspicious_tetragon_event(),
            EventNormalizer(),
            DetectionEngine(),
            soar_integration=integration,
            forwarded_ledger=ledger,
            message_key="security-events:0:12",
        ) == 1

    integration.forward_alerts.assert_called_once()
    alert = integration.forward_alerts.call_args.args[0][0]
    events = integration.forward_alerts.call_args.args[1]
    assert alert.rule_id == "DET-001"
    assert alert.alert_id
    assert alert.severity == "medium"
    assert alert.source == "tetragon"
    assert alert.mitre_tactics == ["Execution"]
    assert alert.mitre_techniques == ["T1059"]
    assert alert.evidence["process"]["pid"] == 4242
    assert events[0].host == "lab-host"

    logged_alerts = [
        json.loads(line)
        for line in output_file.read_text(encoding="utf-8").splitlines()
    ]
    assert len(logged_alerts) == 2
    assert logged_alerts[0]["alert_id"]
    assert logged_alerts[0]["evidence"]["process"]["pid"] == 4242


def test_webhook_receives_alert_evidence_and_simulated_response():
    event = make_suspicious_event()
    response = MagicMock()
    response.__enter__.return_value.status = 200
    integration = DetectionSoarIntegration(
        DetectionEngine(),
        N8nWebhookClient("http://localhost:5678/webhook/soc-alerts"),
    )

    with patch(
        "soar.n8n_webhook.urlopen",
        return_value=response,
    ) as urlopen:
        alerts = integration.process_events([event])

    assert len(alerts) == 1
    payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
    alert_payload = payload["alert"]
    response_payload = payload["response"]
    assert alert_payload["alert_id"] == alerts[0].alert_id
    assert alert_payload["severity"] == "medium"
    assert alert_payload["source"] == "tetragon"
    assert alert_payload["mitre_tactics"] == ["Execution"]
    assert alert_payload["mitre_techniques"] == ["T1059"]
    assert alert_payload["evidence"]["process"]["pid"] == 4242
    assert response_payload["alert_id"] == alerts[0].alert_id
    assert response_payload["response_status"] == "simulated"
    assert response_payload["evidence"]["alert"]["alert_id"] == (
        alerts[0].alert_id
    )
    assert response_payload["evidence"]["process_information"][0]["pid"] == (
        4242
    )
    assert response_payload["response_plan"]["mode"] == "dry_run"
    assert response_payload["response_plan"]["approval_required"] is True
    assert response_payload["response_plan"]["execution_performed"] is False
    assert all(
        action["status"] == "simulated"
        for action in response_payload["response_plan"]["actions"]
    )


def test_webhook_failure_is_logged_and_alert_remains_persisted(
    monkeypatch,
    tmp_path,
    caplog,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    integration = Mock()
    integration.forward_alerts.side_effect = URLError("n8n unavailable")
    ledger = consumer.ForwardedAlertLedger(str(tmp_path / "forwarded.sqlite3"))

    assert consumer.process_message(
        suspicious_tetragon_event(),
        EventNormalizer(),
        DetectionEngine(),
        soar_integration=integration,
        forwarded_ledger=ledger,
        message_key="security-events:0:13",
    ) == 1

    integration.forward_alerts.assert_called_once()
    assert "SOAR forwarding failed" in caplog.text
    logged_alert = json.loads(output_file.read_text(encoding="utf-8"))
    assert logged_alert["rule_id"] == "DET-001"
    assert not ledger.was_forwarded("security-events:0:13", "DET-001")


def test_unmatched_event_is_not_logged_or_forwarded(monkeypatch, tmp_path):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    integration = Mock()
    benign_event = {
        "source": "tetragon",
        "host": "lab-host",
        "type": "process_exec",
        "process": {"pid": 1, "name": "init", "arguments": "init"},
    }

    assert consumer.process_message(
        benign_event,
        EventNormalizer(),
        DetectionEngine(),
        soar_integration=integration,
    ) == 0

    integration.forward_alerts.assert_not_called()
    assert not output_file.exists()


def test_non_success_webhook_status_is_reported():
    response = MagicMock()
    response.__enter__.return_value.status = 503
    client = N8nWebhookClient("http://localhost:5678/webhook/soc-alerts")
    alert = DetectionEngine().evaluate(make_suspicious_event())[0]

    with patch("soar.n8n_webhook.urlopen", return_value=response):
        with pytest.raises(RuntimeError, match="503"):
            client.send_alert(alert)
