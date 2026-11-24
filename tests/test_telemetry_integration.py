import importlib
import json
from unittest.mock import MagicMock, patch

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer
from soar.detection_integration import DetectionSoarIntegration
from soar.n8n_webhook import N8nWebhookClient
from telemetry import kafka_detection_consumer as consumer


def test_simple_event_generator_uses_configured_falco_path(monkeypatch, tmp_path):
    output_file = tmp_path / "falco-events.json"
    monkeypatch.setenv("FALCO_EVENTS_FILE", str(output_file))

    import telemetry.simple_event as simple_event

    importlib.reload(simple_event)
    returned_path = simple_event.write_sample_event()

    assert returned_path == output_file
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["rule"] == "Synthetic Lab Shell Execution"
    assert payload["output_fields"]["proc.name"] == "bash"
    assert payload["output_fields"]["proc.pid"] == 424242
    assert payload["output_fields"]["proc.cmdline"] == (
        "bash -c synthetic-demo"
    )


def test_generated_falco_event_normalizes_and_matches_detection_rule(
    monkeypatch,
    tmp_path,
):
    output_file = tmp_path / "falco-events.json"
    monkeypatch.setenv("FALCO_EVENTS_FILE", str(output_file))

    import telemetry.simple_event as simple_event

    importlib.reload(simple_event)
    simple_event.write_sample_event()

    raw_event = json.loads(output_file.read_text(encoding="utf-8"))
    event = EventNormalizer().normalize(raw_event, source="falco", host="lab-host")
    alerts = DetectionEngine().evaluate(event)

    assert event.source == "falco"
    assert event.event_type == "process_execution"
    assert event.severity == "low"
    assert event.process.name == "bash"
    assert event.process.pid == 424242
    assert event.process.command_line == "bash -c synthetic-demo"
    assert len(alerts) == 1

    alert = alerts[0].to_dict()
    assert alert["rule_id"] == "DET-001"
    assert alert["schema_version"] == "1.0"
    assert alert["alert_id"]
    assert alert["event_id"] == event.event_id
    assert alert["@timestamp"] == alert["timestamp"] == event.timestamp
    assert alert["severity"] == "medium"
    assert alert["source"] == "falco"
    assert alert["process"]["name"] == alert["process_name"] == "bash"
    assert alert["mitre"]["tactics"] == [
        {"id": "TA0002", "name": "Execution"}
    ]
    assert alert["mitre"]["techniques"] == [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
        }
    ]
    assert alert["evidence"]["process"]["pid"] == 424242


def test_generated_falco_alert_reaches_soar_and_is_logged(
    monkeypatch,
    tmp_path,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    event_file = tmp_path / "falco-events.json"
    monkeypatch.setenv("FALCO_EVENTS_FILE", str(event_file))

    import telemetry.simple_event as simple_event

    importlib.reload(simple_event)
    simple_event.write_sample_event()
    raw_event = json.loads(event_file.read_text(encoding="utf-8"))
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
        assert consumer.process_message(
            raw_event,
            EventNormalizer(),
            DetectionEngine(),
            soar_integration=integration,
        ) == 1

    payload = json.loads(
        urlopen.call_args.args[0].data.decode("utf-8")
    )
    assert payload["alert"]["rule_id"] == "DET-001"
    assert payload["alert"]["source"] == "falco"
    assert payload["alert"]["process"]["name"] == "bash"
    assert payload["alert"]["mitre"]["techniques"][0]["id"] == "T1059"
    assert payload["response"]["response_status"] == "simulated"
    assert payload["response"]["response_plan"]["execution_performed"] is False
    logged_alert = json.loads(output_file.read_text(encoding="utf-8"))
    assert logged_alert["alert_id"] == payload["alert"]["alert_id"]
    assert logged_alert["event_id"] == payload["alert"]["event_id"]
    assert logged_alert["mitre"]["techniques"][0]["id"] == "T1059"
