import json
from dataclasses import replace
from urllib.error import URLError
from unittest.mock import MagicMock, patch

import pytest

from detection.detection_engine import DetectionEngine
from detection.event_schema import ProcessInfo, SecurityEvent
from soar.n8n_webhook import N8nWebhookClient


def make_alert():
    event = SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-server",
        process=ProcessInfo(
            name="bash",
            command_line="bash -c whoami",
        ),
    )
    return DetectionEngine().evaluate(event)[0]


def test_sends_alert_as_json_post_to_n8n():
    alert = make_alert()
    response = MagicMock()
    response.__enter__.return_value.status = 200
    client = N8nWebhookClient(
        "http://localhost:5678/webhook/soc-alerts",
        timeout=8,
    )

    with patch("soar.n8n_webhook.urlopen", return_value=response) as urlopen:
        assert client.send_alert(alert) == 200

    request = urlopen.call_args.args[0]
    payload = json.loads(request.data.decode("utf-8"))
    assert request.full_url == "http://localhost:5678/webhook/soc-alerts"
    assert request.method == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert payload["source"] == "ebpf-autonomous-threat-hunting-soc"
    assert payload["alert"]["rule_id"] == "DET-001"
    assert payload["alert"]["host"] == "test-server"
    assert urlopen.call_args.kwargs["timeout"] == 8


@pytest.mark.parametrize(
    ("severity", "alert_id"),
    [
        ("high", "TEST-HIGH-001"),
        ("medium", "TEST-MEDIUM-001"),
    ],
)
def test_sends_high_and_medium_alert_fields_without_loss(severity, alert_id):
    alert = replace(make_alert(), severity=severity, alert_id=alert_id)
    response = MagicMock()
    response.__enter__.return_value.status = 200
    client = N8nWebhookClient("http://localhost/webhook")

    with patch("soar.n8n_webhook.urlopen", return_value=response) as urlopen:
        assert client.send_alert(alert) == 200

    payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
    assert payload["alert"]["alert_id"] == alert_id
    assert payload["alert"]["severity"] == severity
    assert payload["alert"]["rule_id"] == "DET-001"
    assert payload["alert"]["host"] == "test-server"


@pytest.mark.parametrize(
    "webhook_url",
    [
        "localhost:5678/webhook/soc-alerts",
        "ftp://localhost/webhook/soc-alerts",
        "https:///webhook/soc-alerts",
        "https://user:password@example.test/webhook",
        "https://example.test/webhook#fragment",
    ],
)
def test_rejects_invalid_webhook_url(webhook_url):
    with pytest.raises(ValueError):
        N8nWebhookClient(webhook_url)


def test_rejects_nonpositive_timeout():
    with pytest.raises(ValueError, match="timeout"):
        N8nWebhookClient("http://localhost/webhook", timeout=0)


def test_from_env_requires_webhook_url(monkeypatch):
    monkeypatch.delenv("N8N_WEBHOOK_URL", raising=False)

    with pytest.raises(ValueError, match="N8N_WEBHOOK_URL"):
        N8nWebhookClient.from_env()


def test_send_alerts_posts_each_alert():
    client = N8nWebhookClient("http://localhost/webhook")
    alerts = [make_alert(), make_alert()]

    with patch.object(client, "send_alert", return_value=200) as send_alert:
        assert client.send_alerts(alerts) == [200, 200]

    assert send_alert.call_count == 2


def test_network_errors_are_surfaced_to_the_caller():
    client = N8nWebhookClient("http://localhost/webhook")

    with patch(
        "soar.n8n_webhook.urlopen",
        side_effect=URLError("n8n is unavailable"),
    ):
        with pytest.raises(URLError, match="n8n is unavailable"):
            client.send_alert(make_alert())
