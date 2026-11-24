import json
from io import BytesIO
from urllib.error import HTTPError, URLError
from unittest.mock import MagicMock, Mock, patch

import pytest

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer
from detection.event_schema import ProcessInfo, SecurityEvent
from soar.elasticsearch_ingestion import (
    ElasticsearchIngestionError,
    ElasticsearchIngestor,
)
from telemetry import kafka_detection_consumer as consumer


def make_event():
    return SecurityEvent(
        event_id="event-123",
        event_type="process_execution",
        source="falco",
        host="lab-host",
        timestamp="2026-11-13T14:00:00Z",
        process=ProcessInfo(name="bash", command_line="bash -c demo"),
    )


def make_alert():
    return DetectionEngine().evaluate(make_event())[0]


def successful_response(status=201):
    response = MagicMock()
    response.__enter__.return_value.status = status
    return response


def suspicious_falco_event():
    return {
        "time": "2026-11-13T14:00:00Z",
        "hostname": "lab-host",
        "rule": "Synthetic Lab Shell Execution",
        "priority": "Notice",
        "output_fields": {
            "proc.name": "bash",
            "proc.pid": 4242,
            "proc.cmdline": "bash -c synthetic-demo",
        },
    }


def test_indexes_canonical_event_to_events_index_with_stable_id():
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")
    event = make_event()

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(),
    ) as urlopen:
        assert ingestor.index_event(event) == 201
        assert ingestor.index_event(event) == 201

    first_request = urlopen.call_args_list[1].args[0]
    second_request = urlopen.call_args_list[2].args[0]
    create_index_request = urlopen.call_args_list[0].args[0]
    assert create_index_request.full_url.endswith("/security-events")
    mappings = json.loads(create_index_request.data.decode("utf-8"))[
        "mappings"
    ]["properties"]
    assert mappings["@timestamp"] == {"type": "date"}
    assert mappings["severity"] == {"type": "keyword"}
    assert mappings["process"]["properties"]["name"] == {
        "type": "keyword"
    }
    assert first_request.full_url.startswith(
        "http://es.example.test:9200/security-events/_doc/"
    )
    assert first_request.full_url == second_request.full_url
    assert first_request.method == "PUT"
    payload = json.loads(first_request.data.decode("utf-8"))
    assert payload["@timestamp"] == payload["timestamp"]
    assert payload["event_id"] == "event-123"
    assert payload["process"]["name"] == payload["process_name"] == "bash"


def test_indexes_alert_with_response_and_external_workflow_status():
    ingestor = ElasticsearchIngestor(
        "http://es.example.test:9200",
        alerts_index="soc-alerts",
    )
    alert = make_alert()
    response_package = {
        "alert_id": alert.alert_id,
        "response_status": "simulated",
        "evidence": {"evidence_id": "evidence-event-123"},
        "response_plan": {
            "mode": "dry_run",
            "approval_required": True,
            "execution_performed": False,
            "actions": [],
        },
    }

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(),
    ) as urlopen:
        assert ingestor.index_alert(
            alert,
            response_package=response_package,
            external_workflow={
                "provider": "n8n",
                "delivery_status": "request_accepted",
                "result_received": False,
            },
        ) == 201

    request = urlopen.call_args.args[0]
    assert "/soc-alerts/_doc/" in request.full_url
    alert_mapping_request = urlopen.call_args_list[0].args[0]
    alert_mappings = json.loads(alert_mapping_request.data.decode("utf-8"))[
        "mappings"
    ]["properties"]
    assert alert_mappings["@timestamp"] == {"type": "date"}
    assert alert_mappings["response_status"] == {"type": "keyword"}
    assert alert_mappings["evidence_available"] == {"type": "boolean"}
    payload = json.loads(request.data.decode("utf-8"))
    assert payload["alert_id"] == alert.alert_id
    assert payload["event_id"] == alert.event_id
    assert payload["@timestamp"] == payload["timestamp"]
    assert payload["mitre"]["tactics"][0] == {
        "id": "TA0002",
        "name": "Execution",
    }
    assert payload["response"] == response_package
    assert payload["response_status"] == "simulated"
    assert payload["evidence_available"] is True
    assert payload["external_workflow"]["result_received"] is False


def test_alert_without_response_marks_evidence_unavailable():
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(),
    ) as urlopen:
        ingestor.index_alert(make_alert())

    payload = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
    assert payload["evidence_available"] is False
    assert payload["external_workflow"] == {
        "provider": "n8n",
        "delivery_status": "not_configured",
        "result_received": False,
    }


def test_reports_http_and_connection_failures():
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(503),
    ):
        with pytest.raises(ElasticsearchIngestionError, match="HTTP 503"):
            ingestor.index_event(make_event())

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        side_effect=HTTPError(
            "http://es.example.test",
            503,
            "unavailable",
            {},
            None,
        ),
    ):
        with pytest.raises(ElasticsearchIngestionError, match="HTTP 503"):
            ingestor.index_event(make_event())

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        side_effect=URLError("connection refused"),
    ):
        with pytest.raises(
            ElasticsearchIngestionError,
            match="request failed",
        ):
            ingestor.index_alert(make_alert())


def test_existing_index_receives_compatible_p1_mapping():
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")
    already_exists = HTTPError(
        "http://es.example.test/security-events",
        400,
        "already exists",
        {},
        BytesIO(
            b'{"error":{"type":"resource_already_exists_exception"}}'
        ),
    )

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        side_effect=[
            already_exists,
            successful_response(200),
            successful_response(201),
        ],
    ) as urlopen:
        assert ingestor.index_event(make_event()) == 201

    assert urlopen.call_count == 3
    assert urlopen.call_args_list[1].args[0].full_url.endswith(
        "/security-events/_mapping"
    )


def test_rejects_invalid_index_and_conflicting_authentication():
    with pytest.raises(ValueError, match="index name"):
        ElasticsearchIngestor(
            "http://es.example.test:9200",
            events_index="Invalid Index",
        )

    with pytest.raises(ValueError, match="either an API key"):
        ElasticsearchIngestor(
            "http://es.example.test:9200",
            username="soc",
            password="secret",
            api_key="key",
        )


def test_from_env_is_optional_and_reads_index_settings(monkeypatch):
    monkeypatch.delenv("ELASTICSEARCH_URL", raising=False)
    assert ElasticsearchIngestor.from_env() is None

    monkeypatch.setenv("ELASTICSEARCH_URL", "https://es.example.test")
    monkeypatch.setenv("ELASTICSEARCH_EVENTS_INDEX", "events-v1")
    monkeypatch.setenv("ELASTICSEARCH_ALERTS_INDEX", "alerts-v1")
    monkeypatch.setenv("ELASTICSEARCH_API_KEY", "local-test-key")

    ingestor = ElasticsearchIngestor.from_env()

    assert ingestor is not None
    assert ingestor.events_index == "events-v1"
    assert ingestor.alerts_index == "alerts-v1"
    assert ingestor.api_key == "local-test-key"


def test_kafka_consumer_indexes_event_and_alert_idempotently(
    monkeypatch,
    tmp_path,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")
    integration = Mock()
    ledger = consumer.ForwardedAlertLedger(
        str(tmp_path / "forwarded.sqlite3")
    )
    raw_event = suspicious_falco_event()

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(),
    ) as urlopen:
        for _ in range(2):
            assert consumer.process_message(
                raw_event,
                EventNormalizer(),
                DetectionEngine(),
                soar_integration=integration,
                forwarded_ledger=ledger,
                message_key="security-events:0:77",
                elasticsearch_ingestor=ingestor,
            ) == 1

    assert urlopen.call_count == 6
    requests = [call.args[0] for call in urlopen.call_args_list]
    assert requests[1].full_url == requests[4].full_url
    assert requests[3].full_url == requests[5].full_url
    assert "/security-events/_doc/" in requests[1].full_url
    assert "/security-alerts/_doc/" in requests[3].full_url
    first_alert_document = json.loads(requests[3].data.decode("utf-8"))
    assert first_alert_document["response_status"] == "simulated"
    assert first_alert_document["response"]["response_plan"][
        "execution_performed"
    ] is False
    assert first_alert_document["external_workflow"]["result_received"] is False
    assert integration.forward_alerts.call_count == 1
    logged_alerts = output_file.read_text(encoding="utf-8").splitlines()
    assert len(logged_alerts) == 2


def test_elasticsearch_unavailable_does_not_stop_kafka_detection(
    monkeypatch,
    tmp_path,
    caplog,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        side_effect=URLError("connection refused"),
    ):
        assert consumer.process_message(
            suspicious_falco_event(),
            EventNormalizer(),
            DetectionEngine(),
            elasticsearch_ingestor=ingestor,
        ) == 1

    assert "Elasticsearch event indexing failed" in caplog.text
    assert "Elasticsearch alert indexing failed" in caplog.text
    assert json.loads(output_file.read_text(encoding="utf-8"))["rule_id"] == (
        "DET-001"
    )


def test_webhook_failure_is_separate_from_simulated_response_indexing(
    monkeypatch,
    tmp_path,
):
    output_file = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(consumer, "OUTPUT_FILE", str(output_file))
    ingestor = ElasticsearchIngestor("http://es.example.test:9200")
    integration = Mock()
    integration.forward_alerts.side_effect = URLError("n8n unavailable")

    with patch(
        "soar.elasticsearch_ingestion.urlopen",
        return_value=successful_response(),
    ) as urlopen:
        assert consumer.process_message(
            suspicious_falco_event(),
            EventNormalizer(),
            DetectionEngine(),
            soar_integration=integration,
            elasticsearch_ingestor=ingestor,
        ) == 1

    alert_document = json.loads(
        urlopen.call_args.args[0].data.decode("utf-8")
    )
    assert alert_document["response_status"] == "simulated"
    assert alert_document["external_workflow"] == {
        "provider": "n8n",
        "delivery_status": "request_failed",
        "result_received": False,
    }
    assert output_file.exists()
