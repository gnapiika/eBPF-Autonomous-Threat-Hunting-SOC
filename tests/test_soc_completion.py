import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError

import pytest
from kafka.structs import OffsetAndMetadata, TopicPartition

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer
from detection.event_schema import SOC_PRODUCER
from scripts.soc_demo import prepare_branch_alert, replay_alert
from soar.elasticsearch_ingestion import ElasticsearchIngestor
from soar.n8n_webhook import webhook_error_message
from telemetry import kafka_detection_consumer as pipeline
from telemetry.falco.falco_kafka_forwarder import follow_events
from telemetry.simple_event import build_sample_event


ROOT = Path(__file__).resolve().parents[1]


def test_malformed_kafka_records_are_skipped_and_only_processed_offsets_committed(
    tmp_path, monkeypatch, caplog,
):
    alert_log = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(pipeline, "OUTPUT_FILE", str(alert_log))
    kafka = Mock()
    partition = TopicPartition("security-events", 0)
    another = TopicPartition("security-events", 1)
    valid = json.dumps(build_sample_event()).encode("utf-8")
    kafka.poll.return_value = {
        partition: [
            SimpleNamespace(offset=10, value=b"\xff"),
            SimpleNamespace(offset=11, value=b"{} invalid"),
            SimpleNamespace(offset=12, value=b"[]"),
            SimpleNamespace(offset=13, value=b'{"timestamp":"invalid"}'),
            SimpleNamespace(offset=14, value=b'{"process":{"name":[]}}'),
            SimpleNamespace(offset=15, value=valid),
        ],
        another: [SimpleNamespace(offset=2, value=b'{"type":"file_open"}')],
    }

    pipeline.consume_batch(kafka, EventNormalizer(), DetectionEngine())

    commits = [call.args[0] for call in kafka.commit.call_args_list]
    assert commits == [
        {partition: OffsetAndMetadata(offset, "")}
        for offset in range(11, 17)
    ] + [{another: OffsetAndMetadata(3, "")}]
    assert caplog.text.count("Skipping invalid event") == 5
    alert = json.loads(alert_log.read_text(encoding="utf-8"))
    assert alert["rule_id"] == "DET-001"
    assert alert["synthetic"] is True


def test_persistence_failure_stops_before_committing_failing_or_later_offsets(monkeypatch):
    kafka = Mock()
    partition = TopicPartition("security-events", 0)
    kafka.poll.return_value = {
        partition: [SimpleNamespace(offset=offset, value=b"{}") for offset in range(3)],
    }
    process = Mock(side_effect=[0, OSError("disk full"), 0])
    monkeypatch.setattr(pipeline, "process_message", process)
    with pytest.raises(OSError, match="disk full"):
        pipeline.consume_batch(kafka, EventNormalizer(), DetectionEngine())
    kafka.commit.assert_called_once_with({partition: OffsetAndMetadata(1, "")})
    assert process.call_count == 2


def test_tetragon_json_export_uses_node_process_and_parent():
    raw = {
        "node_name": "linux-node",
        "time": "2026-11-24T15:00:00.002123789+05:30",
        "process_exec": {
            "process": {"pid": 22, "uid": 1000, "binary": "/bin/bash", "arguments": "-c demo"},
            "parent": {"pid": 21, "binary": "/usr/bin/demo"},
        },
    }
    event = pipeline.normalize_record(raw, EventNormalizer())
    assert event.source == "tetragon"
    assert event.host == "linux-node"
    assert event.timestamp == "2026-11-24T09:30:00.002Z"
    assert event.process.name == "bash"
    assert event.process.ppid == 21
    assert event.process.parent_name == "demo"
    assert event.process.command_line == "/bin/bash -c demo"
    assert event.user.uid == 1000
    assert event.synthetic is False
    assert DetectionEngine().evaluate(event)[0].rule_id == "DET-001"


def test_network_and_file_shapes_and_canonical_round_trip():
    normalizer = EventNormalizer()
    network = pipeline.normalize_record(build_sample_event("network"), normalizer)
    file = pipeline.normalize_record(build_sample_event("file"), normalizer)
    assert network.event_type == "network_connection"
    assert network.network.destination_ip == "198.51.100.20"
    assert network.network.destination_port == 4444
    assert DetectionEngine().evaluate(network)[0].rule_id == "DET-003"
    assert file.event_type == "file_activity"
    assert file.file.operation == "openat"
    assert file.file.path == "/tmp/synthetic-demo.txt"
    assert file.producer == SOC_PRODUCER
    assert pipeline.normalize_record(file.to_dict(), normalizer).to_dict() == file.to_dict()


def test_real_falco_rule_shape_preserves_file_evidence_and_matches_det_004():
    raw = {
        "rule": "SOC Test File Write",
        "priority": "Notice",
        "source": "syscall",
        "output_fields": {
            "evt.hostname": "linux-sensor",
            "evt.type": "openat",
            "fd.name": "/tmp/soc-falco-test",
            "proc.name": "test-fixture",
        },
    }
    event = pipeline.normalize_record(raw, EventNormalizer())
    alert, = DetectionEngine().evaluate(event)
    assert alert.rule_id == "DET-004"
    assert alert.severity == "low"
    assert alert.synthetic is False
    assert event.host == "linux-sensor"
    assert alert.evidence["file"]["path"] == event.file.path == "/tmp/soc-falco-test"


def test_saved_alert_replay_preserves_evidence_and_updates_the_ledger(tmp_path, monkeypatch):
    path = tmp_path / "alerts.jsonl"
    monkeypatch.setattr(pipeline, "OUTPUT_FILE", str(path))
    engine = DetectionEngine()
    ledger = pipeline.ForwardedAlertLedger(str(tmp_path / "ledger.sqlite3"))
    key = "security-events:0:42"
    raw = build_sample_event("network")
    for _ in range(2):
        pipeline.process_message(raw, EventNormalizer(), engine, message_key=key)
    first, second = map(json.loads, path.read_text(encoding="utf-8").splitlines())
    assert first["alert_id"] == second["alert_id"]
    assert first["event_id"] == second["event_id"]
    client = Mock()
    client.send_alert_record.return_value = 200
    assert replay_alert(first["alert_id"], path, ledger, client) == 200
    alert, response = client.send_alert_record.call_args.args
    assert alert["alert_id"] == first["alert_id"]
    assert "message_key" not in alert
    assert response["evidence"]["network_connections"][0]["destination_port"] == 4444
    assert response["response_status"] == "simulated"
    assert response["response_plan"]["approval_required"] is True
    assert response["response_plan"]["execution_performed"] is False
    assert replay_alert(first["alert_id"], path, ledger, client) is None
    client.send_alert_record.assert_called_once()


def test_webhook_replay_error_does_not_record_delivery(tmp_path):
    alert, response = prepare_branch_alert("medium")
    path = tmp_path / "alerts.jsonl"
    key = "security-events:0:42"
    path.write_text(json.dumps({**alert.to_dict(), "message_key": key, "response": response}), encoding="utf-8")
    ledger = pipeline.ForwardedAlertLedger(str(tmp_path / "ledger.sqlite3"))
    client = Mock()
    client.send_alert_record.side_effect = error = HTTPError(
        "https://example.invalid/webhook/private-path", 503, "unavailable", {}, None,
    )
    with pytest.raises(HTTPError):
        replay_alert(alert.alert_id, path, ledger, client)
    assert not ledger.was_forwarded(key, alert.rule_id)
    assert webhook_error_message(error) == "HTTP 503"


def test_importable_n8n_workflow_keeps_both_branches_and_evidence():
    path = ROOT / "soar/workflows/soc_alert_response.json"
    workflow = json.loads(path.read_text(encoding="utf-8"))
    nodes = {node["name"]: node for node in workflow["nodes"]}
    condition = nodes["Is high severity?"]["parameters"]["conditions"]
    assert condition["conditions"][0]["leftValue"] == "={{ $json.body.alert.severity }}"
    assert condition["conditions"][0]["rightValue"] == "high"
    assert condition["options"]["caseSensitive"] is True
    assert nodes["Is high severity?"]["parameters"]["options"]["ignoreCase"] is False
    assert workflow["active"] is False
    assert all("credentials" not in node for node in nodes.values())
    branches = workflow["connections"]["Is high severity?"]["main"]
    for side, severity, expected_rule in ((0, "high", "TEST-HIGH"), (1, "medium", "DET-001")):
        node = nodes[branches[side][0]["node"]]["parameters"]
        assert node["includeOtherFields"] is True
        assert node["include"] == "all"
        values = {item["name"]: item["value"] for item in node["assignments"]["assignments"]}
        assert values["response_action"] == ("high_severity_review" if side == 0 else "manual_review")
        alert, response = prepare_branch_alert(severity)
        assert alert.severity == severity
        assert alert.rule_id == expected_rule
        assert alert.synthetic is True
        assert values["response_status"] == response["response_status"] == "simulated"
        assert response["evidence"]["event_ids"] == [alert.event_id]


def test_elasticsearch_has_dashboard_fields_and_prepares_both_indices(monkeypatch):
    ingestor = ElasticsearchIngestor("http://127.0.0.1:9200")
    request = Mock(return_value=200)
    monkeypatch.setattr(ingestor, "_request", request)
    ingestor.ensure_indices()
    ingestor.ensure_indices()
    first, second = [call.args for call in request.call_args_list]
    assert first[1].endswith("/security-events")
    assert second[1].endswith("/security-alerts")
    event = first[2]["mappings"]["properties"]
    alert = second[2]["mappings"]["properties"]
    for mapping in (event, alert):
        assert mapping["@timestamp"]["type"] == "date"
        assert mapping["producer"]["type"] == "keyword"
        assert mapping["synthetic"]["type"] == "boolean"
    assert event["network"]["properties"]["destination_port"]["type"] == "integer"
    assert event["file"]["properties"]["path"]["type"] == "keyword"
    assert alert["evidence_available"]["type"] == "boolean"
    assert alert["external_workflow"]["properties"]["delivery_status"]["type"] == "keyword"


def test_forwarder_skips_corrupt_lines_and_can_read_existing_records(tmp_path):
    log = tmp_path / "telemetry.jsonl"
    payload = build_sample_event()
    log.write_bytes(b"\xff\ninvalid\n[]\n" + json.dumps(payload).encode("utf-8") + b"\n")
    events = follow_events(log, from_start=True)
    try:
        assert next(events) == payload
    finally:
        events.close()
