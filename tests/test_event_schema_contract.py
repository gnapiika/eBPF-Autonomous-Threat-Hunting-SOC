from datetime import datetime

import pytest

from detection.event_schema import (
    ProcessInfo,
    SecurityEvent,
)


def test_serialization_emits_utc_aliases_and_canonical_mitre():
    event = SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-host",
        timestamp="2026-03-01T10:00:00+02:00",
        severity="Warning",
        process=ProcessInfo(name="bash"),
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059"],
    )

    result = event.to_dict()

    assert result["@timestamp"] == "2026-03-01T08:00:00.000Z"
    assert result["timestamp"] == result["@timestamp"]
    assert result["timestamp_source"] == "event"
    assert result["severity"] == "medium"
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
    assert result["mitre_tactics"] == ["Execution"]
    assert result["mitre_techniques"] == ["T1059"]


def test_missing_timestamp_uses_utc_ingestion_time():
    result = SecurityEvent(
        event_type="authentication",
        source="test",
        host="test-host",
    ).to_dict()

    parsed = datetime.fromisoformat(result["@timestamp"].replace("Z", "+00:00"))
    assert parsed.utcoffset().total_seconds() == 0
    assert result["timestamp"] == result["@timestamp"]
    assert result["timestamp_source"] == "ingest"


def test_from_dict_prefers_canonical_fields_without_mutating_input():
    data = {
        "schema_version": "1.0",
        "event_type": "process_execution",
        "source": "tetragon",
        "host": "test-host",
        "@timestamp": "2026-03-01T08:00:00Z",
        "timestamp": "2026-03-01T10:00:00+02:00",
        "process": {},
        "process_name": "bash",
        "mitre": {
            "tactics": [{"id": "TA0002", "name": "Execution"}],
            "techniques": [{"id": "T1059", "name": "Interpreter"}],
        },
        "mitre_tactics": ["legacy tactic"],
        "mitre_techniques": ["T9999"],
    }

    event = SecurityEvent.from_dict(data)
    result = event.to_dict()

    assert event.timestamp == "2026-03-01T08:00:00.000Z"
    assert event.process.name == "bash"
    assert result["mitre"]["techniques"] == [
        {"id": "T1059", "name": "Interpreter"}
    ]
    assert result["mitre_tactics"] == ["legacy tactic"]
    assert result["mitre_techniques"] == ["T9999"]
    assert data["process"] == {}
    assert data["@timestamp"] == "2026-03-01T08:00:00Z"


def test_canonical_mitre_also_populates_legacy_aliases():
    event = SecurityEvent(
        event_type="process_execution",
        source="tetragon",
        host="test-host",
        mitre={
            "tactics": [{"id": "TA0002", "name": "Execution"}],
            "techniques": [{"id": "T1059", "name": "Interpreter"}],
        },
    )

    result = event.to_dict()

    assert result["mitre_tactics"] == ["TA0002"]
    assert result["mitre_techniques"] == ["T1059"]


def test_rejects_invalid_timestamp_instead_of_silently_replacing_it():
    with pytest.raises(ValueError, match="invalid ISO 8601 timestamp"):
        SecurityEvent(
            event_type="process_execution",
            source="tetragon",
            host="test-host",
            timestamp="not-a-timestamp",
        )
