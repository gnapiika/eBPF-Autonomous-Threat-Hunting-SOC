import pytest

from detection.event_schema import SecurityEvent, ProcessInfo
from detection.threat_hunting.hunt_engine import ThreatHunter


def make_event(
    event_id="EVT-001",
    event_type="process_execution",
    host="workstation-01",
    source="tetragon",
    severity="medium",
    timestamp="2026-10-10T10:00:00",
    process_name="bash",
    command_line="bash -c whoami",
):
    return SecurityEvent(
        event_id=event_id,
        event_type=event_type,
        source=source,
        host=host,
        timestamp=timestamp,
        severity=severity,
        process=ProcessInfo(
            name=process_name,
            command_line=command_line,
        ),
    )


@pytest.fixture
def hunter():
    events = [
        make_event(),
        make_event(
            event_id="EVT-002",
            host="server-02",
            severity="high",
            timestamp="2026-10-10T11:00:00",
            process_name="python",
            command_line="python app.py",
        ),
        make_event(
            event_id="EVT-003",
            event_type="file_access",
            source="falco",
            severity="low",
            timestamp="2026-10-10T12:00:00",
            process_name="cat",
            command_line="cat notes.txt",
        ),
    ]
    return ThreatHunter(events)


def test_hunt_by_event_type(hunter):
    results = hunter.hunt(event_type="process_execution")

    assert len(results) == 2
    assert all(e.event_type == "process_execution" for e in results)


def test_hunt_by_host_case_insensitive(hunter):
    results = hunter.hunt(host="SERVER-02")

    assert len(results) == 1
    assert results[0].event_id == "EVT-002"


def test_hunt_by_severity(hunter):
    results = hunter.hunt(severity="high")

    assert len(results) == 1
    assert results[0].event_id == "EVT-002"


def test_hunt_by_keyword(hunter):
    results = hunter.hunt(keyword="whoami")

    assert len(results) == 1
    assert results[0].event_id == "EVT-001"


def test_hunt_by_time_range(hunter):
    results = hunter.hunt(
        start_time="2026-10-10T10:30:00",
        end_time="2026-10-10T11:30:00",
    )

    assert len(results) == 1
    assert results[0].event_id == "EVT-002"


def test_hunt_combines_filters(hunter):
    results = hunter.hunt(
        event_type="process_execution",
        host="workstation-01",
        keyword="whoami",
    )

    assert len(results) == 1
    assert results[0].event_id == "EVT-001"


def test_invalid_time_range_raises_error(hunter):
    with pytest.raises(ValueError):
        hunter.hunt(
            start_time="2026-10-10T12:00:00",
            end_time="2026-10-10T10:00:00",
        )


def test_summarize_results(hunter):
    summary = ThreatHunter.summarize(hunter.events)

    assert summary["total_events"] == 3
    assert summary["by_type"]["process_execution"] == 2
    assert summary["by_severity"]["high"] == 1


def test_add_events(hunter):
    hunter.add_events([
        make_event(event_id="EVT-004", host="new-host")
    ])

    assert len(hunter.events) == 4
