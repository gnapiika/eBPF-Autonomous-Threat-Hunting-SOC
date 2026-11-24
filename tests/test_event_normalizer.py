import pytest

from detection.event_normalizer import EventNormalizer


@pytest.fixture
def normalizer():
    return EventNormalizer()


def test_tetragon_process_event(normalizer):
    raw_event = {
        "type": "process_exec",
        "time": "2026-10-08T15:30:00Z",
        "process": {
            "pid": 4210,
            "name": "bash",
            "binary": "/bin/bash",
            "arguments": "bash -c whoami",
            "parent": {
                "pid": 4001,
                "name": "sshd",
                "binary": "/usr/sbin/sshd",
            },
        },
        "user": {
            "uid": 1000,
            "gid": 1000,
            "username": "analyst",
        },
    }

    event = normalizer.normalize(
        raw_event,
        source="tetragon",
        host="server-01",
    )

    assert event.source == "tetragon"
    assert event.host == "server-01"
    assert event.event_type == "process_execution"
    assert event.process.pid == 4210
    assert event.process.name == "bash"
    assert event.process.executable == "/bin/bash"
    assert event.process.parent_name == "sshd"
    assert event.user.username == "analyst"
    assert event.timestamp == "2026-10-08T15:30:00.000Z"
    assert event.timestamp_source == "event"
    assert event.severity == "info"


def test_falco_process_event(normalizer):
    raw_event = {
        "rule": "Terminal shell in container",
        "priority": "Warning",
        "time": "2026-10-08T15:35:00Z",
        "output_fields": {
            "proc.pid": 5001,
            "proc.ppid": 4900,
            "proc.name": "bash",
            "proc.exepath": "/bin/bash",
            "proc.cmdline": "bash",
            "proc.pname": "sshd",
            "user.uid": 1000,
            "user.name": "analyst",
            "fd.cip": "10.0.0.5",
            "fd.cport": 4444,
            "fd.sip": "10.0.0.20",
            "fd.sport": 443,
            "fd.l4proto": "TCP",
        },
    }

    event = normalizer.normalize(
        raw_event,
        source="falco",
        host="server-02",
    )

    assert event.source == "falco"
    assert event.host == "server-02"
    assert event.process.pid == 5001
    assert event.process.name == "bash"
    assert event.network.source_ip == "10.0.0.5"
    assert event.network.destination_ip == "10.0.0.20"
    assert event.network.destination_port == 443
    assert event.user.username == "analyst"
    assert event.severity == "medium"


def test_ebpf_exec_event(normalizer):
    raw_event = {
        "event_type": "execve",
        "timestamp": "2026-10-08T15:40:00Z",
        "pid": 6001,
        "ppid": 5900,
        "comm": "curl",
        "exe": "/usr/bin/curl",
        "args": "curl https://example.com",
        "uid": 1000,
        "gid": 1000,
        "username": "analyst",
    }

    event = normalizer.normalize(
        raw_event,
        source="ebpf",
        host="server-03",
    )

    assert event.source == "ebpf"
    assert event.host == "server-03"
    assert event.event_type == "process_execution"
    assert event.process.pid == 6001
    assert event.process.name == "curl"
    assert event.process.executable == "/usr/bin/curl"
    assert event.user.username == "analyst"


def test_generic_event(normalizer):
    raw_event = {
        "event_type": "custom_security_event",
        "message": "Test security event",
    }

    event = normalizer.normalize(
        raw_event,
        source="custom_source",
        host="test-host",
    )

    assert event.source == "custom_source"
    assert event.host == "test-host"
    assert event.event_type == "custom_security_event"
    assert event.raw_event == raw_event