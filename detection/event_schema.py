"""
Common security event schema for the eBPF Autonomous Threat Hunting SOC.

This module defines the normalized event structure consumed by the
detection, correlation, MITRE ATT&CK mapping, and threat-hunting
components.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
import json
import uuid

from detection.mitre.attack_mapping import canonical_mitre


SCHEMA_VERSION = "1.0"
SOC_PRODUCER = "ebpf-autonomous-threat-hunting-soc"


def normalize_utc_timestamp(
    value: Optional[Union[str, datetime]] = None,
) -> str:
    """Return an ISO 8601 UTC timestamp with millisecond precision."""
    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    else:
        timestamp = str(value).strip()
        if timestamp.endswith("Z"):
            timestamp = timestamp[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(timestamp)
        except ValueError as exc:
            raise ValueError(f"invalid ISO 8601 timestamp: {value}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def normalize_severity(value: Any) -> str:
    """Normalize source severity labels to the shared lowercase enum."""
    mappings = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "crit": "critical",
        "error": "high",
        "err": "high",
        "high": "high",
        "warning": "medium",
        "warn": "medium",
        "medium": "medium",
        "notice": "low",
        "low": "low",
        "info": "info",
        "informational": "info",
    }
    return mappings.get(str(value).lower().strip(), "info")


@dataclass
class ProcessInfo:
    """Information about a process involved in an event."""

    pid: Optional[int] = None
    ppid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None
    parent_name: Optional[str] = None
    parent_executable: Optional[str] = None


@dataclass
class UserInfo:
    """Information about the user responsible for an event."""

    uid: Optional[int] = None
    gid: Optional[int] = None
    username: Optional[str] = None


@dataclass
class NetworkInfo:
    """Network information associated with an event."""

    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass
class FileInfo:
    """File information associated with an event."""

    path: Optional[str] = None
    operation: Optional[str] = None
    hash_sha256: Optional[str] = None


@dataclass
class SecurityEvent:
    """
    Normalized security event.

    All telemetry sources should eventually be converted into this
    structure before reaching the detection engine.
    """

    event_type: str
    source: str
    host: str

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    timestamp: Optional[str] = None
    timestamp_source: Optional[str] = None

    process: ProcessInfo = field(default_factory=ProcessInfo)
    user: UserInfo = field(default_factory=UserInfo)
    network: NetworkInfo = field(default_factory=NetworkInfo)
    file: FileInfo = field(default_factory=FileInfo)

    severity: str = "low"

    tags: List[str] = field(default_factory=list)

    raw_event: Dict[str, Any] = field(default_factory=dict)

    mitre_tactics: List[str] = field(default_factory=list)

    mitre_techniques: List[str] = field(default_factory=list)

    metadata: Dict[str, Any] = field(default_factory=dict)

    mitre: Dict[str, List[Dict[str, Optional[str]]]] = field(
        default_factory=lambda: {"tactics": [], "techniques": []}
    )
    producer: str = SOC_PRODUCER
    synthetic: bool = False

    def __post_init__(self) -> None:
        timestamp_is_source = self.timestamp is not None
        self.timestamp = normalize_utc_timestamp(self.timestamp)
        self.severity = normalize_severity(self.severity)
        if self.timestamp_source is None:
            self.timestamp_source = (
                "event" if timestamp_is_source else "ingest"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the canonical event and its compatibility aliases."""
        event = asdict(self)
        timestamp = normalize_utc_timestamp(self.timestamp)
        mitre = canonical_mitre(
            self.mitre_tactics,
            self.mitre_techniques,
            self.mitre,
        )
        event.update(
            {
                "schema_version": SCHEMA_VERSION,
                "@timestamp": timestamp,
                "timestamp": timestamp,
                "timestamp_source": self.timestamp_source,
                "severity": normalize_severity(self.severity),
                "process_name": self.process.name,
                "mitre": mitre,
                "mitre_tactics": self.mitre_tactics
                or [
                    entry.get("id") or entry.get("name")
                    for entry in mitre["tactics"]
                ],
                "mitre_techniques": self.mitre_techniques
                or [
                    entry.get("id") or entry.get("name")
                    for entry in mitre["techniques"]
                ],
            }
        )
        return event

    def to_json(self) -> str:
        """Serialize the security event as JSON."""

        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create a SecurityEvent from canonical or legacy serialized data."""
        values = dict(data)
        values.pop("schema_version", None)
        canonical_timestamp = values.pop("@timestamp", None)
        if canonical_timestamp is not None:
            values["timestamp"] = canonical_timestamp

        process_data = dict(values.pop("process", {}))
        process_name = values.pop("process_name", None)
        if process_data.get("name") is None and process_name is not None:
            process_data["name"] = process_name
        user_data = dict(values.pop("user", {}))
        network_data = dict(values.pop("network", {}))
        file_data = dict(values.pop("file", {}))
        mitre = values.pop("mitre", {"tactics": [], "techniques": []})
        values.setdefault(
            "mitre_tactics",
            [entry.get("id") for entry in mitre.get("tactics", [])],
        )
        values.setdefault(
            "mitre_techniques",
            [entry.get("id") for entry in mitre.get("techniques", [])],
        )

        return cls(
            process=ProcessInfo(**process_data),
            user=UserInfo(**user_data),
            network=NetworkInfo(**network_data),
            file=FileInfo(**file_data),
            mitre=mitre,
            **values,
        )


def create_process_event(
    source: str,
    host: str,
    process_name: str,
    executable: Optional[str] = None,
    command_line: Optional[str] = None,
    pid: Optional[int] = None,
    ppid: Optional[int] = None,
    username: Optional[str] = None,
    uid: Optional[int] = None,
) -> SecurityEvent:
    """
    Convenience function for creating a normalized process execution event.
    """

    return SecurityEvent(
        event_type="process_execution",
        source=source,
        host=host,
        process=ProcessInfo(
            pid=pid,
            ppid=ppid,
            name=process_name,
            executable=executable,
            command_line=command_line,
        ),
        user=UserInfo(
            uid=uid,
            username=username,
        ),
    )


if __name__ == "__main__":
    event = create_process_event(
        source="tetragon",
        host="server-01",
        process_name="bash",
        executable="/bin/bash",
        command_line="bash -c whoami",
        pid=4210,
        ppid=4001,
        username="analyst",
        uid=1000,
    )

    print(event.to_json())
