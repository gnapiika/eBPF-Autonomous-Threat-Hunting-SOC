"""
Common security event schema for the eBPF Autonomous Threat Hunting SOC.

This module defines the normalized event structure consumed by the
detection, correlation, MITRE ATT&CK mapping, and threat-hunting
components.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json
import uuid


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

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

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

    def to_dict(self) -> Dict[str, Any]:
        """Convert the security event into a dictionary."""

        return asdict(self)

    def to_json(self) -> str:
        """Serialize the security event as JSON."""

        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Create a SecurityEvent from a dictionary."""

        process_data = data.pop("process", {})
        user_data = data.pop("user", {})
        network_data = data.pop("network", {})
        file_data = data.pop("file", {})

        return cls(
            process=ProcessInfo(**process_data),
            user=UserInfo(**user_data),
            network=NetworkInfo(**network_data),
            file=FileInfo(**file_data),
            **data,
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