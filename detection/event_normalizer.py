from dataclasses import fields
from pathlib import PurePosixPath
from typing import Any, Dict, Optional

from detection.event_schema import (
    FileInfo,
    NetworkInfo,
    ProcessInfo,
    SecurityEvent,
    UserInfo,
    normalize_severity,
)

TETRAGON_EVENT_TYPES = ("process_exec", "process_exit", "process_kprobe", "process_tracepoint")


class EventNormalizer:
    """
    Normalize telemetry events from different security sources
    into a common SecurityEvent structure.
    """

    def normalize(
        self,
        raw_event: Dict[str, Any],
        source: str,
        host: str,
    ) -> SecurityEvent:
        """
        Normalize a raw event.

        Args:
            raw_event: Raw telemetry event.
            source: Telemetry source such as Tetragon, Falco, or eBPF.
            host: Host that generated the event.

        Returns:
            A normalized SecurityEvent.
        """

        source = source.lower()

        if "schema_version" in raw_event and "event_type" in raw_event and "event_id" in raw_event:
            event = SecurityEvent.from_dict(raw_event)
        elif source == "tetragon":
            event = self._normalize_tetragon(raw_event, host)
        elif source == "falco":
            event = self._normalize_falco(raw_event, host)
        elif source == "ebpf":
            event = self._normalize_ebpf(raw_event, host)
        else:
            event = self._normalize_generic(raw_event, source, host)
        for value in (event.event_type, event.host, event.source):
            if not isinstance(value, str) or not value:
                raise ValueError("event type, host and source must be nonempty strings")
        for value in (event.process.name, event.process.command_line):
            if value is not None and not isinstance(value, str):
                raise ValueError("process name and command line must be strings")
        event.synthetic = raw_event.get("synthetic") is True
        if event.synthetic and "synthetic" not in event.tags:
            event.tags.append("synthetic")
        if isinstance(raw_event.get("event_id"), str) and raw_event["event_id"]:
            event.event_id = raw_event["event_id"]
        return event

    # ------------------------------------------------------------------
    # Tetragon
    # ------------------------------------------------------------------

    def _normalize_tetragon(
        self,
        raw_event: Dict[str, Any],
        host: str,
    ) -> SecurityEvent:
        """Normalize a Tetragon event."""

        payload = raw_event
        event_kind = raw_event.get("type", raw_event.get("event_type", "unknown"))
        for kind in TETRAGON_EVENT_TYPES:
            if kind in raw_event:
                payload = self._object(raw_event, kind)
                event_kind = kind
                break
        process = self._object(payload, "process")
        parent = self._object(payload, "parent") or self._object(process, "parent")
        user = self._object(payload, "user")
        binary = process.get("binary")
        parent_binary = parent.get("binary")
        arguments = process.get("arguments")
        if payload is not raw_event and isinstance(binary, str):
            arguments = f"{binary} {arguments}" if arguments else binary

        process_info = ProcessInfo(
            pid=self._to_int(process.get("pid")),
            ppid=self._to_int(parent.get("pid")),
            name=process.get("name") or (PurePosixPath(binary).name if binary else None),
            executable=binary,
            command_line=arguments,
            parent_name=parent.get("name") or (PurePosixPath(parent_binary).name if parent_binary else None),
            parent_executable=parent_binary,
        )

        user_info = UserInfo(
            uid=self._to_int(user.get("uid", process.get("uid"))),
            gid=self._to_int(user.get("gid")),
            username=user.get("username"),
        )

        event_type = self._map_event_type(event_kind)

        return SecurityEvent(
            event_type=event_type,
            source="tetragon",
            host=host,
            timestamp=self._get_timestamp(raw_event),
            process=process_info,
            user=user_info,
            network=self._network_info(payload),
            file=self._file_info(payload),
            severity=self._map_severity(raw_event.get("severity")),
            tags=["tetragon"],
            raw_event=raw_event,
            metadata={
                "original_event_type": event_kind,
            },
        )

    # ------------------------------------------------------------------
    # Falco
    # ------------------------------------------------------------------

    def _normalize_falco(
        self,
        raw_event: Dict[str, Any],
        host: str,
    ) -> SecurityEvent:
        """Normalize a Falco event."""

        output = self._object(raw_event, "output_fields")
        operation = output.get("evt.type")
        file_path = output.get("fs.path.name") or output.get("fd.name") or output.get("evt.arg.filename")

        process_info = ProcessInfo(
            pid=self._to_int(output.get("proc.pid")),
            ppid=self._to_int(output.get("proc.ppid")),
            name=output.get("proc.name"),
            executable=output.get("proc.exepath"),
            command_line=output.get("proc.cmdline"),
            parent_name=output.get("proc.pname"),
        )

        user_info = UserInfo(
            uid=self._to_int(output.get("user.uid")),
            username=output.get("user.name"),
        )

        event_type = self._map_event_type(raw_event.get("rule", "unknown"))
        if operation in {"execve", "execveat"}:
            event_type = "process_execution"
        elif operation in {"connect", "accept", "accept4"}:
            event_type = "network_connection"
        elif operation in {"open", "openat", "openat2", "creat", "unlink", "unlinkat", "rename", "renameat", "renameat2"}:
            event_type = "file_activity"
        file_info = FileInfo()
        if event_type == "file_activity":
            file_info = FileInfo(path=file_path, operation=operation)

        network_info = NetworkInfo(
            source_ip=output.get("fd.cip"),
            source_port=self._to_int(output.get("fd.cport")),
            destination_ip=output.get("fd.sip"),
            destination_port=self._to_int(output.get("fd.sport")),
            protocol=output.get("fd.l4proto"),
        )

        severity = self._map_severity(
            raw_event.get("priority")
        )

        return SecurityEvent(
            event_type=event_type,
            source="falco",
            host=host,
            timestamp=self._get_timestamp(raw_event),
            process=process_info,
            user=user_info,
            network=network_info,
            file=file_info,
            severity=severity,
            tags=["falco"],
            raw_event=raw_event,
            metadata={
                "rule": raw_event.get("rule"),
                "priority": raw_event.get("priority"),
                "output": raw_event.get("output"),
            },
        )

    # ------------------------------------------------------------------
    # eBPF
    # ------------------------------------------------------------------

    def _normalize_ebpf(
        self,
        raw_event: Dict[str, Any],
        host: str,
    ) -> SecurityEvent:
        """Normalize a generic eBPF event."""

        process_info = ProcessInfo(
            pid=self._to_int(raw_event.get("pid")),
            ppid=self._to_int(raw_event.get("ppid")),
            name=raw_event.get("comm"),
            executable=raw_event.get("exe"),
            command_line=raw_event.get("args"),
        )

        user_info = UserInfo(
            uid=self._to_int(raw_event.get("uid")),
            gid=self._to_int(raw_event.get("gid")),
            username=raw_event.get("username"),
        )

        event_type = self._map_event_type(
            raw_event.get(
                "event_type",
                raw_event.get("type", "unknown"),
            )
        )

        return SecurityEvent(
            event_type=event_type,
            source="ebpf",
            host=host,
            timestamp=self._get_timestamp(raw_event),
            process=process_info,
            user=user_info,
            network=self._network_info(raw_event),
            file=self._file_info(raw_event),
            severity=self._map_severity(raw_event.get("severity")),
            tags=["ebpf"],
            raw_event=raw_event,
            metadata={
                "original_event_type": raw_event.get("event_type"),
            },
        )

    # ------------------------------------------------------------------
    # Generic events
    # ------------------------------------------------------------------

    def _normalize_generic(
        self,
        raw_event: Dict[str, Any],
        source: str,
        host: str,
    ) -> SecurityEvent:
        """Normalize an event from an unknown/custom source."""

        event_type = self._map_event_type(
            raw_event.get(
                "event_type",
                raw_event.get("type", "unknown"),
            )
        )

        process_data = self._object(raw_event, "process")
        process = ProcessInfo(**{
            field.name: process_data[field.name]
            for field in fields(ProcessInfo)
            if field.name in process_data
        })
        process.pid = self._to_int(process.pid)
        process.ppid = self._to_int(process.ppid)
        return SecurityEvent(
            event_type=event_type,
            source=source,
            host=host,
            timestamp=self._get_timestamp(raw_event),
            process=process,
            network=self._network_info(raw_event),
            file=self._file_info(raw_event),
            severity=self._map_severity(raw_event.get("severity")),
            tags=["generic"],
            raw_event=raw_event,
            metadata={
                "message": raw_event.get("message"),
            },
        )

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def _object(data: Dict[str, Any], key: str) -> Dict[str, Any]:
        value = data.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be a JSON object")
        return value

    def _network_info(self, data: Dict[str, Any]) -> NetworkInfo:
        network = self._object(data, "network") or data
        return NetworkInfo(
            source_ip=network.get("source_ip"),
            source_port=self._to_int(network.get("source_port")),
            destination_ip=network.get("destination_ip"),
            destination_port=self._to_int(network.get("destination_port")),
            protocol=network.get("protocol"),
        )

    def _file_info(self, data: Dict[str, Any]) -> FileInfo:
        file = self._object(data, "file")
        return FileInfo(
            path=file.get("path", data.get("file_path")),
            operation=file.get("operation", data.get("file_operation")),
            hash_sha256=file.get("hash_sha256"),
        )

    @staticmethod
    def _to_int(value: Any) -> Optional[int]:
        """Safely convert a value to an integer."""

        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _get_timestamp(raw_event: Dict[str, Any]) -> Optional[str]:
        """Extract the timestamp from a raw event."""

        timestamp = raw_event.get("@timestamp") or raw_event.get("timestamp")

        if timestamp is None:
            timestamp = raw_event.get("time")

        if timestamp is None:
            timestamp = raw_event.get("datetime")

        return str(timestamp) if timestamp is not None else None

    @staticmethod
    def _map_event_type(event_type: Any) -> str:
        """
        Map different telemetry event names to a common event type.
        """

        if event_type is None:
            return "unknown"

        value = str(event_type).lower().strip()

        mappings = {
            # Process execution
            "process_exec": "process_execution",
            "process_execution": "process_execution",
            "execve": "process_execution",
            "exec": "process_execution",
            "process_start": "process_execution",
            "process_started": "process_execution",

            # Process termination
            "process_exit": "process_termination",
            "process_exit_event": "process_termination",
            "exit": "process_termination",

            # Network
            "network": "network_connection",
            "network_connection": "network_connection",
            "connect": "network_connection",
            "socket_connect": "network_connection",

            # File activity
            "file_open": "file_activity",
            "file_create": "file_activity",
            "file_modify": "file_activity",
            "file_delete": "file_activity",
            "file_activity": "file_activity",

            # Authentication
            "login": "authentication",
            "login_success": "authentication",
            "login_failure": "authentication",
            "authentication": "authentication",
            "auth": "authentication",

            # DNS
            "dns": "dns_query",
            "dns_query": "dns_query",

            # Container
            "container_start": "container_activity",
            "container_stop": "container_activity",
            "container_activity": "container_activity",
        }

        if value in mappings:
            return mappings[value]

        # Falco rule names are usually descriptive rather than
        # standardized event names.
        if "shell" in value or "command" in value:
            return "process_execution"

        if "network" in value or "connection" in value:
            return "network_connection"

        if "file" in value:
            return "file_activity"

        if "login" in value or "authentication" in value:
            return "authentication"

        return value

    @staticmethod
    def _map_severity(severity: Any) -> str:
        """Normalize severity values into a common format."""
        return normalize_severity(severity)


if __name__ == "__main__":
    # Simple manual test.
    normalizer = EventNormalizer()

    sample_event = {
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
        sample_event,
        source="tetragon",
        host="server-01",
    )

    print(event.to_json())
