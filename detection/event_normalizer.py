from typing import Any, Dict, Optional

from detection.event_schema import (
    FileInfo,
    NetworkInfo,
    ProcessInfo,
    SecurityEvent,
    UserInfo,
)


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

        if source == "tetragon":
            return self._normalize_tetragon(raw_event, host)

        if source == "falco":
            return self._normalize_falco(raw_event, host)

        if source == "ebpf":
            return self._normalize_ebpf(raw_event, host)

        return self._normalize_generic(raw_event, source, host)

    # ------------------------------------------------------------------
    # Tetragon
    # ------------------------------------------------------------------

    def _normalize_tetragon(
        self,
        raw_event: Dict[str, Any],
        host: str,
    ) -> SecurityEvent:
        """Normalize a Tetragon event."""

        process = raw_event.get("process", {})
        parent = process.get("parent", {})
        user = raw_event.get("user", {})

        process_info = ProcessInfo(
            pid=self._to_int(process.get("pid")),
            ppid=self._to_int(parent.get("pid")),
            name=process.get("name"),
            executable=process.get("binary"),
            command_line=process.get("arguments"),
            parent_name=parent.get("name"),
            parent_executable=parent.get("binary"),
        )

        user_info = UserInfo(
            uid=self._to_int(user.get("uid")),
            gid=self._to_int(user.get("gid")),
            username=user.get("username"),
        )

        event_type = self._map_event_type(
            raw_event.get("type", raw_event.get("event_type", "unknown"))
        )

        return SecurityEvent(
            event_type=event_type,
            source="tetragon",
            host=host,
            timestamp=self._get_timestamp(raw_event),
            process=process_info,
            user=user_info,
            severity=self._map_severity(raw_event.get("severity")),
            tags=["tetragon"],
            raw_event=raw_event,
            metadata={
                "original_event_type": raw_event.get("type"),
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

        output = raw_event.get("output_fields", {})

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

        network_info = NetworkInfo(
            source_ip=output.get("fd.cip"),
            source_port=self._to_int(output.get("fd.cport")),
            destination_ip=output.get("fd.sip"),
            destination_port=self._to_int(output.get("fd.sport")),
            protocol=output.get("fd.l4proto"),
        )

        event_type = self._map_event_type(
            raw_event.get("rule", "unknown")
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

        return SecurityEvent(
            event_type=event_type,
            source=source,
            host=host,
            timestamp=self._get_timestamp(raw_event),
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

        timestamp = raw_event.get("timestamp")

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

        if severity is None:
            return "info"

        value = str(severity).lower().strip()

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

        return mappings.get(value, "info")


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