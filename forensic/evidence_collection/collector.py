"""Build a forensic evidence bundle from normalized security events."""

from dataclasses import asdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from detection.detection_engine import DetectionAlert
from detection.event_schema import SecurityEvent, normalize_utc_timestamp


class ForensicEvidenceCollector:
    """Collect event-backed evidence without querying or changing the host."""

    def collect(
        self,
        events: Sequence[SecurityEvent],
        alert: Optional[DetectionAlert] = None,
    ) -> Dict[str, Any]:
        """Create a JSON-compatible evidence bundle from supplied events."""
        if not events:
            raise ValueError("at least one security event is required")
        if any(not isinstance(event, SecurityEvent) for event in events):
            raise TypeError("events must contain only SecurityEvent instances")
        hosts = {event.host for event in events}
        if len(hosts) != 1:
            raise ValueError("an evidence bundle must contain events from one host")

        event_records = [event.to_dict() for event in events]
        process_information = [
            self._event_record(event, asdict(event.process))
            for event in events
            if event.process
            and any(value is not None for value in asdict(event.process).values())
        ]
        network_connections = [
            self._event_record(event, asdict(event.network))
            for event in events
            if event.network
            and any(value is not None for value in asdict(event.network).values())
        ]
        file_information = [
            self._event_record(event, asdict(event.file))
            for event in events
            if event.file
            and any(value is not None for value in asdict(event.file).values())
        ]
        relevant_logs = [
            self._event_record(
                event,
                {
                    "metadata": event.metadata,
                    "raw_event": event.raw_event,
                },
            )
            for event in events
            if event.metadata or event.raw_event
        ]

        process_tree = self._build_process_tree(events)
        return {
            "evidence_id": f"evidence-{events[0].event_id}",
            "collected_at": normalize_utc_timestamp(),
            "collection_method": "normalized_event_snapshot",
            "host": events[0].host,
            "alert": alert.to_dict() if alert else None,
            "event_ids": [event.event_id for event in events],
            "timestamps": [
                self._event_record(
                    event,
                    {
                        "@timestamp": event.timestamp,
                        "timestamp": event.timestamp,
                    },
                )
                for event in events
            ],
            "process_information": process_information,
            "process_tree": process_tree,
            "network_connections": network_connections,
            "file_information": file_information,
            "relevant_logs": relevant_logs,
            "raw_events": event_records,
            "coverage": {
                "event_count": len(events),
                "process_event_count": len(process_information),
                "network_event_count": len(network_connections),
                "file_event_count": len(file_information),
                "log_context_event_count": len(relevant_logs),
                "process_tree_node_count": len(process_tree),
            },
        }

    @staticmethod
    def _event_record(
        event: SecurityEvent,
        details: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "event_id": event.event_id,
            "host": event.host,
            "source": event.source,
            "event_type": event.event_type,
            **details,
        }

    @staticmethod
    def _build_process_tree(
        events: Sequence[SecurityEvent],
    ) -> List[Dict[str, Any]]:
        nodes: Dict[Tuple[str, int], Dict[str, Any]] = {}
        for event in events:
            process = event.process
            if not process or process.pid is None or process.pid <= 0:
                continue

            key = (event.host, process.pid)
            node = nodes.setdefault(
                key,
                {
                    "host": event.host,
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "name": process.name,
                    "executable": process.executable,
                    "command_line": process.command_line,
                    "parent_name": process.parent_name,
                    "parent_executable": process.parent_executable,
                    "child_pids": [],
                    "event_ids": [],
                },
            )
            if event.event_id not in node["event_ids"]:
                node["event_ids"].append(event.event_id)

        for node in nodes.values():
            parent_key = (node["host"], node["ppid"])
            parent = nodes.get(parent_key)
            if parent and node["pid"] not in parent["child_pids"]:
                parent["child_pids"].append(node["pid"])

        return sorted(
            nodes.values(),
            key=lambda node: (node["host"], node["pid"]),
        )
