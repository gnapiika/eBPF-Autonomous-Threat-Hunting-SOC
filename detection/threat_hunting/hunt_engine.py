"""In-memory threat hunting utilities for normalized security events."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from detection.event_schema import SecurityEvent


class ThreatHunter:
    """Search normalized events using investigation filters."""

    def __init__(self, events: Optional[List[SecurityEvent]] = None):
        self.events = list(events) if events is not None else []

    def add_events(self, events: List[SecurityEvent]) -> None:
        """Add events to the hunting dataset."""
        self.events.extend(events)

    def hunt(
        self,
        event_type: Optional[str] = None,
        host: Optional[str] = None,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Return events matching all supplied filters.

        Timestamps should be ISO-8601 strings. For reliable time
        comparisons, timestamps should use the same timezone format.
        """
        start = self._parse_time(start_time)
        end = self._parse_time(end_time)

        if start and end and start > end:
            raise ValueError("start_time must not be after end_time")

        results = []

        for event in self.events:
            if event_type and event.event_type.lower() != event_type.lower():
                continue

            if host and event.host.lower() != host.lower():
                continue

            if source and event.source.lower() != source.lower():
                continue

            if severity and event.severity.lower() != severity.lower():
                continue

            event_time = self._parse_time(event.timestamp)

            if start and (event_time is None or event_time < start):
                continue

            if end and (event_time is None or event_time > end):
                continue

            if keyword and keyword.lower() not in self._searchable_text(event):
                continue

            results.append(event)

        return results

    @staticmethod
    def _parse_time(value: Optional[str]) -> Optional[datetime]:
        """Parse an ISO-8601 timestamp, if one is provided."""
        if not value:
            return None

        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"Invalid ISO-8601 timestamp: {value}"
            ) from exc

        return parsed

    @staticmethod
    def _searchable_text(event: SecurityEvent) -> str:
        """Build searchable text from useful event attributes."""
        values: List[str] = [
            event.event_id,
            event.event_type,
            event.source,
            event.host,
            str(event.raw_event or ""),
        ]

        if event.process:
            values.extend([
                event.process.name or "",
                event.process.executable or "",
                event.process.command_line or "",
                event.process.parent_name or "",
            ])

        if event.network:
            values.extend([
                event.network.source_ip or "",
                event.network.destination_ip or "",
                str(event.network.destination_port or ""),
                event.network.protocol or "",
            ])

        if event.file:
            values.append(str(event.file))

        return " ".join(values).lower()

    @staticmethod
    def summarize(results: List[SecurityEvent]) -> Dict[str, Any]:
        """Summarize the number of events by type and severity."""
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}

        for event in results:
            by_type[event.event_type] = (
                by_type.get(event.event_type, 0) + 1
            )

            by_severity[event.severity] = (
                by_severity.get(event.severity, 0) + 1
            )

        return {
            "total_events": len(results),
            "by_type": by_type,
            "by_severity": by_severity,
        }
