
"""Correlate related security events into higher-confidence findings."""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from detection.event_schema import SecurityEvent


class CorrelationEngine:
    """Identify suspicious patterns spanning multiple security events."""

    def __init__(
        self,
        failure_threshold: int = 3,
        window_minutes: int = 10,
    ):
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        if window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")

        self.failure_threshold = failure_threshold
        self.window = timedelta(minutes=window_minutes)

    def detect_login_brute_force(
        self,
        events: List[SecurityEvent],
    ) -> List[Dict[str, Any]]:
        """Find repeated login failures followed by a success.

        Events must identify authentication outcomes in event_type or
        raw_event, and should provide a username and source IP.
        """
        groups = defaultdict(list)

        for event in events:
            outcome = self._auth_outcome(event)
            if outcome not in {"failure", "success"}:
                continue

            username = event.user.username if event.user else None
            source_ip = event.network.source_ip if event.network else None

            if not username or not source_ip:
                continue

            timestamp = self._parse_timestamp(event.timestamp)
            if timestamp is None:
                continue

            # Include host so activity from unrelated machines isn't
            # accidentally combined into one sequence.
            key = (event.host, username.lower(), source_ip)
            groups[key].append((timestamp, outcome, event))

        findings = []

        for (host, username, source_ip), records in groups.items():
            records.sort(key=lambda item: item[0])

            for index, (success_time, outcome, success_event) in enumerate(records):
                if outcome != "success":
                    continue

                window_start = success_time - self.window
                preceding_failures = [
                    event
                    for timestamp, result, event in records[:index]
                    if result == "failure"
                    and window_start <= timestamp < success_time
                ]

                if len(preceding_failures) < self.failure_threshold:
                    continue

                findings.append({
                    "rule_id": "COR-001",
                    "rule_name": "Repeated Login Failures Followed by Success",
                    "severity": "high",
                    "description": (
                        "Repeated authentication failures were followed "
                        "by a successful login for the same account and "
                        "source IP within the configured time window."
                    ),
                    "host": host,
                    "username": username,
                    "source_ip": source_ip,
                    "failure_count": len(preceding_failures),
                    "window_minutes": int(self.window.total_seconds() // 60),
                    "event_ids": [
                        event.event_id for event in preceding_failures
                    ] + [success_event.event_id],
                    "mitre_tactics": ["Credential Access"],
                    "mitre_techniques": ["T1110"],
                })

        return findings

    @staticmethod
    def _auth_outcome(event: SecurityEvent) -> Optional[str]:
        """Extract a recognizable authentication outcome."""
        event_type = (event.event_type or "").lower()
        raw = event.raw_event or {}

        outcome = str(
            raw.get("outcome", raw.get("result", raw.get("status", "")))
        ).lower()

        combined = f"{event_type} {outcome}"

        if "auth" not in event_type and "login" not in event_type:
            return None

        if any(word in outcome for word in ("failure", "failed", "fail", "denied")):
            return "failure"

        if any(word in outcome for word in ("success", "succeeded", "accepted")):
            return "success"

        return None

    @staticmethod
    def _parse_timestamp(value: str) -> Optional[datetime]:
        """Parse an ISO-8601 timestamp, returning None if invalid."""
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, TypeError, AttributeError):
            return None
