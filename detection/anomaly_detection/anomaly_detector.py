
"""Lightweight statistical anomaly detection for security events."""

from collections import Counter
from typing import Any, Dict, List

from detection.event_schema import SecurityEvent


class AnomalyDetector:
    """Flag hosts with unusually high event activity."""

    def __init__(self, minimum_events: int = 5, threshold_multiplier: float = 2.0):
        if minimum_events < 1:
            raise ValueError("minimum_events must be at least 1")
        if threshold_multiplier <= 0:
            raise ValueError("threshold_multiplier must be greater than 0")

        self.minimum_events = minimum_events
        self.threshold_multiplier = threshold_multiplier

    def detect_event_bursts(
        self, events: List[SecurityEvent]
    ) -> List[Dict[str, Any]]:
        """Flag hosts whose event count is unusually high in this batch."""
        if not events:
            return []

        counts = Counter(event.host for event in events if event.host)
        if not counts:
            return []

        baseline = sum(counts.values()) / len(counts)
        threshold = max(
            self.minimum_events,
            baseline * self.threshold_multiplier,
        )

        findings = []
        for host, count in counts.items():
            if count >= threshold and count > baseline:
                findings.append(
                    {
                        "rule_id": "ANOM-001",
                        "rule_name": "Unusually High Event Volume",
                        "severity": "medium",
                        "description": (
                            "This host generated more events than the "
                            "average host in the supplied event batch."
                        ),
                        "host": host,
                        "event_count": count,
                        "baseline_average": round(baseline, 2),
                        "threshold": round(threshold, 2),
                        "event_ids": [
                            event.event_id
                            for event in events
                            if event.host == host
                        ],
                    }
                )

        return findings