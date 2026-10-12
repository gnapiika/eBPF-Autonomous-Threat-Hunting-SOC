
"""Service combining anomaly detection and MITRE ATT&CK enrichment."""

from typing import Any, Dict, List

from detection.anomaly_detection.anomaly_detector import AnomalyDetector
from detection.anomaly_detection.mitre_enrichment import (
    enrich_anomaly_finding,
)
from detection.event_schema import SecurityEvent


class AnomalyDetectionService:
    """Run statistical anomaly detection and enrich its findings."""

    def __init__(
        self,
        detector: AnomalyDetector | None = None,
    ) -> None:
        self.detector = detector or AnomalyDetector()

    def analyze(
        self,
        events: List[SecurityEvent],
    ) -> List[Dict[str, Any]]:
        """Analyze a batch of events and return enriched findings."""
        findings = self.detector.detect_event_bursts(events)

        return [
            enrich_anomaly_finding(finding)
            for finding in findings
        ]