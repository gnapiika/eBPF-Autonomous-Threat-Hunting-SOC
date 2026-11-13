"""Explicit integration between the detection engine and the SOAR webhook."""

from typing import List

from detection.detection_engine import DetectionAlert, DetectionEngine
from detection.event_schema import SecurityEvent
from soar.n8n_webhook import N8nWebhookClient


class DetectionSoarIntegration:
    """Evaluate events and forward resulting alerts to n8n."""

    def __init__(
        self,
        detection_engine: DetectionEngine,
        webhook_client: N8nWebhookClient,
    ) -> None:
        self.detection_engine = detection_engine
        self.webhook_client = webhook_client

    def process_events(
        self,
        events: List[SecurityEvent],
        include_correlations: bool = True,
    ) -> List[DetectionAlert]:
        """Evaluate a batch, forward its alerts, and return those alerts."""
        alerts = self.detection_engine.evaluate_many(
            events,
            include_correlations=include_correlations,
        )
        self.webhook_client.send_alerts(alerts)
        return alerts
