"""Explicit integration between the detection engine and the SOAR webhook."""

from typing import Any, Dict, List, Optional, Sequence

from detection.detection_engine import DetectionAlert, DetectionEngine
from detection.event_schema import SecurityEvent
from soar.n8n_webhook import N8nWebhookClient
from soar.response.week3_workflow import Week3ResponseWorkflow


class DetectionSoarIntegration:
    """Evaluate events and forward resulting alerts to n8n."""

    def __init__(
        self,
        detection_engine: DetectionEngine,
        webhook_client: N8nWebhookClient,
        response_workflow: Optional[Week3ResponseWorkflow] = None,
    ) -> None:
        self.detection_engine = detection_engine
        self.webhook_client = webhook_client
        self.response_workflow = response_workflow or Week3ResponseWorkflow()

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
        self.forward_alerts(alerts, events)
        return alerts

    def forward_alerts(
        self,
        alerts: List[DetectionAlert],
        events: Optional[Sequence[SecurityEvent]] = None,
        response_packages: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> List[int]:
        """Forward existing alerts, optionally attaching evidence and dry-run plans."""
        if response_packages is None and events is None:
            return self.webhook_client.send_alerts(alerts)

        if response_packages is None:
            response_packages = [
                self.response_workflow.process_alert(alert, events)
                for alert in alerts
            ]
        elif len(response_packages) != len(alerts):
            raise ValueError("response_packages must match the alerts length")

        return self.webhook_client.send_alerts(
            alerts,
            response_packages=list(response_packages),
        )
