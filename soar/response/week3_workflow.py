"""Evidence collection and simulated response planning for Week 3."""

from ipaddress import ip_address
from typing import Any, Dict, List, Optional, Sequence

from detection.detection_engine import DetectionAlert, DetectionEngine
from detection.event_schema import SecurityEvent
from forensic.evidence_collection.collector import ForensicEvidenceCollector


class Week3ResponseWorkflow:
    """Collect supplied evidence and create non-executing response actions."""

    def __init__(
        self,
        evidence_collector: Optional[ForensicEvidenceCollector] = None,
    ) -> None:
        self.evidence_collector = (
            evidence_collector or ForensicEvidenceCollector()
        )

    def process_alert(
        self,
        alert: DetectionAlert,
        events: Sequence[SecurityEvent],
    ) -> Dict[str, Any]:
        """Return an evidence bundle and simulated containment plan."""
        if not isinstance(alert, DetectionAlert):
            raise TypeError("alert must be a DetectionAlert")

        alert_events = [event for event in events if event.host == alert.host]
        if not alert_events:
            raise ValueError("events must include at least one event from the alert host")

        evidence = self.evidence_collector.collect(alert_events, alert=alert)
        return {
            "alert_id": alert.alert_id,
            "response_status": "simulated",
            "evidence": evidence,
            "response_plan": self._plan_containment(alert),
        }

    def process_events(
        self,
        detection_engine: DetectionEngine,
        events: Sequence[SecurityEvent],
    ) -> List[Dict[str, Any]]:
        """Detect alerts and build a response package for each alert."""
        event_batch = list(events)
        alerts = detection_engine.evaluate_many(event_batch)
        return [
            self.process_alert(alert, event_batch)
            for alert in alerts
        ]

    @staticmethod
    def _plan_containment(alert: DetectionAlert) -> Dict[str, Any]:
        evidence = alert.evidence
        process = evidence.get("process", {})
        network = evidence.get("network", {})
        actions = []

        pid = process.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            actions.append(
                {
                    "action": "process_isolation",
                    "target": {"host": alert.host, "pid": pid},
                    "status": "simulated",
                }
            )

        destination_ip = network.get("destination_ip")
        if isinstance(destination_ip, str):
            try:
                normalized_ip = str(ip_address(destination_ip))
            except ValueError:
                normalized_ip = None
            if normalized_ip:
                actions.append(
                    {
                        "action": "network_containment",
                        "target": {
                            "host": alert.host,
                            "destination_ip": normalized_ip,
                        },
                        "status": "simulated",
                    }
                )

        return {
            "mode": "dry_run",
            "approval_required": True,
            "execution_performed": False,
            "actions": actions,
            "message": (
                "Containment actions are recommendations only; "
                "no process or network state was changed."
            ),
        }
