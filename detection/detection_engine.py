
"""Rule-based detection and correlation engine for security events."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4

from detection.event_schema import SecurityEvent
from detection.mitre.attack_mapping import get_attack_mapping
from detection.correlation.correlation_engine import CorrelationEngine


@dataclass
class DetectionAlert:
    """Represents a detection raised by a rule or correlation."""

    rule_id: str
    rule_name: str
    severity: str
    description: str
    event_id: str
    event_type: str
    source: str
    host: str
    timestamp: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert into a JSON-compatible dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "host": self.host,
            "timestamp": self.timestamp,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "evidence": self.evidence,
        }


class DetectionEngine:
    """Evaluate events using individual rules and correlation rules."""

    def __init__(
        self,
        rules: Optional[List[Dict[str, Any]]] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
    ):
        self.rules = rules if rules is not None else self.default_rules()
        self.correlation_engine = (
            correlation_engine
            if correlation_engine is not None
            else CorrelationEngine()
        )

    @staticmethod
    def default_rules() -> List[Dict[str, Any]]:
        """Return the initial defensive detection rules."""
        return [
            {
                "id": "DET-001",
                "name": "Suspicious Shell Execution",
                "description": (
                    "A shell was executed with a command pattern "
                    "that deserves investigation."
                ),
                "severity": "medium",
                "event_types": ["process_execution"],
                "process_names": ["bash", "sh", "zsh", "dash"],
                "command_contains": ["-c", "base64", "curl", "wget"],
            },
            {
                "id": "DET-002",
                "name": "Script Interpreter Execution",
                "description": (
                    "A script interpreter executed a command. Review "
                    "the process context to determine whether it is suspicious."
                ),
                "severity": "low",
                "event_types": ["process_execution"],
                "process_names": [
                    "python", "python3", "perl", "ruby", "node"
                ],
                "command_contains": [],
            },
            {
                "id": "DET-003",
                "name": "Connection to Unusual Network Port",
                "description": (
                    "A network event used a port commonly worth "
                    "investigating. Validate it against local policy."
                ),
                "severity": "medium",
                "event_types": ["network_connection"],
                "destination_ports": [4444, 5555, 6667, 31337],
            },
        ]

    def evaluate(self, event: SecurityEvent) -> List[DetectionAlert]:
        """Evaluate one event against individual detection rules."""
        alerts: List[DetectionAlert] = []

        for rule in self.rules:
            if self._matches(rule, event):
                alerts.append(self._create_alert(rule, event))

        return alerts

    def evaluate_many(
        self,
        events: List[SecurityEvent],
        include_correlations: bool = True,
    ) -> List[DetectionAlert]:
        """Evaluate events and optionally generate correlation alerts."""
        alerts = self.evaluate_events(events)

        if include_correlations:
            alerts.extend(self.evaluate_correlations(events))

        return alerts

    def evaluate_events(
        self, events: List[SecurityEvent]
    ) -> List[DetectionAlert]:
        """Run the individual event rules over multiple events."""
        alerts: List[DetectionAlert] = []

        for event in events:
            alerts.extend(self.evaluate(event))

        return alerts

    def evaluate_correlations(
        self, events: List[SecurityEvent]
    ) -> List[DetectionAlert]:
        """Convert correlation findings into standard detection alerts."""
        findings = self.correlation_engine.detect_login_brute_force(events)
        alerts: List[DetectionAlert] = []

        events_by_id = {event.event_id: event for event in events}

        for finding in findings:
            correlated_ids = finding.get("event_ids", [])
            anchor_event = next(
                (
                    events_by_id[event_id]
                    for event_id in reversed(correlated_ids)
                    if event_id in events_by_id
                ),
                None,
            )

            if anchor_event is None:
                continue

            alerts.append(
                DetectionAlert(
                    rule_id=finding["rule_id"],
                    rule_name=finding["rule_name"],
                    severity=finding["severity"],
                    description=finding["description"],
                    event_id=anchor_event.event_id,
                    event_type=anchor_event.event_type,
                    source=anchor_event.source,
                    host=finding["host"],
                    timestamp=anchor_event.timestamp,
                    mitre_tactics=list(finding.get("mitre_tactics", [])),
                    mitre_techniques=list(
                        finding.get("mitre_techniques", [])
                    ),
                    evidence={
                        "username": finding.get("username"),
                        "source_ip": finding.get("source_ip"),
                        "failure_count": finding.get("failure_count", 0),
                        "window_minutes": finding.get("window_minutes"),
                        "correlated_event_ids": correlated_ids,
                    },
                )
            )

        return alerts

    @staticmethod
    def _matches(rule: Dict[str, Any], event: SecurityEvent) -> bool:
        """Check whether an event satisfies a rule's conditions."""
        event_types = rule.get("event_types", [])
        if event_types and event.event_type not in event_types:
            return False

        process_names = rule.get("process_names", [])
        if process_names:
            process_name = (
                event.process.name.lower()
                if event.process and event.process.name
                else ""
            )
            if process_name not in [name.lower() for name in process_names]:
                return False

        command_patterns = rule.get("command_contains", [])
        if command_patterns:
            command_line = (
                event.process.command_line.lower()
                if event.process and event.process.command_line
                else ""
            )
            if not any(
                pattern.lower() in command_line
                for pattern in command_patterns
            ):
                return False

        destination_ports = rule.get("destination_ports", [])
        if destination_ports:
            destination_port = (
                event.network.destination_port if event.network else None
            )
            if destination_port not in destination_ports:
                return False

        return True

    @staticmethod
    def _create_alert(
        rule: Dict[str, Any], event: SecurityEvent
    ) -> DetectionAlert:
        """Build an alert and obtain its ATT&CK mapping centrally."""
        process = event.process
        network = event.network
        evidence: Dict[str, Any] = {}

        if process:
            evidence["process"] = {
                "pid": process.pid,
                "name": process.name,
                "executable": process.executable,
                "command_line": process.command_line,
                "parent_name": process.parent_name,
            }

        if network:
            evidence["network"] = {
                "source_ip": network.source_ip,
                "destination_ip": network.destination_ip,
                "destination_port": network.destination_port,
                "protocol": network.protocol,
            }

        mapping = get_attack_mapping(rule["id"])

        return DetectionAlert(
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule.get("severity", "low"),
            description=rule["description"],
            event_id=event.event_id,
            event_type=event.event_type,
            source=event.source,
            host=event.host,
            timestamp=event.timestamp,
            mitre_tactics=list(mapping.get("tactics", [])),
            mitre_techniques=[
                technique["id"]
                for technique in mapping.get("techniques", [])
            ],
            evidence=evidence,
        )