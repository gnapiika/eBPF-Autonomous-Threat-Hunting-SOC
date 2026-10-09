"""Rule-based detection engine for normalized security events."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import uuid4

from detection.event_schema import SecurityEvent
from detection.mitre.attack_mapping import get_attack_mapping


@dataclass
class DetectionAlert:
    """Represents a detection raised by a security rule."""

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
    """Evaluate normalized events against configurable detection rules."""

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        self.rules = rules if rules is not None else self.default_rules()

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
                    "A script interpreter executed a command. "
                    "Review the process context to determine whether "
                    "the activity is suspicious."
                ),
                "severity": "low",
                "event_types": ["process_execution"],
                "process_names": [
                    "python",
                    "python3",
                    "perl",
                    "ruby",
                    "node",
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
        """Return all alerts whose rules match the supplied event."""
        alerts: List[DetectionAlert] = []

        for rule in self.rules:
            if self._matches(rule, event):
                alerts.append(self._create_alert(rule, event))

        return alerts

    def evaluate_many(
        self, events: List[SecurityEvent]
    ) -> List[DetectionAlert]:
        """Evaluate multiple events and return all generated alerts."""
        alerts: List[DetectionAlert] = []

        for event in events:
            alerts.extend(self.evaluate(event))

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
                event.network.destination_port
                if event.network
                else None
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
            mitre_tactics=mapping["tactics"],
            mitre_techniques=[
                technique["id"]
                for technique in mapping["techniques"]
            ],
            evidence=evidence,
        )
