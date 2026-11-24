
"""Behavior-based detection for suspicious process activity."""

from typing import Any, Dict, List

from detection.event_schema import SecurityEvent
from detection.mitre.attack_mapping import canonical_mitre


SUSPICIOUS_COMMAND_INDICATORS = (
    "base64",
    "curl ",
    "wget ",
    "chmod ",
    "/dev/tcp/",
    "nc -",
    "ncat ",
    "powershell -enc",
)


class BehaviorDetector:
    """Identify suspicious command patterns in process events."""

    def analyze(
        self,
        events: List[SecurityEvent],
    ) -> List[Dict[str, Any]]:
        findings = []

        for event in events:
            if event.event_type != "process_execution":
                continue

            process = event.process
            process_name = (process.name or "").lower()
            command_line = (process.command_line or "").lower()

            indicators = [
                indicator
                for indicator in SUSPICIOUS_COMMAND_INDICATORS
                if indicator in command_line
            ]

            if not indicators:
                continue

            findings.append(
                {
                    "rule_id": "BEHAV-001",
                    "rule_name": "Suspicious Command Pattern",
                    "severity": "medium",
                    "description": (
                        "The process command contains one or more "
                        "patterns that warrant security investigation."
                    ),
                    "host": event.host,
                    "event_id": event.event_id,
                    "timestamp": event.timestamp,
                    "process_name": process_name,
                    "command_line": process.command_line,
                    "indicators": indicators,
                    "mitre_tactics": ["TA0002"],
                    "mitre_techniques": ["T1059"],
                    "mitre": canonical_mitre(
                        ["TA0002"],
                        ["T1059"],
                    ),
                }
            )

        return findings