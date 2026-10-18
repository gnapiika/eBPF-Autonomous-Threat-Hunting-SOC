
# Week 1: Security Event Schema and MITRE ATT&CK Mapping

## 1. Objective

Define a common security event format that converts raw telemetry
from eBPF, Tetragon, or Falco into structured security events that
can be analyzed and mapped to the MITRE ATT&CK.

## 2. Event Processing Flow

Raw Telemetry
    |
    v
Event Normalization
    |
    v
Common Security Event Schema
    |
    v
Detection and Correlation
    |
    v
MITRE ATT&CK Mapping
    |
    v
Security Alert

Kafka is the planned streaming layer for transporting telemetry
between collection and downstream processing components.

## 3. Raw Telemetry Sources

- eBPF: Kernel-level event collection.
- Tetragon: Process and security observability events.
- Falco: Runtime security event detection.
- Kafka: Streaming transport for telemetry events.

The actual source and event format depend on the telemetry
collector selected and configured by Member 1.

## 4. Common Security Event Fields

| Field | Description |
|---|---|
| event_id | Unique identifier for the event |
| event_type | Type of activity, such as process_execution |
| source | Collector that produced the event |
| host | Host where the activity occurred |
| timestamp | Event time in ISO 8601 format |
| process | Process name, command line, PID, and related data |
| user | User associated with the activity |
| network | Source/destination addresses, ports, and protocol |
| file | File path and related file activity |
| severity | Event severity, when assigned |
| tags | Additional classification labels |
| raw_event | Original telemetry payload |
| mitre_tactics | Associated MITRE ATT&CK tactic identifiers |
| mitre_techniques | Associated MITRE ATT&CK technique identifiers |
| metadata | Additional source-specific information |

Optional fields may be absent when the telemetry source does not
provide the corresponding information.

## 5. Normalization

The event normalizer converts source-specific payloads into the
common SecurityEvent representation.

Expected normalization responsibilities:

1. Identify the telemetry source.
2. Extract the event type and host.
3. Normalize timestamps.
4. Extract available process, user, file, and network fields.
5. Preserve the original payload for investigation.
6. Produce a structured event for downstream detection.

## 6. MITRE ATT&CK Mapping

MITRE ATT&CK mappings should be based on observable behavior
and supporting evidence.

| Observed behavior | Potential technique |
|---|---|
| Suspicious command or script execution | T1059 |
| Confirmed use of a non-standard protocol or port for C2 | T1571 |

A suspicious port or high event volume alone does not establish
that an attack technique occurred. Mappings must be validated
against event context and detection evidence.

## 7. Example Normalized Event

{
  "event_type": "process_execution",
  "source": "tetragon",
  "host": "server-01",
  "timestamp": "2026-10-14T10:30:00Z",
  "process": {
    "name": "bash",
    "command_line": "bash -c whoami"
  },
  "user": {
    "name": "analyst"
  },
  "mitre_tactics": [],
  "mitre_techniques": []
}

This is an illustrative example. The final payload must match the
actual SecurityEvent implementation and the telemetry fields
provided by Member 1.

## 8. Integration Responsibilities

- Member 1 provides representative raw telemetry samples and
  documents the collection and Kafka pipeline.
- Member 2 maintains the common event schema, normalization
  logic, and evidence-based MITRE mapping.
- Member 3 defines the alert input format for SOAR integration.
- Member 4 defines the event and alert fields needed by the dashboard.

## 9. Week 1 Validation Checklist

- [ ] Common security event schema documented.
- [ ] Raw telemetry examples obtained from Member 1.
- [ ] Event normalization tested against representative payloads.
- [ ] Timestamps and event types validated.
- [ ] MITRE mappings reviewed for evidence and correctness.
- [ ] Schema and sample payload shared with the team.
- [ ] Integration assumptions documented.