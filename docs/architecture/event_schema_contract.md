
# Security Event Schema Contract

**Owner:** Member 2 — Detection, MITRE ATT&CK and Threat Hunting

## 1. Purpose

This contract defines the common event format used by telemetry
collection, normalization, detection, response, and dashboard components.

## 2. Event lifecycle

Raw telemetry -> Normalizer -> SecurityEvent -> Detection -> Alert

Kafka is the planned transport layer. The exact integration method
must be confirmed with Member 1.

## 3. Common fields

| Field | Type | Requirement | Description |
|---|---|---|---|
| event_id | string | Required | Unique event identifier |
| event_type | string | Required | Normalized activity category |
| source | string | Required | Original collector |
| host | string | Required | Host that generated the event |
| timestamp | string | Required | ISO 8601 timestamp |
| process | object | Optional | Process information |
| user | object | Optional | User information |
| network | object | Optional | Network/socket details |
| file | object | Optional | File activity details |
| severity | string | Optional | Severity assigned by detection |
| tags | array | Optional | Event labels |
| raw_event | object | Optional | Original telemetry payload |
| mitre_tactics | array | Optional | Associated ATT&CK tactic IDs |
| mitre_techniques | array | Optional | Associated ATT&CK technique IDs |
| metadata | object | Optional | Additional context |

The implementation's actual dataclass definitions are authoritative.
If this document and the implementation differ, update this contract
after reviewing the change with the team.

## 4. Normalized event types

Use consistent names where the source provides sufficient evidence:

- process_execution
- file_activity
- network_connection
- authentication

Additional event types can be introduced as required.

## 5. Timestamp rules

- Use ISO 8601 timestamps.
- Preserve timezone information whenever available.
- Normalize timestamps consistently.
- Do not silently invent an event time if the source timestamp is missing.

## 6. MITRE ATT&CK mapping rules

- Map based on observed behavior and supporting evidence.
- Preserve the event even when no technique can be confidently assigned.
- Do not treat an unusual port or high event volume alone as proof of an attack.
- Keep detection findings separate from confirmed incident conclusions.

## 7. Integration responsibilities

### Member 1 — Telemetry

Provide raw event examples, source fields, timestamp formats, and Kafka
transport details.

### Member 2 — Detection

Normalize events, maintain the schema, validate mappings, and provide
detection alerts with evidence.

### Member 3 — SOAR

Consume the agreed alert structure and test a safe webhook workflow.

### Member 4 — Dashboard

Consume agreed event and alert fields for visualizations.

## 8. Week 1 acceptance criteria

- [ ] Schema implementation reviewed.
- [ ] At least one representative raw event obtained.
- [ ] Normalizer tested with the agreed event format.
- [ ] Timestamp and event-type handling verified.
- [ ] MITRE mapping behavior tested.
- [ ] Contract shared with the other members.
- [ ] Integration dependencies documented.