# Canonical Event, Alert, and Response Contract

**Schema version:** `1.0`

This contract is the shared boundary for telemetry normalization, detection,
SOAR, forensic evidence, and dashboard storage. Raw collector payloads remain
source-specific; the normalizer converts them to the canonical event schema.

## 1. Canonical event

The canonical event is serialized with these fields:

| Field | Type | Requirement | Meaning |
|---|---|---|---|
| `schema_version` | string | Required | Contract version, currently `1.0` |
| `producer` | string | Emitted | Canonical record producer |
| `synthetic` | boolean | Emitted | True for explicitly marked synthetic data |
| `event_id` | string | Required | Stable event identifier |
| `event_type` | string | Required | Normalized activity, such as `process_execution` |
| `source` | string | Required | Telemetry collector, such as `falco` or `tetragon` |
| `host` | string | Required | Host that generated the event |
| `@timestamp` | string | Required | ISO 8601 UTC timestamp used by Elasticsearch |
| `timestamp` | string | Required | Backward-compatible alias of `@timestamp` |
| `timestamp_source` | string | Required | `event` or `ingest`, identifying timestamp provenance |
| `severity` | string | Required | Lowercase event severity enum |
| `process` | object | Optional | Canonical nested process information |
| `process_name` | string | Optional | Backward-compatible alias of `process.name` |
| `user` | object | Optional | User identity information |
| `network` | object | Optional | Network endpoints, ports, and protocol |
| `file` | object | Optional | File path, operation, and hash |
| `mitre` | object | Required | Canonical ATT&CK tactics and techniques |
| `mitre_tactics` | array | Deprecated alias | Existing tactic values retained during migration |
| `mitre_techniques` | array | Deprecated alias | Existing technique values retained during migration |
| `tags` | array | Optional | Event labels |
| `metadata` | object | Optional | Source-specific normalized context |
| `raw_event` | object | Optional | Original collector payload |

`@timestamp` and `timestamp` must contain the same UTC value, formatted with a
`Z` suffix. A valid source timestamp is converted to UTC and sets
`timestamp_source` to `event`. If the source timestamp is absent, `@timestamp`
is the UTC ingestion time and `timestamp_source` is `ingest`; the original raw
payload remains available for investigation. Invalid timestamps must be
reported rather than silently treated as valid event time.

The accepted severity values are `critical`, `high`, `medium`, `low`, and
`info`. Source-specific values such as Falco `Warning` or `Notice` are mapped
to this enum before serialization.

`process` is canonical. It uses `pid`, `ppid`, `name`, `executable`,
`command_line`, `parent_name`, and `parent_executable` where available.
`process_name` is an additive dashboard compatibility alias and must equal
`process.name`.

The canonical ATT&CK representation uses objects so IDs and display names
cannot be confused:

```json
{
  "tactics": [{"id": "TA0002", "name": "Execution"}],
  "techniques": [
    {"id": "T1059", "name": "Command and Scripting Interpreter"}
  ]
}
```

The existing top-level `mitre_tactics` and `mitre_techniques` arrays remain
temporarily for compatibility. Their existing values are not authoritative:
historical producers have emitted both tactic names and IDs. New consumers
must use the canonical `mitre` object.

Example event:

```json
{
  "schema_version": "1.0",
  "event_id": "event-123",
  "event_type": "process_execution",
  "source": "falco",
  "host": "lab-host",
  "@timestamp": "2026-11-13T14:00:00.000Z",
  "timestamp": "2026-11-13T14:00:00.000Z",
  "timestamp_source": "event",
  "severity": "low",
  "process": {
    "pid": 424242,
    "name": "synthetic-lab-process",
    "command_line": "synthetic --demo"
  },
  "process_name": "synthetic-lab-process",
  "user": {"username": "lab-user"},
  "network": {},
  "file": {},
  "mitre": {"tactics": [], "techniques": []},
  "mitre_tactics": [],
  "mitre_techniques": [],
  "tags": ["falco"],
  "metadata": {},
  "raw_event": {}
}
```

## 2. Canonical alert

An alert represents a detection, not a confirmed incident. It uses the same
identity, source, host, timestamp, severity, process, and ATT&CK conventions as
an event, with these alert-specific fields:

| Field | Type | Requirement | Meaning |
|---|---|---|---|
| `schema_version` | string | Required | Contract version, currently `1.0` |
| `producer` | string | Emitted | Canonical record producer |
| `synthetic` | boolean | Emitted | True for explicitly marked synthetic data |
| `alert_id` | string | Required | Unique detection alert identifier |
| `rule_id` | string | Required | Detection or correlation rule identifier |
| `rule_name` | string | Required | Human-readable rule name |
| `description` | string | Required | Detection explanation |
| `event_id` | string | Required | Event that anchored the alert |
| `source` | string | Required | Telemetry collector that produced the event |
| `host` | string | Required | Host associated with the event |
| `@timestamp` | string | Required | ISO 8601 UTC event timestamp |
| `timestamp` | string | Required | Backward-compatible alias of `@timestamp` |
| `timestamp_source` | string | Required | `event` or `ingest` provenance |
| `severity` | string | Required | Lowercase shared severity enum |
| `process` | object | Optional | Canonical nested process information |
| `process_name` | string | Optional | Backward-compatible alias of `process.name` |
| `mitre` | object | Required | Canonical ATT&CK tactics and techniques |
| `evidence` | object | Required | Existing rule evidence, retained without restructuring |

Alert `severity` is the detection-rule severity; event `severity` is source or
normalized event severity. Both use the same lowercase enum, but they must not
be conflated. `process` is the canonical process view for consumers such as the
dashboard; existing `evidence.process`, `evidence.network`, and
`evidence.falco` fields remain unchanged.

The existing `mitre_tactics` and `mitre_techniques` alert arrays are retained
as deprecated aliases. The canonical `mitre` object is authoritative.

## 3. Webhook envelope and response package

The webhook retains the existing envelope and adds `producer` as the
unambiguous application identifier:

```json
{
  "schema_version": "1.0",
  "producer": "ebpf-autonomous-threat-hunting-soc",
  "source": "ebpf-autonomous-threat-hunting-soc",
  "alert": {},
  "response": {
    "alert_id": "same alert ID",
    "response_status": "simulated",
    "evidence": {},
    "response_plan": {
      "mode": "dry_run",
      "approval_required": true,
      "execution_performed": false,
      "actions": []
    }
  }
}
```

Top-level `source` is retained as a backward-compatible alias for `producer`.
`alert.source` always identifies the telemetry collector.

The response package contains `alert_id`, `response_status`, `evidence`, and
`response_plan`. The plan contains `mode`, `approval_required`,
`execution_performed`, and `actions`; actions retain their target and
simulation status.

The response package preserves the existing forensic evidence structure:
`evidence_id`, collection metadata, host, alert, event IDs, timestamps, process
information/tree, network connections, file information, relevant logs, raw
events, and coverage counts. `response_status` is `simulated`; each planned
action is marked `simulated`; `mode` is `dry_run`;
`approval_required` is `true`; and `execution_performed` is `false`.
This contract does not authorize or describe real containment.

## 4. Elasticsearch and dashboard contract

Use separate indices:

- `security-events` stores canonical event documents.
- `security-alerts` stores canonical alert documents and the associated
  response package when available.

Both use `@timestamp` as the Elasticsearch date field. The `security-events`
projection retains `event_type`, `host`, `severity`, and `source` as
top-level fields and exposes `process_name` for the current dashboard.
The `security-alerts` projection exposes `alert_id`, rule name, severity,
source, host, `@timestamp`, process fields, canonical `mitre`, response status,
and evidence.

The Elasticsearch alert document may additionally expose
`response_status` and `evidence_available` at the top level for dashboard
queries while retaining the complete `response` package. The separate
`external_workflow` object records webhook delivery metadata, not a workflow
result. In particular, a successful n8n HTTP request does not mean an n8n
workflow completed; `result_received` remains `false` until an actual result is
received.

The integrated Grafana dashboard configuration reads `security-events` and
`security-alerts` and defines event, alert, MITRE, response, and evidence
panels. This is a local configuration contract, not a claim that Elasticsearch
ingestion or Grafana queries have been validated against live services.

## 5. Migration and compatibility

- Keep `timestamp`, `process_name`, and the existing MITRE arrays as additive
  compatibility aliases; canonical fields take precedence when both forms
  are supplied.
- Keep vendor-native Kafka messages and `raw_event`; normalize at the
  detection boundary.
- Keep the webhook `source` and `alert` fields; add `producer` and `response`.
- Keep the forensic evidence field names and structure.
- Update readers to the canonical fields before removing any deprecated alias.

## 6. Ownership

- **Member 1:** publish raw source events and preserve collector provenance.
- **Member 2:** normalize events, generate canonical alerts, and enrich ATT&CK
  metadata.
- **Member 3:** forward canonical alerts and safe response/evidence packages.
- **Member 4:** consume the event and alert indices and render their documented
  fields.

The Kafka consumer appends the alert fields, a `response` package, and a Kafka `message_key` to its local JSONL. The webhook keeps the envelope above and the replay command omits the local transport key. Existing JSONL readers can continue reading the top-level alert fields.
