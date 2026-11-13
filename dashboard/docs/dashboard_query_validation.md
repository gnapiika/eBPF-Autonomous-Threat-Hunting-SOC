# SOC Dashboard Query Validation

## Objective
Validate the Elasticsearch queries and fields required by the Grafana SOC dashboard.

## Environment
- Dashboard: eBPF Autonomous Threat Hunting SOC
- Visualization: Grafana
- Data source: Elasticsearch
- Index: security-events
- Timestamp field: @timestamp

## Validation Results

### 1. Total Security Events
Query:
FROM security-events
| STATS total_events = COUNT(*)

Result: PASS
Observed total: 1 event.

### 2. Security Events by Severity
Query:
FROM security-events
| STATS event_count = COUNT(*) BY severity

Result: PASS
Observed result: 1 event with medium severity.

### 3. Security Events Detail Fields
Query:
FROM security-events
| KEEP @timestamp, event_type, host, message, process_name, severity

Result: PASS
All six requested fields were returned.

Observed test record:
- Event type: process_execution
- Host: kali-lab
- Process name: suspicious-test-process
- Severity: medium
- Timestamp: 2026-10-13T10:00:00.000Z

### 4. Hourly Event Trend
Validation query:
FROM security-events
| STATS event_count = COUNT(*) BY bucket = DATE_TRUNC(1 hour, @timestamp)

Result: PASS
Observed result: 1 event in the hourly bucket beginning at 2026-10-13T10:00:00.000Z.

## Limitations
- The validated record is synthetic test data, not confirmed live eBPF telemetry.
- These tests validate Elasticsearch query execution and required data fields.
- Successful execution does not, by itself, confirm that every Grafana panel renders correctly in the browser.
- End-to-end integration with live telemetry remains pending.

## Scope
This validation covers the Member 4 dashboard work only.
No files belonging to other project members were changed.
