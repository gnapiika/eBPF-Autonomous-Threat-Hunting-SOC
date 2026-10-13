# Day 2 — Grafana and Elasticsearch Integration

## Project
eBPF Autonomous Threat Hunting SOC

**Role:** Member 4 — SOC Dashboard, Visualization & Attack Simulation

**Branch:** `member4-dashboard`

## Objective
Configure Elasticsearch as the Grafana data source and develop initial SOC dashboard visualizations using synthetic security event data.

## Work Completed

### 1. Elasticsearch Verification
- Verified that the Elasticsearch service was running.
- Confirmed connectivity through the HTTPS REST API.
- Verified the `security-events` index.

### 2. Grafana Integration
- Connected Grafana to Elasticsearch.
- Configured the Elasticsearch data source.
- Verified that Grafana could retrieve data from Elasticsearch.

### 3. Synthetic Security Event
- Verified one synthetic security event in the `security-events` index.
- Confirmed the event fields, including timestamp, event type, source, host, severity, process name, and message.

### 4. Dashboard Development
- Created the `eBPF Autonomous Threat Hunting SOC` Grafana dashboard.
- Created the `Total Security Events` Stat panel.
- Configured an ES|QL query to count security events.
- Verified that the panel displayed one event.
- Created the `Security Events by Severity` bar chart.
- Configured an ES|QL aggregation to group events by severity.
- Verified that the chart displayed one medium-severity event.

## Queries Used

### Total Security Events
```esql
FROM security-events
| STATS total_events = COUNT(*)
```

### Security Events by Severity
```esql
FROM security-events
| STATS event_count = COUNT(*) BY severity
```

## Results
- Elasticsearch data source: Connected
- Security events index: Verified
- Synthetic test events: 1
- Total Security Events panel: Working
- Security Events by Severity chart: Working

## Important Note
The dashboard currently uses synthetic test data for validation. Live eBPF telemetry and integration with the project's detection pipeline are pending.

## Next Steps
- Develop additional SOC dashboard panels.
- Add security event trends and detailed event tables.
- Integrate live telemetry when the event pipeline becomes available.
- Continue testing and documenting dashboard development.
