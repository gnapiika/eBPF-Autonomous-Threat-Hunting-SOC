# Day 3 — Security Events Detail Table

## Project
eBPF Autonomous Threat Hunting SOC

**Role:** Member 4 — SOC Dashboard, Visualization & Attack Simulation

**Branch:** `member4-dashboard`

## Objective
Add a table visualization to display individual security event records in Grafana.

## Work Completed

### 1. Dashboard Verification
- Opened the existing eBPF Autonomous Threat Hunting SOC dashboard.
- Set the dashboard time range to Last 7 days.
- Verified that the total event count was 1.
- Verified one medium-severity event in the severity chart.

### 2. Security Events Detail Table
- Added a new panel using the existing Elasticsearch data source.
- Selected the Raw Data query type.
- Changed the visualization to Table.
- Verified that the synthetic security event record appeared in the table.
- Set the panel title to `Security Events Detail Table`.

## Validation Results
- Total Security Events: 1
- Medium-severity events: 1
- Security Events Detail Table: Displaying the synthetic event record.

## Important Note
The dashboard currently uses synthetic test data. This does not represent verified live eBPF telemetry. Integration with the project's live event pipeline remains pending.

## Next Steps
- Export and version-control the Grafana dashboard configuration.
- Improve the table columns to show relevant event fields clearly.
- Integrate live telemetry when the event pipeline becomes available.
