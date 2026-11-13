# SOC Dashboard

## Purpose
Build the visualization layer for the eBPF-Powered Autonomous Threat Hunting SOC using Grafana.

## Current Dashboard
Dashboard title: eBPF Autonomous Threat Hunting SOC

Implemented panels:
- Total Security Events
- Security Events by Severity
- Security Events Detail Table
- Security Events Trend

## Data Source
- Visualization platform: Grafana
- Data source: Elasticsearch
- Index: `security-events`
- Timestamp field: `@timestamp`

## Validation Notes
- The dashboard has been exported to `grafana/soc_dashboard.json`.
- A synthetic test event has been verified in Elasticsearch and displayed in Grafana.
- The current test event uses `event_type: process_execution`, `host: kali-lab`, and `severity: medium`.
- The test event is synthetic; live eBPF telemetry integration has not yet been verified through the dashboard.

## Integration Scope
The dashboard consumes security events through the agreed data interface. Dashboard development is limited to the `dashboard/` directory and does not modify other team members' implementation files.

## Current Status
- Dashboard prototype: implemented.
- Four visualization panels: configured.
- Dashboard JSON: exported and version-controlled.
- Live telemetry visualization: pending end-to-end validation.
