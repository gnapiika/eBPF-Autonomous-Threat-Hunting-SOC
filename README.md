# eBPF-Powered Autonomous Threat Hunting SOC

## Project Overview

An eBPF-powered autonomous Security Operations Center (SOC) framework designed
to monitor Linux systems, detect suspicious behavior, map threats to MITRE
ATT&CK techniques, perform automated response, collect forensic evidence,
and visualize security telemetry in real time.

This project is being developed as part of the Cybersecurity Internship at
Zaalima Development Pvt. Ltd.

---

## Problem Statement

Design a next-generation Security Operations Center (SOC) framework utilizing
extended Berkeley Packet Filter (eBPF) for deep, low-overhead kernel-level
telemetry.

The system aims to:

- Monitor Linux systems at the kernel level
- Collect process, file, and network activity
- Stream telemetry through Apache Kafka
- Correlate events into process execution chains
- Detect behavioral anomalies and malicious activity
- Map detected activity to MITRE ATT&CK
- Execute automated threat response
- Collect forensic evidence
- Visualize threats through a SOC dashboard

---

## Architecture

```text
Linux Servers
      |
      v
eBPF / Tetragon / Falco
      |
      v
Apache Kafka
      |
      v
Event Processing / CEP
      |
      +----------------------+
      |                      |
      v                      v
Detection Engine       Threat Hunting
      |                      |
      +----------+-----------+
                 |
                 v
        MITRE ATT&CK Mapping
                 |
                 v
              SOAR
          n8n / Cortex
                 |
                 v
       Automated Response
                 |
                 v
       Forensic Evidence
                 |
                 v
       SOC Dashboard
      Grafana / Kibana
```

## Week 1 SOAR Webhook Integration (n8n)

The detection engine can forward generated alerts to an n8n webhook. This
integration only sends alert data; it does not perform containment or other
response actions.

1. In n8n, create a workflow with a **Webhook** trigger using the `POST` method.
   Activate the workflow and copy its production webhook URL.
2. Set the URL in the environment before running the integration:

   ```powershell
   $env:N8N_WEBHOOK_URL = "http://localhost:5678/webhook/soc-alerts"
   ```

3. Evaluate events and forward any alerts:

   ```python
   from detection.detection_engine import DetectionEngine
   from soar.detection_integration import DetectionSoarIntegration
   from soar.n8n_webhook import N8nWebhookClient

   integration = DetectionSoarIntegration(
       detection_engine=DetectionEngine(),
       webhook_client=N8nWebhookClient.from_env(),
   )
   alerts = integration.process_events(events)
   ```

The webhook receives one JSON `POST` per alert with a `source` field and an
`alert` object containing the detection alert fields. Network and non-success
HTTP errors are raised to the caller rather than being silently ignored.

## Week 1 SOAR Integration — Test Results

### Objective

Verify that the Python Detection Engine can identify a simulated suspicious
process event, generate a security alert, and pass the alert to the n8n SOAR
webhook.

### Integration Flow

```text
Simulated Process Event
          |
          v
Python Detection Engine
          |
          v
Detection Rule: DET-001
Suspicious Shell Execution
          |
          v
Generated Security Alert
          |
          v
SOAR Integration
          |
          v
n8n Webhook (HTTP POST)
```

### Detection Test

A simulated bash process event is used to test the detection pipeline. The
test does not execute the shell command.

The detection rule `DET-001` matches the suspicious shell execution pattern.
The generated alert contains the following information:

| Field | Value |
|---|---|
| Detection Rule | `DET-001` |
| Rule Name | Suspicious Shell Execution |
| Severity | Medium |
| MITRE ATT&CK Tactic | Execution |
| MITRE ATT&CK Technique | `T1059` |
| Evidence | Process name and command line |

### Webhook Integration

The SOAR integration forwards generated alerts to the configured n8n webhook
using an HTTP `POST` request with JSON data.

The webhook client reports unsuccessful HTTP responses and network errors to
the caller rather than silently ignoring them.

### Verification and Evidence

The following checks are part of the Week 1 verification:

- [ ] Generate a simulated security alert through the Python Detection Engine.
- [ ] Test the Python-to-n8n webhook integration.
- [ ] Confirm the latest detection-generated alert in the n8n execution history.
- [ ] Capture screenshots of the successful test and n8n execution.

**Evidence to collect:**

1. Python terminal output showing the generated alert.
2. n8n execution details showing the received alert payload.
3. Test output showing the result of the integration tests.

### Scope and Limitations

This Week 1 implementation focuses on alert generation and webhook
communication. It does not yet terminate processes, isolate hosts, block
network connections, or perform automated remediation.

### Next Steps

- Verify end-to-end alert delivery.
- Document and preserve test evidence.
- Commit the Week 1 integration files to the `member3-soar` GitHub branch.
- Develop safe, simulated response workflows in the next phase.

## Week 2 n8n Alert Routing

Week 2 adds a severity check and safe simulated response labels to the n8n
workflow. See the [Week 2 guide](docs/week-2-n8n-alert-routing.md) for the
workflow configuration, test results, and repeatable test instructions.

## Week 3 Response and Evidence Collection

Week 3 now includes safe dry-run response planning and forensic evidence
bundles from normalized events. See the
[Week 3 remediation and evidence guide](docs/week-3-remediation-and-evidence.md)
for the implementation, test instructions, limitations, and remaining live
containment requirements. The separate
[n8n response guide](docs/week-3-n8n-alert-response.md) covers simulated
workflow labels; it does not represent host remediation.
