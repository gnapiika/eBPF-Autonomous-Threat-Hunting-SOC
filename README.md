# eBPF-Powered Autonomous Threat Hunting SOC

An intelligent Security Operations Center (SOC) framework that monitors Linux systems, detects suspicious activities, maps threats to MITRE ATT&CK, and supports automated incident response and security visualization.

**Developed as part of the Cybersecurity Internship at Zaalima Development Pvt. Ltd.**

## 1. Project Overview

Traditional security monitoring systems generate large volumes of logs, making threat detection and investigation challenging. This project aims to simplify security monitoring through automated telemetry collection, behavioral analysis, threat detections, and incident response.

### Objectives
- Monitor Linux process, file, and network activities.
- Collect and stream all security events using eBPF-based tools and Apache Kafka.
- Normalize and analyze events for suspicious behavior.
- Detect threats using rule-based and behavioral analysis.
- Map detections to MITRE ATT&CK.
- Support automated incident response through SOAR workflows.
- Store forensic evidence and visualize security alerts.

## 2. System Architecture

```text
Linux Systems
     |
     v
eBPF / Falco / Tetragon
     |
     v
Apache Kafka
<<<<<<< HEAD
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
=======
     |
     v
Event Processing
     |
     +-------------------+
     |                   |
     v                   v
Detection Engine    Threat Hunting
     |                   |
     +---------+---------+
               |
               v
       MITRE ATT&CK Mapping
               |
               v
         Alert Generation
               |
               v
          SOAR / n8n
               |
               v
      Automated Response
               |
               v
    Elasticsearch / Storage
               |
               v
       Grafana / Kibana
```

*The architecture represents the overall system design. Integrations are validated progressively during development.*

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Event processing and threat detection |
| eBPF, Falco, Tetragon | Linux telemetry collection |
| Apache Kafka | Real-time event streaming |
| MITRE ATT&CK | Threat classification |
| n8n / Cortex | SOAR and incident response |
| Elasticsearch | Security data storage and search |
| Grafana / Kibana | Security dashboards |
| pytest | Automated testing |
| Git / GitHub | Version control |

## 4. Core Modules

- **Telemetry Collection:** Monitors Linux system activities using configured security monitoring tools.
- **Event Processing:** Normalizes raw telemetry into structured security events and streams them through Kafka.
- **Detection Engine:** Identifies suspicious activities using detection rules and statistical anomaly analysis.
- **Threat Hunting:** Investigates suspicious patterns and maps supported detections to MITRE ATT&CK.
- **SOAR Integration:** Supports webhook-based alert routing and automated response workflows.
- **Forensics and Visualization:** Preserves alert evidence and supports security monitoring through dashboards.

## 5. Sample Security Alert

Alerts are generated in structured JSON format to enable communication between system modules.

```json
{
  "alert_id": "ALERT-001",
  "rule_name": "Suspicious Process Execution",
  "severity": "high",
  "event_type": "process_execution",
  "host": "linux-test-machine",
  "mitre_tactics": [],
  "mitre_techniques": [],
  "evidence": {}
}
```

*The final alert structure depends on the interface agreed upon between the detection engine and SOAR integration.*

## 6. Installation and Setup

### Prerequisites
- Python 3
- Linux / Ubuntu on WSL2
- Docker and Apache Kafka
- Falco installation
- Git

### Clone the Repository

```bash
git clone https://github.com/gnapiika/eBPF-Autonomous-Threat-Hunting-SOC.git
cd eBPF-Autonomous-Threat-Hunting-SOC
```

### Create Virtual Environment

```bash
python3 -m venv .venv-wsl
source .venv-wsl/bin/activate
```

Install all the required dependencies using the repository's dependency file, if available.

### Start Kafka

```bash
docker compose -f telemetry/kafka/docker-compose.yml up -d
```

### Run the Telemetry Forwarder

```bash
PYTHONPATH=. python telemetry/falco/falco_kafka_forwarder.py
```

### Run the Detection Consumer

In a separate terminal:

```bash
PYTHONPATH=. python telemetry/kafka_detection_consumer.py
```

## 7. Testing and Validation

Run the automated test suite:

```bash
python -m pytest -q
```

**Latest recorded result: 45 tests passed.**

The Falco-to-Kafka-to-detection pipeline has also been demonstrated using a test file-activity event. Further integration testing is ongoing for SOAR, Elasticsearch, and dashboard components.

## 8. Team Responsibilities

| Member | Responsibility |
|---|---|
| Member 1 | eBPF telemetry collection and Kafka streaming |
| Member 2 | Detection engine, threat hunting, and MITRE ATT&CK |
| Member 3 | SOAR integration and automated response |
| Member 4 | Elasticsearch integration and dashboard visualization |

## 9. Future Enhancements

- Expand telemetry collection and attack scenario coverage.
- Improve behavioral detection and process-chain correlation.
- Complete SOAR and dashboard integrations.
- Enhance forensic evidence collection and investigation.
- Improve system reliability and integration testing.

## 10. Contributors

Developed collaboratively by the Cybersecurity Internship team at **Zaalima Development Pvt. Ltd.**

**GitHub Repository:** [eBPF-Autonomous-Threat-Hunting-SOC](https://github.com/gnapiika/eBPF-Autonomous-Threat-Hunting-SOC)
>>>>>>> origin/member2-detection
