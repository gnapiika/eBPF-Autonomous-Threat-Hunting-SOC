# eBPF-Powered Autonomous Threat Hunting SOC

An intelligent Security Operations Center (SOC) framework that monitors Linux systems, detects suspicious activities, maps threats to MITRE ATT&CK, and supports automated incident response and security visualization.

**Developed as part of the Cybersecurity Internship at Zaalima Development Pvt. Ltd.**

## 1. Project Overview

Traditional security monitoring systems generate large volumes of logs, making threat detection and investigation challenging. This project aims to simplify the security monitoring through automated telemetry collection, behavioral analysis, threat detections, and incident response.

### Objectives
- Monitor Linux process, file, and network activities.
- Collect and stream security events using eBPF-based tools and Apache Kafka.
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
