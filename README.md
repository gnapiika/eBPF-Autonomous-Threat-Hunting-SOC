# eBPF-Powered Autonomous Threat Hunting SOC

An intelligent Security Operations Center (SOC) framework designed to monitor Linux systems, detect suspicious activities, map threats to MITRE ATT&CK, automate incident response, and visualize security events.

**Developed as part of the Cybersecurity Internship at Zaalima Development Pvt. Ltd.**

## 1. Project Overview

Traditional security monitoring systems can generate large volumes of logs, making threat detection and investigation time-consuming. This project aims to build a modular SOC framework that collects Linux telemetry, analyzes suspicious behavior, generates security alerts, and supports automated response.

### Objectives

- Monitor process, file, and network activity on Linux systems.
- Collect and stream security events using eBPF-based monitoring and Apache Kafka.
- Normalize and correlate events for threat detection.
- Detect behavioral anomalies and suspicious activity.
- Map relevant detections to MITRE ATT&CK.
- Support automated response through SOAR workflows.
- Preserve forensic evidence and visualize security alerts.

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
Detection Engine     Threat Hunting
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

The diagram represents the intended architecture. Individual integrations are validated as development progresses.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Event processing and detection |
| eBPF / Falco / Tetragon | Linux telemetry collection |
| Apache Kafka | Security event streaming |
| MITRE ATT&CK | Threat classification |
| n8n / Cortex | SOAR and response workflows |
| Elasticsearch | Security data indexing and search |
| Grafana / Kibana | Security dashboards |
| pytest | Automated testing |
| Git and GitHub | Version control and collaboration |

## 4. Core Modules

**Telemetry Collection:** Collects relevant Linux system events through configured monitoring tools.

**Event Processing:** Normalizes telemetry into a consistent security-event format and streams events through Kafka.

**Detection Engine:** Uses rule-based detection, behavioral analysis, and statistical anomaly detection to identify suspicious activity.

**Threat Hunting and MITRE ATT&CK:** Investigates suspicious patterns and associates supported findings with relevant attack tactics and techniques.

**SOAR Integration:** Connects alerts to webhook-based workflows for severity-based routing and configured response actions.

**Forensics and Visualization:** Records alert evidence and supports security monitoring through an Elasticsearch-backed dashboard architecture.

## 5. Alert Format

Security alerts use structured JSON to communicate information between modules. The following is a simplified example:

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

The exact payload structure depends on the agreed interface between the detection engine and the SOAR webhook.

## 6. Installation and Setup

### Prerequisites

- Python 3
- Linux or Ubuntu on WSL2
- Docker and Apache Kafka
- Configured Falco installation
- Git

### Clone the Repository

```bash
git clone https://github.com/gnapiika/eBPF-Autonomous-Threat-Hunting-SOC.git
cd eBPF-Autonomous-Threat-Hunting-SOC
```

### Create a Virtual Environment

```bash
python3 -m venv .venv-wsl
source .venv-wsl/bin/activate
```

Install dependencies using the repository's dependency file, if available.

### Start Kafka

```bash
docker compose -f telemetry/kafka/docker-compose.yml up -d
```

### Run the Telemetry Forwarder

```bash
PYTHONPATH=. python telemetry/falco/falco_kafka_forwarder.py
```

### Run the Detection Consumer

In a separate terminal, activate the virtual environment and run:

```bash
PYTHONPATH=. python telemetry/kafka_detection_consumer.py
```

## 7. Testing

Run the automated test suite:

```bash
python -m pytest -q
```

**Latest recorded result:** 45 tests passed.

The live Falco-to-Kafka-to-detection pipeline has also been demonstrated with a test file-activity event. Further validation is required for complete SOAR, Elasticsearch, and dashboard integration.

## 8. Team Responsibilities

| Member | Responsibility |
|---|---|
| Member 1 | eBPF telemetry collection and Kafka streaming |
| Member 2 | Detection engine, threat hunting, and MITRE ATT&CK |
| Member 3 | SOAR integration and automated response |
| Member 4 | Elasticsearch integration and dashboard visualization |

## 9. Future Enhancements

- Improve process chain correlation and behavioral detection.
- Expand telemetry coverage and validate additional attack scenarios.
- Complete SOAR, Elasticsearch, and dashboard integration.
- Improve forensic evidence collection and alert investigation.
- Strengthen error handling, reliability, and integration testing.

## 10. Contributors

Developed collaboratively by the cybersecurity internship team at **Zaalima Development Pvt. Ltd.**

**Repository:** [eBPF-Autonomous-Threat-Hunting-SOC](https://github.com/gnapiika/eBPF-Autonomous-Threat-Hunting-SOC)
