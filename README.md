# eBPF-Powered Autonomous Threat Hunting SOC

## Project Overview

An eBPF-powered autonomous Security Operations Center (SOC) framework designed
to monitor Linux systems, detect suspicious behavior, map threats to MITRE
ATT&CK techniques, perform automated response, collect forensic evidence,
and visualize the security telemetry in real time.

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
