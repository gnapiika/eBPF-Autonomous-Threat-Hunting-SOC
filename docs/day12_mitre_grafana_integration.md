
# Day 12 - MITRE ATT&CK Integration and Grafana Visualization

**Project:** eBPF Autonomous Threat Hunting SOC  
**Role:** Member 4 - SOC Dashboard, Visualization & Attack Simulation  
**Date:** 12 November 2026  
**Branch:** `member4-dashboard`

## 1. Objective

The objective of this work session was to validate the Member 4 Kafka-to-Elasticsearch ingestion pipeline, verify Detection Engine alert generation with MITRE ATT&CK enrichment, and create MITRE visualization panels in Grafana.

## 2. Falco to Kafka to Elasticsearch Integration Test

A controlled file-write event was generated using the SOC Falco test file:

`/tmp/soc-falco-test`

The Member 2 Falco Kafka forwarder published the event to the Kafka topic:

- Kafka topic: `security-events`
- Partition: `0`
- Published offset: `6`

The Member 4 Elasticsearch consumer successfully indexed the event.

Observed result:

- Elasticsearch indexing: Successful
- Kafka offset committed: `6`
- Detection alerts: `0`

No alert was expected for this test because the event represented file activity and did not match the configured process-execution detection rules.

## 3. Detection Engine and MITRE ATT&CK Integration

A synthetic process-execution event was published directly to Kafka using a Kafka producer.

Test event details:

- Process: `bash`
- Command: `bash -c whoami`
- Host: `member4-kafka-test`
- Kafka topic: `security-events`
- Partition: `0`
- Published offset: `7`

The synthetic event was used to test the live Member 4 Kafka consumer and Detection Engine. This test bypassed the Falco forwarder.

The consumer successfully processed the event and generated a security alert.

Observed detection result:

| Field | Result |
|---|---|
| Detection Rule | DET-001 |
| Event Type | security_alert |
| Severity | medium |
| MITRE Tactic | Execution |
| MITRE Technique | T1059 |
| Alert indexing | Successful |
| Kafka offset committed | 7 |
| Alerts generated | 1 |

The alert was successfully indexed in Elasticsearch.

## 4. Elasticsearch Verification

The Elasticsearch search API was used to verify the stored security alerts.

Search results confirmed:

- Total matching security alerts: 2
- Detection rule: DET-001
- Severity: medium
- MITRE tactic: Execution
- MITRE technique: T1059

Both alert documents contained the expected MITRE enrichment fields.

## 5. Grafana MITRE ATT&CK Visualizations

Two visualization panels were created and saved in the existing Grafana SOC Dashboard.

### Panel 1: MITRE ATT&CK Tactics Distribution

ES|QL query:

```sql
FROM security-events
| WHERE event_type == "security_alert"
| STATS alert_count = COUNT(*) BY mitre_tactics
| SORT alert_count DESC
```

Observed result:

- Execution: 2 alerts

### Panel 2: MITRE ATT&CK Techniques Distribution

ES|QL query:

```sql
FROM security-events
| WHERE event_type == "security_alert"
| STATS alert_count = COUNT(*) BY mitre_techniques
| SORT alert_count DESC
```

Observed result:

- T1059: 2 alerts

Both panels were saved successfully in Grafana.

## 6. Pending Work

The following task remains pending:

- Create and configure the SOAR Response Status panel.
- Complete final dashboard verification.
- Synchronize the latest Grafana dashboard JSON with the Git repository.

## 7. Outcome

The following work was completed and verified during this session:

1. Successfully tested Falco file-write event ingestion through the Kafka forwarder and Elasticsearch consumer.
2. Successfully tested direct synthetic Kafka event processing by the Member 4 consumer.
3. Verified Detection Engine rule DET-001.
4. Verified MITRE ATT&CK enrichment with Execution and T1059.
5. Confirmed security alert documents in Elasticsearch.
6. Created and saved two MITRE ATT&CK visualization panels in Grafana.

**Status:** MITRE ATT&CK detection integration and Grafana visualizations successfully verified.

