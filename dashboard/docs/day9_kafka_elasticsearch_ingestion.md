# Day 9 — Kafka to Elasticsearch Ingestion and Grafana Integration

## 1. Objective

The objective of Day 9 was to integrate Kafka with Elasticsearch and validate the end-to-end security event ingestion pipeline. Falco-generated security events were forwarded to Kafka, consumed by the Member 4 ingestion adapter, stored in Elasticsearch, and visualized through Grafana.

## 2. System Architecture

The implemented data flow is:

Linux Host
    ↓
Falco Modern eBPF
    ↓
/var/log/falco/events.json
    ↓
Falco Kafka Forwarder
    ↓
Kafka Topic: security-events
    ↓
Member 4 Kafka-to-Elasticsearch Ingestion Adapter
    ↓
Elasticsearch Index: security-events
    ↓
Grafana Elasticsearch Data Source
    ↓
SOC Dashboard

## 3. Environment and Components

| Component | Version / Configuration |
|---|---|
| Operating System | Kali Linux |
| Falco | 0.45.2 |
| Apache Kafka | 3.9.1 |
| Elasticsearch | 9.5.5 |
| Grafana | 13.2.3 |
| Python Environment | falco-kafka-venv |
| kafka-python | 3.0.12 |
| Elasticsearch Python Client | 9.5.1 |

## 4. Kafka-to-Elasticsearch Ingestion Adapter

Created the Member 4 ingestion adapter:

`dashboard/ingestion/kafka_to_elasticsearch.py`

The adapter performs the following tasks:

- Connects to the Kafka broker.
- Consumes events from the `security-events` topic.
- Parses incoming Falco JSON events.
- Normalizes event fields.
- Converts events into Elasticsearch-compatible documents.
- Indexes normalized documents into the `security-events` index.
- Commits Kafka offsets after successful indexing.

### Configuration

The adapter supports these environment variables:

- `KAFKA_BOOTSTRAP_SERVERS`
- `KAFKA_TOPIC`
- `KAFKA_GROUP_ID`
- `ELASTICSEARCH_URL`
- `ELASTICSEARCH_USERNAME`
- `ELASTICSEARCH_PASSWORD`
- `ELASTICSEARCH_CA_CERT`
- `ELASTICSEARCH_INDEX`

The Elasticsearch password is supplied through an environment variable rather than hardcoded in the source code.

## 5. Event Normalization

The adapter maps Falco events into structured fields.

### Flat fields

- `@timestamp`
- `event_type`
- `source`
- `host`
- `severity`
- `process_name`
- `message`

### Nested fields

- `process`
- `user`
- `network`
- `file`
- `tags`
- `raw_event`
- `mitre_tactics`
- `mitre_techniques`
- `metadata`

The file path is mapped from the Falco output field `fd.name` into `file.path`.

Fields such as file operation and SHA-256 hash remain null when reliable source values are unavailable.

## 6. Falco-to-Kafka Forwarding

The Falco Kafka forwarder reads new JSON events from:

`/var/log/falco/events.json`

It publishes events to the Kafka topic:

`security-events`

The forwarder implementation is maintained by Member 2.

For local restart validation, a temporary copy was recovered from the remote `member2-detection` branch without switching branches or modifying Member 2 source files.

## 7. Elasticsearch Integration

Elasticsearch was configured as the storage and search backend.

Configuration:

- Elasticsearch URL: `https://localhost:9200`
- Index: `security-events`
- Time field: `@timestamp`
- CA certificate: `/home/chetan/http_ca.crt`

The ingestion adapter successfully connected to Elasticsearch and indexed the consumed Kafka events.

## 8. End-to-End Validation

A controlled file-write event was generated using:

`echo "SOC restart verification" | sudo tee -a /tmp/soc-falco-test`

Falco detected the file-write activity and generated a security event.

### Verified ingestion result

| Field | Result |
|---|---|
| Event ID | 461c5425-ab19-42ca-96e2-612f0d0e3402 |
| Event Type | file_activity |
| Severity | medium |
| Elasticsearch HTTP Status | 201 |
| Indexing Result | created |
| Kafka Partition | 0 |
| Kafka Offset | 4 |
| File Path | /tmp/soc-falco-test |

The indexed Elasticsearch document was checked to confirm that the file path was correctly stored.

The Elasticsearch index contained 4 documents at the time of one verification check. This was a test-time count, not a fixed expected value.

## 9. Grafana Dashboard Integration

The Grafana Elasticsearch data source was configured with:

- Data source UID: `bg10tjcobatq8c`
- Elasticsearch index: `security-events`
- Time field: `@timestamp`

The data source health check was successful.

The following four dashboard panels were verified:

1. Total Security Events
2. Security Events by Severity
3. Security Events Detail Table
4. Security Events Trend

All four panels were visible and working in Grafana.

## 10. Service Restart Validation

After restarting the system, the following services were started:

- Elasticsearch
- Grafana Server
- Falco Modern eBPF
- Kafka Docker container

The Kafka forwarder and Elasticsearch ingestion adapter were restarted manually.

Kafka connectivity, event forwarding, Elasticsearch indexing, and Grafana visualization were validated again.

## 11. Current Limitations

- File operation and file hash fields remain null when the source event does not provide reliable values.
- MITRE ATT&CK enrichment requires further implementation.
- Current validation covers a controlled file-write detection scenario.
- The temporary forwarder copy must be recovered after reboot until a persistent local startup arrangement is established.
- Additional event categories and attack simulations require further testing.

## 12. Future Work

- Add more security event categories.
- Improve severity-based visualization.
- Add host and process activity panels.
- Integrate MITRE ATT&CK technique visualization.
- Add suspicious process monitoring.
- Perform additional attack simulations.
- Improve ingestion error handling and reliability.

## 13. Conclusion

Day 9 successfully validated the integration between Falco, Kafka, Elasticsearch, and Grafana.

Security events generated by Falco were forwarded through Kafka, normalized by the Member 4 ingestion adapter, indexed in Elasticsearch, and displayed in the Grafana SOC dashboard.

The end-to-end event ingestion and visualization pipeline is operational.
