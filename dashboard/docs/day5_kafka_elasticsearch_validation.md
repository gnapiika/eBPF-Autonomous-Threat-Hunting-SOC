# Day 5 — Kafka and Elasticsearch Connectivity Validation

## Objective
Validate the local Kafka broker and Elasticsearch connectivity for the SOC dashboard integration.

## Environment
- Git branch: `member4-dashboard`
- Kafka topic: `security-events`
- Elasticsearch version: 9.5.5
- Elasticsearch index: `security-events`
- Python virtual environment: `.venv`

## Validation Results

### Kafka
- Kafka broker reachable at `localhost:9092` using `kafka-python`.
- Available topics included `security-events` and `__consumer_offsets`.
- A synthetic JSON event was successfully published to and consumed from `security-events`.

### Elasticsearch
- Python Elasticsearch client installed in the virtual environment.
- HTTPS connection to `https://localhost:9200` succeeded.
- CA certificate verification remained enabled using a readable copy of the Elasticsearch CA certificate.
- Elasticsearch reported version `9.5.5`.
- The `security-events` index exists.

## Limitations
- These checks validate connectivity and synthetic message transport only.
- Live Falco telemetry has not yet been verified end to end.
- Kafka-to-Elasticsearch ingestion and live Grafana event validation remain pending.
- No Member 2 detection implementation was modified as part of these checks.

## Next Steps
1. Review the existing detection consumer and event schema without modifying other members' files.
2. Design and implement Kafka-to-Elasticsearch ingestion within the dashboard team's agreed scope.
3. Validate real incoming events in Elasticsearch and Grafana.
