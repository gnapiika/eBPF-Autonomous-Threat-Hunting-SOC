# Day 8 - Falco to Kafka Forwarding Validation

## Objective
Verify that Falco security events are successfully forwarded to Kafka.

## Environment
- Kali Linux
- Falco 0.45.2
- Modern eBPF Engine
- Apache Kafka 3.9.1
- Kafka Topic: security-events
- kafka-python 3.0.12

## Test Results

1. Falco detected a controlled file-write event.
2. Falco generated a JSON event in /var/log/falco/events.json.
3. The Kafka forwarder read the new event.
4. The event was published to Kafka.

Forwarder output:

Published rule=SOC Test File Write Detection partition=0 offset=1

## Kafka Consumer Verification

Kafka console consumer successfully read one message.

Verified fields:
- Rule: SOC Test File Write Detection
- Priority: Warning
- Source: syscall
- Process: zsh
- User: chetan
- File: /tmp/soc-falco-test

## Conclusion

PASS - Falco to Kafka forwarding successfully verified.

## Pending Work
- Kafka to Elasticsearch integration.
- Grafana live event visualization.

## Ownership
Member 4 - SOC Dashboard, Visualization & Attack Simulation.

Member 2 source code was used without modification.
