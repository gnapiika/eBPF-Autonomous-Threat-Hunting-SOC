# Falco-to-Kafka Integration Status

This records the earlier team test. Follow the [current Falco setup and demo](../telemetry/falco/Configure-Falco.md) for the repeatable procedure.

## Components verified in the earlier test
- Falco modern eBPF service generates filesystem events.
- The custom SOC Test File Write rule detects writes to
  `/tmp/soc-falco-test`.
- The Falco Kafka forwarder publishes events to the
  `security-events` Kafka topic.
- Kafka topic metadata confirms an available partition and leader.
- The detection consumer connects to Kafka.

## Pending verification
The detection consumer reported an empty partition assignment during
testing. End-to-end processing of live Falco events by the detection
engine remains unverified.

## Test procedure
1. Start the Falco Kafka forwarder.
2. Start the Kafka detection consumer.
3. Generate a test event:
   `printf '%s\n' 'SOC integration test' >> /tmp/soc-falco-test`
4. Verify that the event is published to Kafka.
5. Verify that the consumer normalizes the event and evaluates it
   with the detection engine.
6. Confirm any generated alerts in `telemetry/detection_alerts.jsonl`.

## Next steps
- Investigate consumer partition assignment and offset handling.
- Verify Falco-specific event normalization.
- Add automated tests for live-event normalization and detection.
