
import json
import os
import sys
import time

from kafka import KafkaProducer
from kafka.errors import KafkaError

FALCO_LOG = "/var/log/falco/events.json"
KAFKA_BOOTSTRAP = "127.0.0.1:9092"
KAFKA_TOPIC = "security-events"


def main():
    if not os.path.isfile(FALCO_LOG):
        print(f"Falco log not found: {FALCO_LOG}", file=sys.stderr)
        return 1

    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda event: json.dumps(event).encode("utf-8"),
            acks="all",
            retries=5,
            request_timeout_ms=10000,
        )
    except Exception as exc:
        print(f"Cannot connect to Kafka: {exc}", file=sys.stderr)
        return 1

    print(f"Reading {FALCO_LOG}")
    print(f"Publishing to Kafka topic: {KAFKA_TOPIC}")
    print("Waiting for new events. Press Ctrl+C to stop.")

    try:
        with open(FALCO_LOG, "r", encoding="utf-8") as log_file:
            log_file.seek(0, os.SEEK_END)

            while True:
                line = log_file.readline()

                if not line:
                    time.sleep(0.2)
                    continue

                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise ValueError("Event must be a JSON object")
                except (json.JSONDecodeError, ValueError) as exc:
                    print(f"Skipping invalid event: {exc}", file=sys.stderr)
                    continue

                try:
                    metadata = producer.send(KAFKA_TOPIC, event).get(timeout=15)
                    print(
                        f"Published rule={event.get('rule', 'unknown')} "
                        f"partition={metadata.partition} offset={metadata.offset}"
                    )
                except KafkaError as exc:
                    print(f"Kafka publish failed: {exc}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\nStopping forwarder.")
    finally:
        producer.flush(timeout=10)
        producer.close(timeout=10)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
