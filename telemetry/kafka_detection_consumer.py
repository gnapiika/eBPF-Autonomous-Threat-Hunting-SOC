
"""Consume Kafka security events and run the SOC detection engine."""

import json
import logging
import os
import sys
from typing import Any, Dict

from kafka import KafkaConsumer
from kafka.errors import KafkaError

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer


BOOTSTRAP_SERVERS = os.getenv("SOC_KAFKA_BOOTSTRAP", "127.0.0.1:9092")
KAFKA_TOPIC = os.getenv("SOC_KAFKA_TOPIC", "security-events")
KAFKA_GROUP_ID = os.getenv("SOC_KAFKA_GROUP_ID", "soc-detection-engine")
OUTPUT_FILE = os.getenv(
    "SOC_DETECTION_OUTPUT",
    "telemetry/detection_alerts.jsonl",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("soc-kafka-detection")


def append_json_line(path: str, record: Dict[str, Any]) -> None:
    """Append one JSON record to a newline-delimited JSON output file."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")


def process_message(
    raw_event: Dict[str, Any],
    normalizer: EventNormalizer,
    engine: DetectionEngine,
) -> int:
    """Normalize one message, evaluate it, and persist any alerts."""
    source = str(raw_event.get("source", "falco")).lower()
    host = str(raw_event.get("hostname") or raw_event.get("host") or "unknown")

    event = normalizer.normalize(
        raw_event=raw_event,
        source=source,
        host=host,
    )

    logger.info(
        "Processed event source=%s host=%s type=%s",
        event.source,
        event.host,
        event.event_type,
    )

    alerts = engine.evaluate(event)

    if not alerts:
        logger.info("No detection rule matched this event.")
        return 0

    for alert in alerts:
        alert_record = alert.to_dict()
        append_json_line(OUTPUT_FILE, alert_record)

        logger.warning(
            "DETECTION rule=%s name=%s severity=%s host=%s "
            "MITRE_tactics=%s MITRE_techniques=%s",
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.host,
            ",".join(alert.mitre_tactics),
            ",".join(alert.mitre_techniques),
        )

    return len(alerts)


def main() -> int:
    """Start consuming Kafka events until interrupted."""
    normalizer = EventNormalizer()
    engine = DetectionEngine()

    try:
        consumer = KafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=BOOTSTRAP_SERVERS,
            group_id=KAFKA_GROUP_ID,
            auto_offset_reset="latest",
            enable_auto_commit=False,
            value_deserializer=lambda value: json.loads(
                value.decode("utf-8")
            ),
            consumer_timeout_ms=1000,
        )
    except KafkaError as exc:
        logger.error("Could not connect to Kafka: %s", exc)
        return 1

    logger.info("Connected to Kafka at %s", BOOTSTRAP_SERVERS)
    logger.info("Consuming topic %s", KAFKA_TOPIC)
    logger.info("Detection alerts will be appended to %s", OUTPUT_FILE)

    try:
        while True:
            received = consumer.poll(timeout_ms=1000)

            for _partition, messages in received.items():
                for message in messages:
                    try:
                        if not isinstance(message.value, dict):
                            raise ValueError(
                                "Kafka message must contain a JSON object"
                            )

                        process_message(
                            message.value,
                            normalizer,
                            engine,
                        )

                        # Commit only after processing the message.
                        consumer.commit()

                    except (
                        json.JSONDecodeError,
                        UnicodeDecodeError,
                        ValueError,
                        TypeError,
                        KeyError,
                    ) as exc:
                        logger.error(
                            "Invalid event at partition=%s offset=%s: %s",
                            message.partition,
                            message.offset,
                            exc,
                        )
                        # Do not commit an invalid message automatically.
    except KeyboardInterrupt:
        logger.info("Stopping Kafka detection consumer.")
    finally:
        consumer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
