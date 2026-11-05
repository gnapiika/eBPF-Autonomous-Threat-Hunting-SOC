
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


def identify_source(raw_event: Dict[str, Any]) -> str:
    """Identify the telemetry format rather than the Falco event subsystem."""
    if "output_fields" in raw_event and "rule" in raw_event:
        return "falco"

    source = str(raw_event.get("source", "generic")).lower()
    if source in {"tetragon", "ebpf", "falco"}:
        return source

    return "generic"


def process_message(
    raw_event: Dict[str, Any],
    normalizer: EventNormalizer,
    engine: DetectionEngine,
) -> int:
    """Normalize one message, evaluate it, and persist any alerts."""
    source = identify_source(raw_event)
    host = str(
        raw_event.get("hostname")
        or raw_event.get("host")
        or "unknown"
    )

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
        append_json_line(OUTPUT_FILE, alert.to_dict())
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
    """Consume security events until interrupted."""
    normalizer = EventNormalizer()
    engine = DetectionEngine()

    try:
        consumer = KafkaConsumer(
            bootstrap_servers=BOOTSTRAP_SERVERS,
            group_id=KAFKA_GROUP_ID,
            enable_auto_commit=False,
            auto_offset_reset="latest",
            value_deserializer=lambda value: json.loads(
                value.decode("utf-8")
            ),
        )
        consumer.subscribe([KAFKA_TOPIC])
    except KafkaError as exc:
        logger.error("Could not connect to Kafka: %s", exc)
        return 1

    logger.info("Connected to Kafka at %s", BOOTSTRAP_SERVERS)
    logger.info("Subscribed to topic %s", KAFKA_TOPIC)
    logger.info("Detection alerts will be appended to %s", OUTPUT_FILE)

    try:
        while True:
            # poll() also drives group coordination and partition assignment.
            received = consumer.poll(timeout_ms=1000)

            assignment = consumer.assignment()
            if assignment:
                logger.debug("Assigned partitions: %s", assignment)
            elif not received:
                logger.debug("Waiting for Kafka partition assignment.")

            for _partition, messages in received.items():
                for message in messages:
                    try:
                        raw_event = message.value
                        if not isinstance(raw_event, dict):
                            raise ValueError(
                                "Kafka message must contain a JSON object"
                            )

                        process_message(raw_event, normalizer, engine)
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
                    except Exception:
                        logger.exception(
                            "Failed to process event at partition=%s offset=%s",
                            message.partition,
                            message.offset,
                        )

    except KeyboardInterrupt:
        logger.info("Stopping Kafka detection consumer.")
    except KafkaError:
        logger.exception("Kafka consumer encountered an error.")
        return 1
    finally:
        consumer.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
