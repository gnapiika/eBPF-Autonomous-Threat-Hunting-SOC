"""Consume Kafka security events and run the SOC detection engine."""

import json
import logging
import os
import sqlite3
import sys
from contextlib import closing
from typing import Any, Dict, Optional
from uuid import NAMESPACE_URL, uuid5

from detection.detection_engine import DetectionAlert, DetectionEngine
from detection.event_normalizer import EventNormalizer, TETRAGON_EVENT_TYPES
from detection.event_schema import SecurityEvent
from soar.detection_integration import DetectionSoarIntegration
from soar.elasticsearch_ingestion import (
    ElasticsearchIngestionError,
    ElasticsearchIngestor,
)
from soar.n8n_webhook import N8nWebhookClient, webhook_error_message
from soar.response.week3_workflow import Week3ResponseWorkflow
from telemetry.kafka_config import BOOTSTRAP_SERVERS, KAFKA_TOPIC


KAFKA_GROUP_ID = os.getenv("SOC_KAFKA_GROUP_ID", "soc-detection-engine")
OUTPUT_FILE = os.getenv(
    "SOC_DETECTION_OUTPUT",
    "telemetry/detection_alerts.jsonl",
)
FORWARDED_ALERTS_DB = os.getenv(
    "SOC_FORWARDED_ALERTS_DB",
    "telemetry/forwarded_alerts.sqlite3",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("soc-kafka-detection")


class ForwardedAlertLedger:
    """Persist successful Kafka-record alert deliveries to avoid replay duplicates."""

    def __init__(self, path: str) -> None:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self.path = path
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS forwarded_alerts (
                    message_key TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    PRIMARY KEY (message_key, rule_id)
                )
                """
            )

    def was_forwarded(self, message_key: str, rule_id: str) -> bool:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            result = connection.execute(
                """
                SELECT 1
                FROM forwarded_alerts
                WHERE message_key = ? AND rule_id = ?
                """,
                (message_key, rule_id),
            ).fetchone()
        return result is not None

    def mark_forwarded(
        self,
        message_key: str,
        rule_id: str,
        alert_id: str,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO forwarded_alerts
                    (message_key, rule_id, alert_id)
                VALUES (?, ?, ?)
                """,
                (message_key, rule_id, alert_id),
            )


def append_json_line(path: str, record: Dict[str, Any]) -> None:
    """Append one JSON record to a newline-delimited JSON output file."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "a", encoding="utf-8") as output:
        output.write(json.dumps(record, allow_nan=False) + "\n")


class InvalidEvent(ValueError):
    """A Kafka record contains invalid telemetry and can be skipped."""


def identify_source(raw_event: Dict[str, Any]) -> str:
    """Identify the telemetry format rather than the Falco event subsystem."""
    if "output_fields" in raw_event and "rule" in raw_event:
        return "falco"
    if any(kind in raw_event for kind in TETRAGON_EVENT_TYPES):
        return "tetragon"
    return str(raw_event.get("source") or "generic").lower()


def decode_record(value: bytes) -> Dict[str, Any]:
    """Decode inside the record handler so bad values cannot break poll()."""
    try:
        raw_event = json.loads(value.decode("utf-8"))
        if not isinstance(raw_event, dict):
            raise ValueError("Kafka message must contain a JSON object")
        json.dumps(raw_event, allow_nan=False)
    except (AttributeError, ValueError, RecursionError) as exc:
        raise InvalidEvent("expected a UTF-8 JSON object with finite values") from exc
    return raw_event


def normalize_record(
    raw_event: Dict[str, Any],
    normalizer: EventNormalizer,
    message_key: Optional[str] = None,
) -> SecurityEvent:
    """Normalize the wire format and retain a stable Kafka event identity."""
    output_fields = raw_event.get("output_fields")
    falco_host = (
        output_fields.get("evt.hostname") if isinstance(output_fields, dict) else None
    )
    host = str(
        raw_event.get("hostname")
        or raw_event.get("host")
        or raw_event.get("node_name")
        or falco_host
        or "unknown"
    )
    try:
        event = normalizer.normalize(raw_event, identify_source(raw_event), host)
    except (ValueError, TypeError, AttributeError, OverflowError) as exc:
        raise InvalidEvent("invalid event timestamp or field types") from exc
    source_event_id = raw_event.get("event_id")
    if message_key and not (isinstance(source_event_id, str) and source_event_id):
        event.event_id = str(uuid5(NAMESPACE_URL, f"soc:event:{message_key}"))
    return event


def process_message(
    raw_event: Dict[str, Any],
    normalizer: EventNormalizer,
    engine: DetectionEngine,
    soar_integration: Optional[DetectionSoarIntegration] = None,
    forwarded_ledger: Optional[ForwardedAlertLedger] = None,
    message_key: Optional[str] = None,
    elasticsearch_ingestor: Optional[ElasticsearchIngestor] = None,
) -> int:
    """Normalize and detect one message, persist alerts, and forward them."""
    event = normalize_record(raw_event, normalizer, message_key)
    logger.info(
        "Processed event source=%s host=%s type=%s synthetic=%s",
        event.source, event.host, event.event_type, event.synthetic,
    )
    stable_identity = message_key or json.dumps(
        {"source": event.source, "host": event.host, "raw_event": raw_event},
        sort_keys=True,
        separators=(",", ":"),
    )
    if elasticsearch_ingestor is not None:
        try:
            elasticsearch_ingestor.index_event(
                event,
                document_id=elasticsearch_ingestor.deterministic_document_id("event", stable_identity),
            )
            logger.info("Indexed normalized event event_id=%s", event.event_id)
        except ElasticsearchIngestionError as exc:
            logger.error(
                "Elasticsearch event indexing failed for event_id=%s (%s)",
                event.event_id, exc,
            )

    alerts = engine.evaluate(event)
    if not alerts:
        logger.info("No detection rule matched this event.")
        return 0

    workflow = (
        soar_integration.response_workflow
        if isinstance(soar_integration, DetectionSoarIntegration)
        else Week3ResponseWorkflow()
    )
    for alert in alerts:
        if message_key:
            identity = f"soc:alert:{message_key}:{alert.rule_id}"
            alert.alert_id = str(uuid5(NAMESPACE_URL, identity))
        response_package = workflow.process_alert(alert, [event])
        record = alert.to_dict()
        record["response"] = response_package
        if message_key:
            record["message_key"] = message_key
        append_json_line(OUTPUT_FILE, record)
        logger.warning(
            "DETECTION alert_id=%s rule=%s severity=%s host=%s "
            "MITRE_tactics=%s MITRE_techniques=%s response_status=%s",
            alert.alert_id, alert.rule_id, alert.severity, alert.host,
            ",".join(alert.mitre_tactics), ",".join(alert.mitre_techniques),
            response_package["response_status"],
        )
        delivery_status = forward_alert(
            alert, event, response_package, stable_identity, soar_integration, forwarded_ledger,
        )
        if elasticsearch_ingestor is not None:
            try:
                elasticsearch_ingestor.index_alert(
                    alert,
                    response_package=response_package,
                    external_workflow={
                        "provider": "n8n",
                        "delivery_status": delivery_status,
                        "result_received": False,
                    },
                    document_id=elasticsearch_ingestor.deterministic_document_id(
                        "alert", f"{stable_identity}:{alert.rule_id}",
                    ),
                )
                logger.info("Indexed alert and response evidence alert_id=%s", alert.alert_id)
            except ElasticsearchIngestionError as exc:
                logger.error(
                    "Elasticsearch alert indexing failed for alert_id=%s (%s)",
                    alert.alert_id, exc,
                )

    return len(alerts)


def forward_alert(
    alert: DetectionAlert,
    event: SecurityEvent,
    response_package: Dict[str, Any],
    message_key: str,
    soar_integration: Optional[DetectionSoarIntegration],
    ledger: Optional[ForwardedAlertLedger],
) -> str:
    """Deliver the package and record confirmed HTTP acceptance."""
    if soar_integration is None:
        return "not_configured"
    if ledger is not None and ledger.was_forwarded(message_key, alert.rule_id):
        logger.info("Skipping duplicate SOAR forwarding for alert_id=%s", alert.alert_id)
        return "previously_accepted"

    try:
        statuses = soar_integration.forward_alerts([alert], [event], response_packages=[response_package])
    except Exception as exc:
        logger.error(
            "SOAR forwarding failed for alert_id=%s; alert remains in %s (%s)",
            alert.alert_id, OUTPUT_FILE, webhook_error_message(exc),
        )
        return "request_failed"

    if ledger is not None:
        try:
            ledger.mark_forwarded(message_key, alert.rule_id, alert.alert_id)
        except sqlite3.Error:
            logger.exception(
                "SOAR accepted alert_id=%s but its deduplication record could not be saved",
                alert.alert_id,
            )
    logger.info("SOAR webhook accepted alert_id=%s status=%s", alert.alert_id, statuses)
    return "request_accepted"


def create_soar_integration(detection_engine: DetectionEngine) -> Optional[DetectionSoarIntegration]:
    """Build the optional SOAR bridge from the configured webhook URL."""
    if not os.environ.get("N8N_WEBHOOK_URL"):
        logger.info("N8N_WEBHOOK_URL is unset; alerts and evidence are written locally to %s", OUTPUT_FILE)
        return None
    try:
        return DetectionSoarIntegration(detection_engine, N8nWebhookClient.from_env())
    except ValueError:
        logger.error("SOAR forwarding is disabled. Check N8N_WEBHOOK_URL and N8N_WEBHOOK_TIMEOUT.")
        return None


def create_elasticsearch_ingestor() -> Optional[ElasticsearchIngestor]:
    """Build the optional Elasticsearch sink from environment settings."""
    try:
        return ElasticsearchIngestor.from_env()
    except ValueError as exc:
        logger.error("Elasticsearch ingestion is disabled (%s)", exc)
        return None


def consume_batch(
    consumer,
    normalizer: EventNormalizer,
    engine: DetectionEngine,
    soar_integration: Optional[DetectionSoarIntegration] = None,
    forwarded_ledger: Optional[ForwardedAlertLedger] = None,
    elasticsearch_ingestor: Optional[ElasticsearchIngestor] = None,
) -> None:
    """Commit the next offset for just the partition and record handled."""
    from kafka.structs import OffsetAndMetadata

    for partition, messages in consumer.poll(timeout_ms=1000).items():
        for message in messages:
            message_key = f"{partition.topic}:{partition.partition}:{message.offset}"
            try:
                process_message(
                    decode_record(message.value), normalizer, engine,
                    soar_integration=soar_integration,
                    forwarded_ledger=forwarded_ledger,
                    message_key=message_key,
                    elasticsearch_ingestor=elasticsearch_ingestor,
                )
            except InvalidEvent as exc:
                logger.warning("Skipping invalid event at %s (%s)", message_key, exc)
            consumer.commit({partition: OffsetAndMetadata(message.offset + 1, "")})


def main() -> int:
    """Consume security events until interrupted."""
    try:
        from kafka import KafkaConsumer
        from kafka.errors import KafkaError
    except ImportError:
        logger.error("Kafka dependency is unavailable; install requirements.txt")
        return 1

    offset_reset = os.getenv("SOC_KAFKA_OFFSET_RESET", "latest")
    if offset_reset not in {"latest", "earliest"}:
        logger.error("SOC_KAFKA_OFFSET_RESET must be latest or earliest")
        return 1
    normalizer = EventNormalizer()
    engine = DetectionEngine()
    soar_integration = create_soar_integration(engine)
    elasticsearch_ingestor = create_elasticsearch_ingestor()
    if elasticsearch_ingestor is not None:
        try:
            elasticsearch_ingestor.ensure_indices()
        except ElasticsearchIngestionError as exc:
            logger.error("Could not prepare Elasticsearch indices; writes will retry mapping setup (%s)", exc)

    forwarded_ledger = None
    if soar_integration:
        try:
            forwarded_ledger = ForwardedAlertLedger(FORWARDED_ALERTS_DB)
        except (OSError, sqlite3.Error):
            logger.exception("Could not initialize the SOAR ledger; forwarding is disabled")
            soar_integration = None

    try:
        consumer = KafkaConsumer(
            bootstrap_servers=BOOTSTRAP_SERVERS,
            group_id=KAFKA_GROUP_ID,
            enable_auto_commit=False,
            auto_offset_reset=offset_reset,
            max_poll_records=1,
        )
    except KafkaError as exc:
        logger.error("Could not connect to Kafka: %s", exc)
        return 1

    try:
        consumer.subscribe([KAFKA_TOPIC])
        logger.info(
            "Kafka broker=%s topic=%s group=%s offset_reset=%s",
            BOOTSTRAP_SERVERS, KAFKA_TOPIC, KAFKA_GROUP_ID, offset_reset,
        )
        logger.info("Detection alerts and evidence will be appended to %s", OUTPUT_FILE)
        while True:
            consume_batch(
                consumer, normalizer, engine, soar_integration,
                forwarded_ledger, elasticsearch_ingestor,
            )
    except KeyboardInterrupt:
        logger.info("Stopping Kafka detection consumer.")
    except Exception:
        logger.exception("Kafka consumer stopped before committing the failed record")
        return 1
    finally:
        consumer.close(autocommit=False)

    return 0


if __name__ == "__main__":
    sys.exit(main())
