import json
import logging
import os
import signal
import uuid

from datetime import datetime, timezone

from kafka import KafkaConsumer
from elasticsearch import Elasticsearch


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger("member4-ingestion")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-events")
KAFKA_GROUP = os.getenv("KAFKA_GROUP_ID", "member4-es-ingestor")

ES_URL = os.getenv("ELASTICSEARCH_URL", "https://localhost:9200")
ES_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ES_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD")
ES_CA_CERT = os.getenv(
    "ELASTICSEARCH_CA_CERT",
    "/home/chetan/http_ca.crt",
)
ES_INDEX = os.getenv("ELASTICSEARCH_INDEX", "security-events")

running = True


def stop_handler(signum, frame):
    global running
    running = False
    log.info("Shutdown signal received")


signal.signal(signal.SIGINT, stop_handler)
signal.signal(signal.SIGTERM, stop_handler)


def normalize_event(raw):
    """Normalize a Falco event using Member 2's documented mappings."""

    output = raw.get("output_fields") or {}

    timestamp = (
        raw.get("timestamp")
        or raw.get("time")
        or raw.get("datetime")
    )

    rule = str(raw.get("rule") or "unknown").lower().strip()

    # Match Member 2's event-type mappings.
    if "shell" in rule or "command" in rule:
        event_type = "process_execution"
    elif "network" in rule or "connection" in rule:
        event_type = "network_connection"
    elif "file" in rule:
        event_type = "file_activity"
    elif "login" in rule or "authentication" in rule:
        event_type = "authentication"
    else:
        event_type = rule

    # Match Member 2's severity mappings.
    priority = str(raw.get("priority") or "info").lower().strip()

    severity_map = {
        "emergency": "critical",
        "alert": "critical",
        "critical": "critical",
        "crit": "critical",
        "error": "high",
        "err": "high",
        "high": "high",
        "warning": "medium",
        "warn": "medium",
        "medium": "medium",
        "notice": "low",
        "low": "low",
        "info": "info",
        "informational": "info",
    }

    severity = severity_map.get(priority, "info")

    host = raw.get("hostname") or "unknown"

    process = {
        "pid": output.get("proc.pid"),
        "ppid": output.get("proc.ppid"),
        "name": output.get("proc.name"),
        "executable": output.get("proc.exepath"),
        "command_line": output.get("proc.cmdline"),
        "parent_name": output.get("proc.pname"),
        "parent_executable": None,
    }

    user = {
        "uid": output.get("user.uid"),
        "gid": output.get("user.gid"),
        "username": output.get("user.name"),
    }

    network = {
        "source_ip": output.get("fd.cip"),
        "source_port": output.get("fd.cport"),
        "destination_ip": output.get("fd.sip"),
        "destination_port": output.get("fd.sport"),
        "protocol": output.get("fd.l4proto"),
    }

    event_id = str(uuid.uuid4())
    message = raw.get("output", "")

    # Normalized fields + backward-compatible Grafana fields.
    document = {
        "event_id": event_id,
        "timestamp": timestamp,
        "@timestamp": timestamp,
        "event_type": event_type,
        "source": "falco",
        "host": host,
        "severity": severity,
        "process_name": process["name"],
        "message": message,
        "process": process,
        "user": user,
        "network": network,
        "file": {
            "path": output.get("fd.name"),
            "operation": None,
            "hash_sha256": None,
        },
        "tags": ["falco"],
        "raw_event": raw,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "metadata": {
            "rule": raw.get("rule"),
            "priority": raw.get("priority"),
            "output": message,
            "falco_source": raw.get("source"),
            "falco_tags": raw.get("tags", []),
        },
    }

    return document


def main():
    if not ES_PASSWORD:
        raise RuntimeError("ELASTICSEARCH_PASSWORD environment variable is missing")

    es = Elasticsearch(
        ES_URL,
        basic_auth=(ES_USERNAME, ES_PASSWORD),
        ca_certs=ES_CA_CERT,
        request_timeout=15,
    )

    if not es.ping():
        raise RuntimeError("Cannot connect to Elasticsearch")

    log.info("Elasticsearch connected: %s", ES_URL)
    log.info("Target index: %s", ES_INDEX)

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP,
        enable_auto_commit=False,
        auto_offset_reset="latest",
        max_poll_records=1,
    )

    log.info("Kafka consumer started")
    log.info("Topic: %s | Group: %s", KAFKA_TOPIC, KAFKA_GROUP)
    log.info("Waiting for new Falco events...")

    try:
        while running:
            records = consumer.poll(timeout_ms=1000, max_records=1)

            for partition_records in records.values():
                for record in partition_records:
                    try:
                        raw = json.loads(record.value.decode("utf-8"))

                        if not isinstance(raw, dict):
                            raise ValueError("Kafka event must be a JSON object")

                        document = normalize_event(raw)

                        result = es.index(
                            index=ES_INDEX,
                            document=document,
                            id=document["event_id"],
                        )

                        # Commit only after Elasticsearch confirms indexing.
                        consumer.commit()

                        log.info(
                            "Indexed event_id=%s event_type=%s severity=%s "
                            "ES_result=%s partition=%s offset=%s",
                            document["event_id"],
                            document["event_type"],
                            document["severity"],
                            result["result"],
                            record.partition,
                            record.offset,
                        )

                    except Exception:
                        log.exception(
                            "Event processing failed at partition=%s offset=%s. "
                            "Offset was not committed.",
                            record.partition,
                            record.offset,
                        )
                        raise

    finally:
        consumer.close()
        es.close()
        log.info("Kafka consumer and Elasticsearch client closed")


if __name__ == "__main__":
    main()
