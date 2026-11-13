
import json
import logging
import os
import signal
import uuid

from kafka import KafkaConsumer
from elasticsearch import Elasticsearch

from detection.event_schema import (
    SecurityEvent,
    ProcessInfo,
    NetworkInfo,
)
from detection.detection_engine import DetectionEngine


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger("member4-ingestion")

KAFKA_BOOTSTRAP = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"
)
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "security-events")
KAFKA_GROUP = os.getenv("KAFKA_GROUP_ID", "member4-es-ingestor")

ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
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
    """Normalize a Falco event for Elasticsearch and Grafana."""

    output = raw.get("output_fields") or {}

    timestamp = (
        raw.get("timestamp")
        or raw.get("time")
        or raw.get("datetime")
    )

    rule = str(raw.get("rule") or "unknown").lower().strip()

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

    priority = str(
        raw.get("priority") or "info"
    ).lower().strip()

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

    process = {
        "pid": output.get("proc.pid"),
        "ppid": output.get("proc.ppid"),
        "name": output.get("proc.name"),
        "executable": output.get("proc.exepath"),
        "command_line": output.get("proc.cmdline"),
        "parent_name": output.get("proc.pname"),
        "parent_executable": None,
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

    document = {
        "event_id": event_id,
        "timestamp": timestamp,
        "@timestamp": timestamp,
        "event_type": event_type,
        "source": "falco",
        "host": raw.get("hostname") or "unknown",
        "severity": severity,
        "process_name": process["name"],
        "message": message,
        "process": process,
        "user": {
            "uid": output.get("user.uid"),
            "gid": output.get("user.gid"),
            "username": output.get("user.name"),
        },
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


def detect_security_alerts(document, detection_engine):
    """Convert normalized data and evaluate detection rules."""

    process_data = document.get("process") or {}
    network_data = document.get("network") or {}

    event = SecurityEvent(
        event_id=document.get("event_id"),
        event_type=document.get("event_type", "unknown"),
        source=document.get("source", "falco"),
        host=document.get("host", "unknown"),
        timestamp=document.get("timestamp"),
        severity=document.get("severity", "info"),

        process=ProcessInfo(
            pid=process_data.get("pid"),
            ppid=process_data.get("ppid"),
            name=process_data.get("name"),
            executable=process_data.get("executable"),
            command_line=process_data.get("command_line"),
            parent_name=process_data.get("parent_name"),
            parent_executable=process_data.get(
                "parent_executable"
            ),
        ),

        network=NetworkInfo(
            source_ip=network_data.get("source_ip"),
            source_port=network_data.get("source_port"),
            destination_ip=network_data.get("destination_ip"),
            destination_port=network_data.get(
                "destination_port"
            ),
            protocol=network_data.get("protocol"),
        ),
    )

    alerts = detection_engine.evaluate(event)

    alert_documents = []

    for alert in alerts:
        alert_document = alert.to_dict()

        alert_document["@timestamp"] = (
            alert_document.get("timestamp")
        )

        alert_document["event_type"] = "security_alert"
        alert_document["source"] = "detection_engine"

        alert_document["original_event_id"] = (
            document.get("event_id")
        )

        alert_document["message"] = (
            alert_document.get("description", "")
        )

        alert_documents.append(alert_document)

    return alert_documents


def main():

    es = Elasticsearch(
        ES_URL,
        request_timeout=15,
    )

    if not es.ping():
        raise RuntimeError(
            "Cannot connect to Elasticsearch"
        )

    log.info("Elasticsearch connected: %s", ES_URL)
    log.info("Target index: %s", ES_INDEX)

    detection_engine = DetectionEngine()

    log.info("Detection Engine initialized")
    log.info("MITRE ATT&CK enrichment enabled")

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP,
        enable_auto_commit=False,
        auto_offset_reset="latest",
        max_poll_records=1,
    )

    log.info("Kafka consumer started")
    log.info(
        "Topic: %s | Group: %s",
        KAFKA_TOPIC,
        KAFKA_GROUP,
    )

    log.info("Waiting for new Falco events...")

    try:

        while running:

            records = consumer.poll(
                timeout_ms=1000,
                max_records=1,
            )

            for partition_records in records.values():

                for record in partition_records:

                    try:

                        raw = json.loads(
                            record.value.decode("utf-8")
                        )

                        if not isinstance(raw, dict):
                            raise ValueError(
                                "Kafka event must be a JSON object"
                            )

                        document = normalize_event(raw)

                        # Evaluate the normalized event.
                        alert_documents = detect_security_alerts(
                            document,
                            detection_engine,
                        )

                        # Index original Falco event.
                        event_result = es.index(
                            index=ES_INDEX,
                            document=document,
                            id=document["event_id"],
                        )

                        log.info(
                            "Event indexed: id=%s result=%s",
                            document["event_id"],
                            event_result["result"],
                        )

                        # Index generated security alerts.
                        for alert_document in alert_documents:

                            alert_id = alert_document.get(
                                "alert_id"
                            )

                            if not alert_id:
                                raise ValueError(
                                    "Detection alert has no alert_id"
                                )

                            alert_result = es.index(
                                index=ES_INDEX,
                                document=alert_document,
                                id=alert_id,
                            )

                            log.warning(
                                "SECURITY ALERT indexed: "
                                "alert_id=%s rule=%s "
                                "tactics=%s techniques=%s "
                                "result=%s",
                                alert_id,
                                alert_document.get("rule_id"),
                                alert_document.get("mitre_tactics"),
                                alert_document.get("mitre_techniques"),
                                alert_result["result"],
                            )

                        # Commit only after all indexing succeeds.
                        consumer.commit()

                        log.info(
                            "Kafka offset committed: "
                            "partition=%s offset=%s "
                            "alerts=%s",
                            record.partition,
                            record.offset,
                            len(alert_documents),
                        )

                    except Exception:

                        log.exception(
                            "Event processing failed at "
                            "partition=%s offset=%s. "
                            "Offset was not committed.",
                            record.partition,
                            record.offset,
                        )

                        raise

    finally:

        consumer.close()
        es.close()

        log.info(
            "Kafka consumer and Elasticsearch client closed"
        )


if __name__ == "__main__":
    main()
