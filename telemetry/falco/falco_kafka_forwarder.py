"""Forward Falco or Tetragon JSONL telemetry to Kafka."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from telemetry.kafka_config import BOOTSTRAP_SERVERS, KAFKA_TOPIC


FALCO_LOG = os.getenv("FALCO_EVENTS_FILE") or os.getenv("FALCO_LOG") or "/var/log/falco/events.json"


def create_producer():
    from kafka import KafkaProducer

    return KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        acks="all",
        retries=5,
        request_timeout_ms=10000,
        max_block_ms=15000,
    )


def publish_event(producer, event):
    value = json.dumps(event, allow_nan=False).encode("utf-8")
    metadata = producer.send(KAFKA_TOPIC, value).get(timeout=15)
    print(
        f"Kafka accepted topic={KAFKA_TOPIC} partition={metadata.partition} "
        f"offset={metadata.offset} synthetic={event.get('synthetic') is True}",
        flush=True,
    )
    return metadata


def follow_events(path: Path, from_start: bool):
    """Tail newline-terminated records, reopening after file rotation."""
    log_file = path.open("rb")
    try:
        if not from_start:
            log_file.seek(0, os.SEEK_END)
        while True:
            position = log_file.tell()
            line = log_file.readline()
            if line.endswith(b"\n"):
                try:
                    event = json.loads(line.decode("utf-8"))
                    if not isinstance(event, dict):
                        raise ValueError("telemetry must be a JSON object")
                    json.dumps(event, allow_nan=False)
                except (ValueError, RecursionError):
                    print("Skipping invalid JSONL telemetry record.", file=sys.stderr)
                    continue
                yield event
                continue

            log_file.seek(position)
            try:
                current_file = path.stat()
            except FileNotFoundError:
                time.sleep(0.2)
                continue
            original_file = os.fstat(log_file.fileno())
            if not os.path.samestat(original_file, current_file):
                try:
                    next_file = path.open("rb")
                except FileNotFoundError:
                    time.sleep(0.2)
                    continue
                log_file.close()
                log_file = next_file
            elif current_file.st_size < position:
                log_file.seek(0)
            else:
                time.sleep(0.2)
    finally:
        log_file.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=Path(FALCO_LOG))
    parser.add_argument("--from-start", action="store_true", help="include records already in the file")
    options = parser.parse_args()
    if not options.file.is_file():
        print(f"Telemetry file not found: {options.file}", file=sys.stderr)
        return 1

    try:
        from kafka.errors import KafkaError
    except ImportError:
        print("Kafka dependency is unavailable; install requirements.txt", file=sys.stderr)
        return 1

    try:
        producer = create_producer()
        try:
            print(f"Reading {options.file} and publishing to {KAFKA_TOPIC}. Press Ctrl+C to stop.", flush=True)
            for event in follow_events(options.file, options.from_start):
                publish_event(producer, event)
        finally:
            producer.close(timeout=10)
    except KeyboardInterrupt:
        print("Stopping forwarder.")
    except (KafkaError, OSError) as exc:
        print(f"Forwarding stopped: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
