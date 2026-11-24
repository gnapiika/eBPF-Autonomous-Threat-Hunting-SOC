#!/usr/bin/env python3
"""Generate harmless synthetic Falco-shaped JSON telemetry."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union


DEFAULT_SAMPLE_FILE = "data/synthetic-falco.jsonl"


def build_sample_event(kind: str = "process") -> dict:
    rule, fields = {
        "process": ("Synthetic Lab Shell Execution", {
            "evt.type": "execve", "proc.name": "bash", "proc.exepath": "/bin/bash",
            "proc.cmdline": "bash -c synthetic-demo",
        }),
        "network": ("Synthetic Lab Network Connection", {
            "evt.type": "connect", "fd.cip": "192.0.2.10", "fd.cport": 40000,
            "fd.sip": "198.51.100.20", "fd.sport": 4444, "fd.l4proto": "tcp",
        }),
        "file": ("Synthetic Lab File Activity", {
            "evt.type": "openat", "fd.name": "/tmp/synthetic-demo.txt",
        }),
    }[kind]
    return {
        "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "hostname": "synthetic-lab-host",
        "rule": rule,
        "priority": "Notice",
        "synthetic": True,
        "output": "Synthetic test data only; no process, connection or file activity was performed",
        "output_fields": {
            "proc.pid": 424242,
            "proc.ppid": 424241,
            "proc.pname": "synthetic-parent",
            "user.name": "lab-user",
            **fields,
        },
    }


def resolve_event_file_path(path: Optional[Union[str, os.PathLike[str]]] = None) -> Path:
    """Use a portable demo path or an explicitly selected output file."""
    configured = path or os.getenv("FALCO_EVENTS_FILE") or os.getenv("FALCO_LOG") or DEFAULT_SAMPLE_FILE
    target = Path(configured)
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def write_sample_event(path=None, kind: str = "process") -> Path:
    """Append one synthetic event as JSONL."""
    target = resolve_event_file_path(path)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(build_sample_event(kind)) + "\n")
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("process", "network", "file"), default="process")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--file", type=Path)
    output.add_argument("--kafka", action="store_true", help="publish directly to the configured topic")
    options = parser.parse_args()
    if not options.kafka:
        print(f"Wrote a synthetic {options.kind} event to {write_sample_event(options.file, options.kind)}")
        return 0

    try:
        from kafka.errors import KafkaError
        from telemetry.falco.falco_kafka_forwarder import create_producer, publish_event
    except ImportError:
        print("Kafka dependency is unavailable; install requirements.txt", file=sys.stderr)
        return 1
    try:
        producer = create_producer()
        try:
            publish_event(producer, build_sample_event(options.kind))
        finally:
            producer.close(timeout=10)
    except KafkaError as exc:
        print(f"Kafka publish failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
