"""Shared broker and topic settings for host-side telemetry clients."""

import os


BOOTSTRAP_SERVERS = (
    os.getenv("SOC_KAFKA_BOOTSTRAP")
    or os.getenv("KAFKA_BOOTSTRAP_SERVERS")
    or os.getenv("KAFKA_BOOTSTRAP")
    or "127.0.0.1:9092"
)
KAFKA_TOPIC = os.getenv("SOC_KAFKA_TOPIC") or os.getenv("KAFKA_TOPIC") or "security-events"
