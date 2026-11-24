"""Run the synthetic SOC demo, webhook branch checks, or an alert replay."""

import argparse
import json
import sqlite3
import sys
from dataclasses import replace
from pathlib import Path

from detection.detection_engine import DetectionEngine
from detection.event_normalizer import EventNormalizer
from soar.n8n_webhook import N8nWebhookClient, webhook_error_message
from soar.response.week3_workflow import Week3ResponseWorkflow
from telemetry.kafka_detection_consumer import (
    FORWARDED_ALERTS_DB,
    OUTPUT_FILE,
    ForwardedAlertLedger,
    normalize_record,
    process_message,
)
from telemetry.simple_event import build_sample_event


def prepare_branch_alert(severity):
    event = normalize_record(build_sample_event(), EventNormalizer())
    alert, = DetectionEngine().evaluate(event)
    if severity == "high":
        alert = replace(
            alert,
            rule_id="TEST-HIGH",
            rule_name="Synthetic high-severity routing test",
            description="Synthetic payload for the n8n high-severity review branch.",
            severity="high",
            mitre_tactics=[],
            mitre_techniques=[],
            mitre={},
        )
    return alert, Week3ResponseWorkflow().process_alert(alert, [event])


def replay_alert(alert_id, output_path, ledger, client):
    with Path(output_path).open(encoding="utf-8") as alerts:
        for line in alerts:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict) or record.get("alert_id") != alert_id:
                continue
            message_key = record.pop("message_key", None)
            response = record.pop("response", None)
            if message_key and response:
                break
        else:
            raise ValueError("no replayable Kafka alert with that ID was found in JSONL")

    rule_id = record["rule_id"]
    if ledger.was_forwarded(message_key, rule_id):
        return None
    status = client.send_alert_record(record, response)
    ledger.mark_forwarded(message_key, rule_id, alert_id)
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--webhook", choices=("medium", "high"), help="POST one synthetic branch check")
    mode.add_argument("--replay", metavar="ALERT_ID", help="POST a saved Kafka alert and its evidence")
    args = parser.parse_args()

    if args.webhook is None and args.replay is None:
        engine = DetectionEngine()
        normalizer = EventNormalizer()
        alert_count = sum(
            process_message(build_sample_event(kind), normalizer, engine)
            for kind in ("process", "network", "file")
        )
        print(f"Local demo processed 3 synthetic events and saved {alert_count} alerts to {OUTPUT_FILE}.")
        return 0

    try:
        client = N8nWebhookClient.from_env()
    except ValueError:
        print("Set N8N_WEBHOOK_URL to a valid webhook and check N8N_WEBHOOK_TIMEOUT.", file=sys.stderr)
        return 1

    if args.replay:
        try:
            ledger = ForwardedAlertLedger(FORWARDED_ALERTS_DB)
            status = replay_alert(args.replay, OUTPUT_FILE, ledger, client)
        except (sqlite3.Error, ValueError, KeyError) as exc:
            print(f"Replay could not complete ({type(exc).__name__}). Check the alert ID, JSONL and SQLite ledger.", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Replay failed ({webhook_error_message(exc)}).", file=sys.stderr)
            return 1
        if status is None:
            print(f"Alert {args.replay} was already accepted according to the local ledger.")
        else:
            print(f"Webhook accepted replay of {args.replay} with HTTP {status}.")
        return 0

    alert, response = prepare_branch_alert(args.webhook)
    try:
        status = client.send_alert(alert, response)
    except Exception as exc:
        print(f"Webhook test failed ({webhook_error_message(exc)}).", file=sys.stderr)
        return 1

    route = "high_severity_review" if alert.severity == "high" else "manual_review"
    print(f"Webhook accepted {alert.rule_id} ({alert.severity}) with HTTP {status}. Expected n8n route is {route}.")
    print(f"Check execution output for alert {alert.alert_id}, evidence, and simulated response.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
