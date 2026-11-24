# Week 3: Safe remediation planning and forensic evidence

This implementation connects the current detection engine to an evidence
bundle and a dry-run containment plan. It does **not** stop processes, modify
firewall rules, isolate a host, or query the operating system. A live response
provider and an explicitly authorized isolated Linux test environment are not
present in this repository.

## What is implemented

`Week3ResponseWorkflow.process_events()` evaluates a supplied batch using the
existing `DetectionEngine`. For each alert it creates a response package with:

- **Process information:** normalized process fields associated with each
  event.
- **Network connections:** normalized endpoints, ports, and protocol when
  present.
- **Relevant logs:** source event metadata and raw event context, when
  available.
- **File information:** normalized file path, operation, and hash when present.
- **Timestamps:** original event timestamps and bundle collection time.
- **Process tree:** observed PID/PPID relationships within the supplied event
  batch, including parent/child PID links and process context.

Missing telemetry is represented by empty collections and the coverage counts;
the workflow does not fabricate values. Process relationships only reflect
observed events, not a live or complete operating-system process tree. PID
reuse can make a batch-only process tree ambiguous. No separate log reader,
filesystem scanner, network enumerator, or eBPF/Falco/Tetragon collector is
implemented.

The response planner proposes `process_isolation` when the alert has a
positive process PID and `network_containment` when it has a valid destination
IP. These are plans only: every package reports `response_status: simulated`,
`mode: dry_run`, `approval_required: true`, and
`execution_performed: false`. Invalid or missing targets do not produce an
action. This makes the flow safe to test without changing the host or network.

## Kafka detection to SOAR handoff

When `N8N_WEBHOOK_URL` is configured, the Kafka detection consumer writes each
alert to `telemetry/detection_alerts.jsonl` and forwards the same alert through
`DetectionSoarIntegration`. The webhook keeps the existing `source` and
`alert` fields and adds a `response` object containing the existing evidence
bundle and simulated response plan. If the webhook is not configured or a
request fails, the consumer logs the failure and retains the alert in JSONL.
Failed deliveries are not automatically retried after the Kafka offset is
committed; replay or manual forwarding from the saved alert is required.

Successful deliveries are recorded in
`telemetry/forwarded_alerts.sqlite3` by Kafka topic, partition, offset, and
detection rule. Override the database path with `SOC_FORWARDED_ALERTS_DB`.
This prevents normal Kafka replays from sending the same record/rule twice.
The HTTP request and local database cannot form a distributed transaction, so
a process interruption between webhook acceptance and ledger persistence can
still result in a duplicate delivery.

## Local usage

```python
from detection.detection_engine import DetectionEngine
from forensic.evidence_collection.collector import ForensicEvidenceCollector
from soar.response.week3_workflow import Week3ResponseWorkflow

workflow = Week3ResponseWorkflow(ForensicEvidenceCollector())
packages = workflow.process_events(DetectionEngine(), events)

for package in packages:
    print(package["alert_id"])
    print(package["evidence"]["process_information"])
    print(package["evidence"]["network_connections"])
    print(package["evidence"]["file_information"])
    print(package["evidence"]["process_tree"])
    print(package["response_plan"])
```

`events` must be normalized `SecurityEvent` objects. The workflow returns one
package per generated alert. The evidence includes raw event snapshots, which
may contain sensitive host data; restrict access and retention to authorized
analysts.

Run the focused tests:

```powershell
python -m pytest -q tests/test_week3_response.py
```

## Completion status and next requirements

| Requirement | Status |
|---|---|
| Create evidence bundles from normalized event batches | Implemented and locally tested |
| Include process, network, file, log context, timestamps, and observed process tree | Implemented when those values exist in supplied telemetry |
| Automatically select candidate response actions | Implemented as a dry-run plan |
| Verify missing telemetry and reject mixed-host bundles | Covered by focused tests |
| Actually isolate a process | Not implemented; requires an approved host response provider and isolated lab validation |
| Actually contain network traffic | Not implemented; requires an approved network control/provider and isolated lab validation |
| Collect evidence directly from the host or telemetry backend | Not implemented; this workflow consumes events supplied by callers |
| Test on the project’s deployed telemetry and dashboard | Pending integration with those components |

Do not enable real containment until an authorized Linux lab host, action
provider, target allowlist, operator approval policy, rollback procedure, and
audit trail have been agreed and tested. The current Python implementation
intentionally has no enforcement switch or host-changing code.
