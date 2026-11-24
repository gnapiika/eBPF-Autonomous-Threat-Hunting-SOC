# Week 3: Complete and verify n8n alert responses

For the current import file and reusable medium/high commands, see the [final n8n demonstration](final-demo.md#3-show-the-n8n-branches). The examples and verification below describe the original weekly implementation.

Week 3 adds an explicit status to each simulated response, rechecks alert
routing, and documents the Python/n8n integration and proposed team contract.
The response remains simulated: it does not contain or execute containment
actions.

## Workflow configuration in n8n

In the existing `SOC Alert Response` workflow, keep the IF condition checking
whether `body.alert.severity` is exactly `high`. Configure both Edit Fields
nodes to retain their incoming fields, then add these fields:

| IF output | `response_action` | `response_status` |
|---|---|---|
| True → `Edit Fields1` | `high_severity_review` | `simulated` |
| False → `Edit Fields` | `manual_review` | `simulated` |

Set `response_status` to the string `simulated` in each node. The input alert
should remain available in the final output, including its `alert_id`,
`severity`, rule, host, and other original fields. With the existing Python
payload, the alert fields are nested under `body.alert`; the response fields
are added to the output item by the selected Edit Fields node.

The live workflow was inspected on 26 October 2026. Its IF node compares
`{{ $json.body.alert.severity }}` to the fixed string `high` using `is equal
to`. The True connection goes to `Edit Fields1` (`high_severity_review`), and
the False connection goes to `Edit Fields` (`manual_review`). Both nodes have
**Include Other Input Fields** enabled with **All** selected, and both now
include the string field `response_status` set to `simulated`.

## Expected branch results

| Test `alert_id` | Severity | IF output | `response_action` | `response_status` |
|---|---|---|---|---|
| `TEST-HIGH-001` | `high` | True | `high_severity_review` | `simulated` |
| `TEST-MEDIUM-001` | `medium` | False | `manual_review` | `simulated` |

The IF condition is an exact comparison, so `medium` and every other value
besides `high` follow False. Keep a high-severity branch test synthetic; it
does not represent a real attack or detection.

## Run a live test

The Python client sends one JSON `POST` per alert. Its payload is shaped like:

```json
{
  "source": "ebpf-autonomous-threat-hunting-soc",
  "alert": {
    "alert_id": "TEST-HIGH-001",
    "severity": "high"
  }
}
```

The real alert object includes additional fields such as `rule_id`, `host`,
`timestamp`, and evidence. Do not add `response_action` or
`response_status` in Python: those are the workflow's response output.

1. In n8n, open the workflow and click **Listen for test event** on the
   Webhook node.
2. Set `N8N_WEBHOOK_URL` in the PowerShell terminal to the current n8n **Test
   URL**. Keep the URL private:

   ```powershell
   $env:N8N_WEBHOOK_URL = "YOUR_CURRENT_N8N_TEST_WEBHOOK_URL"
   ```

3. To verify the actual detection pipeline's medium alert, run:

   ```powershell
   @'
   from detection.detection_engine import DetectionEngine
   from detection.event_schema import ProcessInfo, SecurityEvent
   from soar.detection_integration import DetectionSoarIntegration
   from soar.n8n_webhook import N8nWebhookClient

   event = SecurityEvent(
       event_type="process_execution",
       source="test",
       host="test-server",
       process=ProcessInfo(name="bash", command_line="bash -c whoami"),
   )
   integration = DetectionSoarIntegration(
       DetectionEngine(),
       N8nWebhookClient.from_env(),
   )
   alerts = integration.process_events([event])
   print([(alert.alert_id, alert.rule_id, alert.severity) for alert in alerts])
   '@ | python -
   ```

   This event is simulated and does not execute the command. The current
   `DET-001` rule should produce a `medium` alert. Inspect the n8n execution
   for the False branch and verify the original alert fields,
   `response_action: manual_review`, and `response_status: simulated`.

4. To verify the high branch, start a new test-listener execution and send a
   synthetic alert:

   ```powershell
   @'
   from datetime import datetime, timezone
   from detection.detection_engine import DetectionAlert
   from soar.n8n_webhook import N8nWebhookClient

   alert = DetectionAlert(
       alert_id="TEST-HIGH-001",
       rule_id="TEST-HIGH",
       rule_name="Synthetic high-severity branch test",
       severity="high",
       description="Synthetic test payload for the n8n high branch.",
       event_id="test-high-event",
       event_type="test",
       source="manual-test",
       host="test-server",
       timestamp=datetime.now(timezone.utc).isoformat(),
   )
   status = N8nWebhookClient.from_env().send_alert(alert)
   print("HTTP status:", status, "| alert_id:", alert.alert_id)
   '@ | python -
   ```

   Inspect the n8n execution and verify the True branch and its output fields:
   `response_action: high_severity_review` and
   `response_status: simulated`, with the original alert still present.

An HTTP `200` confirms an HTTP response, not that the intended branch or final
fields are correct. Verify those in the n8n execution output. Python unit tests
mock HTTP and cannot confirm n8n received a request. A `404` from an n8n test
URL usually means the Webhook node is no longer listening; start the listener
again and retry.

## Integration contract and storage

Proposed alert contract for coordination with the detection and dashboard
members:

- Preserve the existing envelope: `source` plus the complete `alert` object.
- Keep detection fields in `alert`; add `response_action` and
  `response_status` to the workflow's output item.
- Treat response labels as simulated metadata, not evidence that a host action
  was performed.
- Confirm with the team whether the dashboard needs these response fields,
  which fields it displays, and whether it reads n8n output or another
  integration.

No permanent storage is added. The current requirement is to route an alert
and inspect its execution; add a persistence service only if the team confirms
that durable alert history or dashboard queries require one.

## Week 3 verification record

| Check | Result |
|---|---|
| Python webhook and detection integration tests | Verified locally: `14 passed` |
| Week 3 evidence and response tests | Verified locally: `8 passed` |
| Full Python test suite | Verified locally: `62 passed` |
| IF condition and true/false branch wiring | Verified in the live workflow editor |
| Both response status fields added | Verified in the live workflow editor |
| Original input fields preserved in both Edit Fields nodes | Verified: Include Other Input Fields is enabled and set to All |
| High and medium branch executions after changes | Pending: inspect executions for branch, response fields, and original alert fields |
| Exact output field paths in n8n execution data | Pending live execution inspection; node configuration alone does not prove the final shape |
| Python-to-n8n live delivery after workflow changes | Pending; requires the current test URL and active listener |
| Alert/dashboard contract agreed with project members | Pending team confirmation |
| Permanent storage | Not added; no current need established |

The medium-branch example below constructs a test event in Python. Its source
is labeled `test`, not `tetragon`, because the event was not collected by
Tetragon. The sample command is descriptive test data; it is not executed.

The workflow editor shows **Publish**. The changes are in the editor, but the
workflow has not been published; publishing may change the workflow available
to production callers and should be coordinated before release. Use the n8n
test listener for the live checks unless the project owner explicitly approves
publishing.

Run the local tests from the repository root:

```powershell
python -m pytest -q tests/test_n8n_webhook.py tests/test_detection_soar_integration.py
```

These tests verify JSON payload construction and Python forwarding behavior;
they use mocked HTTP and are not a substitute for the live n8n checks above.
