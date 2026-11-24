# Week 2: Route security alerts in n8n

For the current import file and reusable medium/high commands, see the [final n8n demonstration](final-demo.md#3-show-the-n8n-branches). The examples and verification below describe the original weekly implementation.

This guide explains what was built and tested in Week 2, what the results
mean, and how to repeat the tests safely.

## The goal

In Week 1, the Python project detected a suspicious event and sent its alert to
n8n. In Week 2, n8n was configured to inspect the alert severity and choose a
simulated response label:

```text
Simulated event
    -> Python Detection Engine
    -> JSON alert sent by HTTP POST
    -> n8n Webhook
    -> IF node checks severity
         -> True:  response_action = high_severity_review
         -> False: response_action = manual_review
```

The response labels are for testing and review. They do not stop processes,
change network settings, or take other action on a computer.

## What each part means

### 1. Python creates an alert

The project uses the `DET-001` rule for suspicious shell execution. The
simulated event used for the test described a `bash` command, but the command
was not executed. The detection rule currently assigns this alert **medium**
severity.

The integration code evaluates the event and passes any generated alerts to
the webhook client. The client sends one JSON `POST` request per alert.

### 2. n8n's Webhook receives the alert

The Webhook node is configured for `POST`. The incoming JSON has this
important shape:

```json
{
  "source": "ebpf-autonomous-threat-hunting-soc",
  "alert": {
    "rule_id": "DET-001",
    "severity": "medium"
  }
}
```

n8n exposes the request body as `body`, so the severity is available at
`body.alert.severity`.

### 3. The IF node sorts the alert

The IF node condition is:

| Setting | Value |
|---|---|
| Value 1 | `{{ $json.body.alert.severity }}` (Expression mode) |
| Operator | `is equal to` |
| Value 2 | `high` |

If the incoming severity exactly equals `high`, the item leaves the **True**
output. Any other value, including `medium`, leaves the **False** output.

### 4. Edit Fields labels the simulated response

An **Edit Fields** node is connected to each IF output. Each adds a string
field named `response_action`:

| IF output | `response_action` |
|---|---|
| True | `high_severity_review` |
| False | `manual_review` |

The nodes are configured to include the other input fields too, so the alert
is still available alongside the new response label. This adds the field to
the workflow's execution output; it does not save a separate record in a
database.

## What was tested and what happened

### Medium alert: detection from a simulated test event

The detection engine generated a `DET-001` alert from a manually constructed
simulated event whose source is `test`, not Tetragon-collected telemetry. Its
severity was `medium`. The alert was received by the n8n Webhook and took the
**False** branch. The False-branch output included:

```text
severity: medium
response_action: manual_review
response_status: simulated
```

This is the expected result because `medium` is not equal to `high`.

### High alert: synthetic branch test

The current `DET-001` detection rule produces a medium-severity alert, so it
cannot be used to test the high branch as-is. To test that branch, a separate
synthetic alert was sent directly through the webhook client with severity
`high` and test identifiers. It did not come from a real detection rule or a
real process event.

n8n received this synthetic alert, took the **True** branch, and the
True-branch output included:

```text
severity: high
response_action: high_severity_review
response_status: simulated
```

This confirms the high-severity path and its simulated response label work.

### Local automated tests

The project's integration tests were also run:

```powershell
python -m pytest -q tests/test_detection_soar_integration.py
```

Result: **2 passed**. These tests use a mock webhook client. They verify that
the Python integration forwards alerts, but they do not contact n8n. The live
webhook checks above were separate.

## Repeat the live tests

Run these steps from the repository root in PowerShell. Replace the placeholder
with the current **Test URL** shown in the n8n Webhook node. A test URL only
works while n8n is listening for a test event.

1. In n8n, open the workflow and click the Webhook node.
2. Click **Listen for test event** and leave it waiting.
3. In a VS Code PowerShell terminal, set the URL for that terminal session:

   ```powershell
   $env:N8N_WEBHOOK_URL = "YOUR_CURRENT_N8N_TEST_WEBHOOK_URL"
   ```

4. Send a manually constructed test event through the project's detection
   pipeline. The event is not collected by Tetragon, and the command is not
   executed:

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
   print([(alert.rule_id, alert.severity) for alert in alerts])
   '@ | python -
   ```

   The expected Python output includes `('DET-001', 'medium')`. In n8n, the
   IF node should show one item on **False**, and the False Edit Fields output
   should contain `response_action: manual_review` and
   `response_status: simulated`.

5. To exercise the high branch, click **Listen for test event** again if the
   earlier test has ended. Send a synthetic high alert (this tests the branch;
   it does not change the Detection Engine rule):

   ```powershell
   @'
   from datetime import datetime, timezone
   from detection.detection_engine import DetectionAlert
   from soar.n8n_webhook import N8nWebhookClient

   alert = DetectionAlert(
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
   print("HTTP status:", status, "| severity:", alert.severity)
   '@ | python -
   ```

   The expected HTTP status is `200`. In n8n, the IF node should show one item
   on **True**, and the True Edit Fields output should contain
   `response_action: high_severity_review` and
   `response_status: simulated`.

If Python reports HTTP `404`, the test listener is not active for that request.
Click **Listen for test event** again, then retry while it is waiting. Do not
use the test URL for a production workflow.

## Current scope and safety

- The Webhook and IF condition are configured for this test flow.
- Both IF outputs have their own simulated `response_action` label.
- The real Python `DET-001` alert is medium severity. The high test is
  synthetic and exists only to exercise the other branch.
- The workflow was tested with n8n's test listener. It was **not published**
  or activated for production.
- No process termination, host isolation, firewall changes, or other
  containment actions were added.
- Before publishing, review the workflow and choose the appropriate production
  webhook configuration. Production use is outside this test procedure.
