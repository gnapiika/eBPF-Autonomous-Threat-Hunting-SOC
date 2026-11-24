# Final presentation

Run each command from the repository root. The offline path works with Python on Windows. The service path needs Docker and a private Grafana password. Use the webhook checks only with a workflow you control.

## 1. Offline fallback

```powershell
$env:SOC_DETECTION_OUTPUT = 'data/demo-alerts.jsonl'
python -m scripts.soc_demo
$row = Get-Content $env:SOC_DETECTION_OUTPUT -Tail 2 |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.rule_id -eq 'DET-001' }
$row | Select-Object alert_id, rule_id, severity, synthetic
$row.mitre | ConvertTo-Json -Depth 6
$row.response.response_plan | ConvertTo-Json -Depth 6
$row.response.evidence.coverage
```

Show two medium alerts (`DET-001` and `DET-003`), three normalized event types, and `DET-001` with Execution and T1059. Show `response_status=simulated`, the approval flag, and evidence coverage. The synthetic file record demonstrates normalization without creating an alert.

## 2. Start the stack

Create the virtual environment and install dependencies once using the [setup instructions](../README.md#setup-and-tests). Start Docker Desktop. In PowerShell:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
code --wait .env
docker compose config --quiet
docker compose up -d --wait
docker compose ps
docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic security-events --partitions 1 --replication-factor 1
```

Before running Compose, save a unique `GRAFANA_ADMIN_PASSWORD` in `.env`. If `code` is unavailable, open the file directly in VS Code. Keep the file off-screen during the presentation.

In terminal A, start the consumer:

```powershell
$env:ELASTICSEARCH_URL = 'http://127.0.0.1:9200'
$env:SOC_KAFKA_OFFSET_RESET = 'earliest'
$env:SOC_DETECTION_OUTPUT = 'data/kafka-demo-alerts.jsonl'
$env:SOC_FORWARDED_ALERTS_DB = 'data/kafka-demo-deliveries.sqlite3'
.\.venv\Scripts\python.exe -m telemetry.kafka_detection_consumer
```

In terminal B, publish three records:

```powershell
.\.venv\Scripts\python.exe -m telemetry.simple_event --kafka
.\.venv\Scripts\python.exe -m telemetry.simple_event --kafka --kind network
.\.venv\Scripts\python.exe -m telemetry.simple_event --kafka --kind file
Get-Content data/kafka-demo-alerts.jsonl -Tail 2
```

Point out the producer's Kafka offsets, the consumer's normalized event types, the detection rule IDs, and the event and alert indexing logs. Visit `http://127.0.0.1:3000`, sign in as `admin`, and open **eBPF Autonomous Threat Hunting SOC**. Use **Last 15 minutes**. Show the event and alert counts, process/network/file fields, MITRE columns, and simulated response and evidence panels. Counts reflect the selected window and any earlier runs. The event and alert counts increase by three and two for this set.

On Linux or WSL, use the same Compose commands after privately editing `.env`. Replace PowerShell environment assignments with the following and use `.venv-wsl/bin/python` in each command:

```bash
export ELASTICSEARCH_URL=http://127.0.0.1:9200
export SOC_KAFKA_OFFSET_RESET=earliest
export SOC_DETECTION_OUTPUT=data/kafka-demo-alerts.jsonl
export SOC_FORWARDED_ALERTS_DB=data/kafka-demo-deliveries.sqlite3
.venv-wsl/bin/python -m telemetry.kafka_detection_consumer
```

## 3. Show the n8n branches

In n8n, use **Import from File** with [soc_alert_response.json](../soar/workflows/soc_alert_response.json). Open the Webhook node, select **Test URL**, then **Listen for test event**.

```powershell
$env:N8N_WEBHOOK_URL = [System.Net.NetworkCredential]::new('', (Read-Host 'Paste n8n Test URL' -AsSecureString)).Password
.\.venv\Scripts\python.exe -m scripts.soc_demo --webhook medium
# Re-arm Listen for test event in n8n before the high test.
.\.venv\Scripts\python.exe -m scripts.soc_demo --webhook high
Remove-Item Env:N8N_WEBHOOK_URL
```

In the n8n editor, show `manual_review` for medium and `high_severity_review` for high. Both outputs should retain `body.alert`, `body.response.evidence`, and `body.response.response_plan`. Both add `response_status=simulated`. Verify the output for each execution even when Python reports HTTP 2xx.

For a single end-to-end attempt with the n8n Test URL, stop the consumer in terminal A, privately set its `N8N_WEBHOOK_URL`, re-arm the listener, restart the consumer, and publish only the process sample in terminal B. Confirm its `DET-001` alert in Kafka consumer output, n8n, and Grafana. If you set the Test URL after starting the consumer, restart the consumer so it reads the new variable.

## 4. Stop the demo

Press **Ctrl+C** in the consumer terminal, then run `docker compose stop`. This keeps the Compose data volumes.
