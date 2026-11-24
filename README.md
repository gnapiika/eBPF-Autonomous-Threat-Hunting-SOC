# eBPF-Powered Autonomous Threat Hunting SOC

This internship project from **Zaalima Development Pvt. Ltd.** collects Linux security telemetry, applies detection rules, enriches alerts with MITRE ATT&CK, and gives analysts an evidence package and a simulated response plan. The project can also demonstrate process, network, and file telemetry using synthetic data on Windows.

## Architecture and team

```text
Falco / Tetragon JSONL -> file forwarder -------+
Synthetic process / network / file event -----+-> Kafka security-events
                                                        |
                                                 Normalize UTC event
                                                 |                 |
                             Elasticsearch security-events     Detect + MITRE
                                                 |                 |
                                                 |      Evidence + dry-run plan
                                                 |                 |
                                                 |        JSONL alert record
                                                 |                 |
                                                 |          Optional n8n POST
                                                 |          + SQLite success ledger
                                                 |                 |
                                                 |   Elasticsearch security-alerts
                                                 |                 |
                                                 +-------> Grafana <+
```

| Member | Responsibility | Main paths |
| --- | --- | --- |
| 1 | Falco/eBPF and Tetragon telemetry formats, synthetic data, Kafka producer | `telemetry/` |
| 2 | Normalization, detection rules, MITRE mapping, correlation, anomaly analysis, and hunting | `detection/`, `scripts/member2_demo.py` |
| 3 | Kafka consumer integration, n8n routing, simulated responses, and event-backed evidence | `soar/`, `forensic/`, `telemetry/kafka_detection_consumer.py` |
| 4 | Elasticsearch ingestion and Grafana dashboard | `soar/elasticsearch_ingestion.py`, `dashboard/` |

The streaming consumer evaluates individual events. Login correlation, anomaly detection, and threat hunting are available through Member 2's batch APIs. Run `python -m scripts.member2_demo` for the behavior, anomaly, and hunting demo. The [canonical schema](docs/architecture/event_schema_contract.md) defines UTC timestamps, severity, ATT&CK objects, and compatibility aliases.

## Setup and tests

Run the commands from the repository root. Python 3.10 or later is required. The offline demonstration uses the standard library. Kafka transport requires the pinned client in `requirements.txt`, and the test suite uses pytest.

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt pytest
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python.exe -m scripts.soc_demo
```

**Linux or WSL**

```bash
python3 -m venv .venv-wsl
.venv-wsl/bin/python -m pip install -r requirements.txt pytest
.venv-wsl/bin/python -m pytest -q -p no:cacheprovider
.venv-wsl/bin/python -m scripts.soc_demo
```

The offline demo saves two alerts and evidence packages in `telemetry/detection_alerts.jsonl`. The synthetic process record generates medium-severity `DET-001`, the network record generates medium-severity `DET-003`, and the ordinary file record is normalized without an alert. Set `SOC_DETECTION_OUTPUT` to select another JSONL file.

See the [presentation guide](docs/final-demo.md) for ordered commands and expected output. The [submission report](docs/final-submission-report.md) records the verified test count and live service results.

## Kafka, Elasticsearch, and Grafana

The local Compose stack pins Apache Kafka 3.9.1, Elasticsearch 9.4.9, and Grafana 13.2.3. Install and start Docker Desktop on Windows, or Docker Engine with the Compose plugin on Linux. Docker Desktop uses a Linux container engine. Diagnose WSL with `wsl --status` and `wsl --list --verbose`; the collector requires a usable Linux distribution and an eBPF-capable kernel.

1. Copy `.env.example` to `.env` if `.env` does not already exist. Edit `GRAFANA_ADMIN_PASSWORD` in the private file with a unique local password.
2. Run `docker compose config --quiet`, then `docker compose up -d --wait` and `docker compose ps`.
3. Start the consumer, using the commands in the [presentation guide](docs/final-demo.md).
4. Publish synthetic data with `python -m telemetry.simple_event --kafka`. Add `--kind network` or `--kind file` for other example records.
5. Open Grafana at `http://127.0.0.1:3000`. Sign in as `admin` and open **eBPF Autonomous Threat Hunting SOC**. Use **Last 15 minutes** for a new run.
6. Stop services with `docker compose stop`. Named volumes preserve the stack's data.

Compose provisions the dashboard and its Elasticsearch data source. The [dashboard guide](dashboard/README.md) also covers manual import, index names, and queries. The standalone Kafka setup at `telemetry/kafka/docker-compose.yml` is available for Kafka-only work. It and the root stack use the same host port, so start one broker at a time. Member 1's historical Compose file remains available for reference.

### Configuration

Python reads values exported in its process environment. Docker Compose reads `.env` for interpolation. Keep actual URLs and credentials in private environment variables or the ignored local file.

| Variable | Default or purpose |
| --- | --- |
| `SOC_KAFKA_BOOTSTRAP`, `SOC_KAFKA_TOPIC` | `127.0.0.1:9092`, `security-events`. Both clients also accept legacy `KAFKA_BOOTSTRAP_SERVERS` / `KAFKA_BOOTSTRAP` and `KAFKA_TOPIC`. |
| `SOC_KAFKA_GROUP_ID`, `SOC_KAFKA_OFFSET_RESET` | `soc-detection-engine`, `latest`. Set `earliest` for a new presentation group to include retained records. |
| `FALCO_EVENTS_FILE` | File forwarder defaults to `/var/log/falco/events.json`. The synthetic writer defaults to `data/synthetic-falco.jsonl`. Both accept `FALCO_LOG` or an explicit `--file`. |
| `SOC_DETECTION_OUTPUT`, `SOC_FORWARDED_ALERTS_DB` | `telemetry/detection_alerts.jsonl`, `telemetry/forwarded_alerts.sqlite3`. |
| `ELASTICSEARCH_URL` | Optional. Set to `http://127.0.0.1:9200` for Compose. |
| `ELASTICSEARCH_EVENTS_INDEX`, `ELASTICSEARCH_ALERTS_INDEX` | `security-events`, `security-alerts`. Update dashboard queries if you change them. |
| `ELASTICSEARCH_USERNAME` and `ELASTICSEARCH_PASSWORD`, or `ELASTICSEARCH_API_KEY` | Alternate authentication options for a secured Elasticsearch endpoint. |
| `N8N_WEBHOOK_URL`, `N8N_WEBHOOK_TIMEOUT` | Optional private endpoint and timeout in seconds (default `5`). |
| `GRAFANA_ADMIN_PASSWORD` | Required for Compose. Applies when Grafana initializes its database. |

The local demo services bind host ports to loopback. The lab Elasticsearch service uses plain HTTP with security and mmap disabled. Use synthetic data in this lab. For a secured Elasticsearch server, use HTTPS and give the Python identity index creation, mapping update, and document write permissions. Evidence can include raw events and command-line arguments. Keep JSONL, SQLite, and any copies of alert payloads private.

## n8n and forensic evidence

Import [the sanitized workflow](soar/workflows/soc_alert_response.json) into your n8n editor. Open the Webhook node, choose **Test URL**, and select **Listen for test event**. Set `N8N_WEBHOOK_URL` privately in the terminal running the script. Start a new listener for each branch.

```powershell
$env:N8N_WEBHOOK_URL = [System.Net.NetworkCredential]::new('', (Read-Host 'Paste n8n Test URL' -AsSecureString)).Password
.\.venv\Scripts\python.exe -m scripts.soc_demo --webhook medium
# In n8n, select Listen for test event again.
.\.venv\Scripts\python.exe -m scripts.soc_demo --webhook high
Remove-Item Env:N8N_WEBHOOK_URL
```

On Linux use `read -rsp 'Paste n8n Test URL: ' N8N_WEBHOOK_URL`, then `export N8N_WEBHOOK_URL` and run the same modules using `.venv-wsl/bin/python`.

| Alert severity | n8n response action |
| --- | --- |
| `high` | `high_severity_review` |
| `medium`, `critical`, `low`, `info` (informational) | `manual_review` |

The current policy uses an exact comparison to `high`. Both branches keep `body.alert` and `body.response` and add `response_action` and `response_status=simulated` to the output item. The medium example comes from `DET-001`. The high example is a synthetic `TEST-HIGH` alert. Verify the selected node in n8n's execution view. Python records an HTTP operation as accepted when it returns 2xx. The local response package is always a dry run with `approval_required=true` and `execution_performed=false`.

## Real Linux telemetry

Use a Linux host or a WSL 2 distribution with an eBPF-capable kernel and the permissions required by the collector. Falco's modern eBPF driver typically requires Linux 5.8 or newer, BTF, and the kernel features needed by the installed Falco build. WSL kernel and distribution support can vary. Follow the [Falco setup and safe file demo](telemetry/falco/Configure-Falco.md). [Falco driver requirements](https://falco.org/about/faq/)

If Windows has WSL installed without a distribution, the machine owner can install Ubuntu in an elevated PowerShell session with `wsl --install -d Ubuntu`. After setup, check that Ubuntu reports version 2 with `wsl --list --verbose`, open it with `wsl -d Ubuntu`, and check the kernel as described in the Falco setup. Use a native Linux host if the WSL kernel lacks a feature your collector needs.

For an installed Tetragon agent exporting JSONL, run this from the repository root on the host with access to that file:

```bash
.venv-wsl/bin/python -m telemetry.falco.falco_kafka_forwarder --file /var/log/tetragon/tetragon.log
```

Start the consumer and generate only ordinary authorized host activity, such as `/usr/bin/true` to demonstrate process telemetry. Native Tetragon process execution and exit exports are supported. Network and file details come from Falco or structured records that contain those fields. Custom Tetragon tracing policies can emit different payloads and may require a mapper. The repository contains format handlers for generic eBPF telemetry. It relies on installed collectors for kernel capture. [Tetragon JSON events](https://tetragon.io/docs/concepts/events/)

## Delivery and troubleshooting

- **Kafka errors or no records.** Check `docker compose ps`, the broker health, and the topic and group used by both clients. `latest` only applies where the group has no valid prior offset. For a fresh demo group that needs retained records, set `SOC_KAFKA_OFFSET_RESET=earliest`. The forwarder tails new lines by default. Use `--from-start` to read existing lines.
- **Malformed records.** The consumer logs the topic, partition, and offset of a rejected record and commits past it. It commits valid records individually after processing. A local persistence or Kafka commit failure stops the consumer so a later offset cannot silently skip the failed record. Restart after resolving the error.
- **Webhook failures and replay.** The alert and simulated response are written before delivery. After fixing the endpoint, use `python -m scripts.soc_demo --replay ALERT_ID` with the same output and SQLite paths. Run replay while the consumer is stopped. A recorded 2xx prevents a resend for the same Kafka topic, partition, offset, and rule. Ambiguous timeouts, crashes between HTTP and SQLite, and separate ledgers can cause repeated delivery. Older JSONL records that lack a response or message key require reprocessing the retained Kafka source. JSONL is append-only and may contain repeated stable IDs. Keep the ledger with its Kafka cluster and topic history because offsets can be reused on new brokers or topics.
- **Elasticsearch failures.** Indexing is best effort. Failed writes are logged and the Kafka record can still be committed. To rebuild from retained Kafka records, run a fresh group with `earliest` and leave `N8N_WEBHOOK_URL` unset. This reindexes by deterministic document ID (and appends new JSONL entries). The dashboard's delivery field reflects the indexing run. There is no retry queue for expired Kafka records.
- **Grafana shows no data or a query error.** Verify `ELASTICSEARCH_URL` was exported for the consumer, the requested time window contains your events, and both indices have the expected mappings. If an existing index has incompatible field types, choose a new index and update its dashboard queries. Check `docker compose logs elasticsearch grafana` for service errors.
- **n8n returns HTTP 404.** Re-arm **Listen for test event** and send one request to the current Test URL. For repeated delivery, use a published workflow's Production URL only when its owner authorizes it. Inspect the execution output for the selected branch.

[Project repository](https://github.com/gnapiika/eBPF-Autonomous-Threat-Hunting-SOC)
