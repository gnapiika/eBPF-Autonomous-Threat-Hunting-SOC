# Grafana SOC dashboard

The dashboard uses the Elasticsearch data-source UID `bg10tjcobatq8c`. The local Compose stack provisions the data source and dashboard automatically. Open **eBPF Autonomous Threat Hunting SOC** and choose **Last 15 minutes** after publishing the demo samples.

## Panels and queries

| Index | What the dashboard shows |
| --- | --- |
| `security-events` | Total count, severity and source breakdowns, process execution, network and file fields, and a five-minute event timeline. |
| `security-alerts` | Alert count and severity, ATT&CK tactic and technique IDs and names, simulated response status, n8n request status, and forensic evidence availability. |

Queries use ES|QL and the `@timestamp` date field. Event and alert tables include `synthetic` so the presentation data is identifiable. The consumer initializes both index mappings so panels can query an empty alerts index. Events and alerts appear after Elasticsearch refreshes their indices.

`response_status` describes the local simulated response package. `external_workflow.delivery_status` reports the outbound request. `external_workflow.result_received` remains false because the project receives no separate workflow result.

## Manual import

1. In a Grafana instance using a compatible v2 dashboard schema and ES|QL data source, add an Elasticsearch data source with UID `bg10tjcobatq8c`. Use the URL reachable **from Grafana**, `@timestamp` as the time field, and `security-*` as the index pattern. For Compose, the internal Elasticsearch URL is `http://elasticsearch:9200`.
2. Upload [soc_dashboard.json](grafana/soc_dashboard.json) through the Grafana import screen, or provision the resource file using the [dashboard provider and data-source definitions](grafana/provisioning/).
3. Start the consumer with `ELASTICSEARCH_URL` set, publish demo telemetry, and inspect the queries in the dashboard. If you use custom Elasticsearch index names, update the relevant `FROM` clauses and data source.

The Python ingestor supports a username/password pair or an API key for authenticated Elasticsearch. Compose uses a loopback-only demo endpoint. If a previously created index has incompatible field mappings, Elasticsearch requires migration or a new compatible index. The project logs failed writes and continues detection. See the [README](../README.md#delivery-and-troubleshooting) for retained Kafka replay.

[Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/) · [Elasticsearch query editor](https://grafana.com/docs/grafana/latest/datasources/elasticsearch/query-editor/)
