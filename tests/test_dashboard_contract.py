import json
from pathlib import Path


def load_dashboard():
    dashboard_path = (
        Path(__file__).resolve().parents[1]
        / "dashboard"
        / "grafana"
        / "soc_dashboard.json"
    )
    return json.loads(dashboard_path.read_text(encoding="utf-8"))


def query_for(dashboard, title):
    for panel in dashboard["spec"]["elements"].values():
        panel_spec = panel["spec"]
        if panel_spec["title"] == title:
            return panel_spec["data"]["spec"]["queries"][0]["spec"][
                "query"
            ]["spec"]
    raise AssertionError(f"dashboard panel not found: {title}")


def test_dashboard_has_event_and_alert_panels_for_canonical_indices():
    dashboard = load_dashboard()
    panels = dashboard["spec"]["elements"]
    titles = {panel["spec"]["title"] for panel in panels.values()}

    assert len(panels) == 11
    assert {
        "Total Security Events",
        "Security Events by Severity",
        "Security Events Detail Table",
        "Security Events Trend",
        "Detection Alert Count",
        "Alerts by Severity",
        "Events by Source",
        "Process Information",
        "Alerts, MITRE and Response Details",
        "Response Status",
        "Forensic Evidence Availability",
    } == titles

    for panel in panels.values():
        query = panel["spec"]["data"]["spec"]["queries"][0]["spec"][
            "query"
        ]["spec"]
        assert query["timeField"] == "@timestamp"
        assert query["queryType"] == "esql"
        assert "FROM security-events" in query["query"] or (
            "FROM security-alerts" in query["query"]
        )


def test_dashboard_queries_cover_p1_process_mitre_and_response_fields():
    dashboard = load_dashboard()
    process_query = query_for(dashboard, "Process Information")["query"]
    alert_query = query_for(
        dashboard,
        "Alerts, MITRE and Response Details",
    )["query"]
    response_query = query_for(dashboard, "Response Status")["query"]
    evidence_query = query_for(
        dashboard,
        "Forensic Evidence Availability",
    )["query"]

    assert "FROM security-events" in process_query
    assert "`process.name`" in process_query
    assert "process_name" in process_query
    assert "FROM security-alerts" in alert_query
    assert "`mitre.tactics.id`" in alert_query
    assert "`mitre.tactics.name`" in alert_query
    assert "`mitre.techniques.id`" in alert_query
    assert "`mitre.techniques.name`" in alert_query
    assert "response_status" in alert_query
    assert "evidence_available" in alert_query
    assert "BY response_status" in response_query
    assert "BY evidence_available" in evidence_query


def test_dashboard_layout_references_every_panel_once():
    dashboard = load_dashboard()
    panel_names = set(dashboard["spec"]["elements"])
    references = [
        item["spec"]["element"]["name"]
        for item in dashboard["spec"]["layout"]["spec"]["items"]
    ]

    assert set(references) == panel_names
    assert len(references) == len(set(references))
