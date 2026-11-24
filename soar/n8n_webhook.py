"""HTTP client for forwarding detection alerts to an n8n webhook."""

import json
import math
import os
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from detection.detection_engine import DetectionAlert
from detection.event_schema import SCHEMA_VERSION, SOC_PRODUCER


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


# urllib can turn an HTTP redirect into a GET and report the wrong endpoint's 2xx.
urlopen = build_opener(_NoRedirect()).open

def webhook_error_message(error: Exception) -> str:
    """Report enough to diagnose failures without logging the webhook URL."""
    if isinstance(error, HTTPError):
        return f"HTTP {error.code}"
    if isinstance(error, TimeoutError) or isinstance(getattr(error, "reason", None), TimeoutError):
        return "request timed out"
    if isinstance(error, RuntimeError) and str(error).startswith("n8n webhook returned unsuccessful status "):
        return str(error)
    return type(error).__name__


class N8nWebhookClient:
    """Send detection alerts to an n8n webhook using HTTP POST."""

    def __init__(self, webhook_url: str, timeout: float = 5.0) -> None:
        parsed_url = urlsplit(webhook_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
        ):
            raise ValueError("webhook_url must be an absolute HTTP or HTTPS URL")
        # Validate a malformed or out-of-range port during startup.
        _ = parsed_url.port
        if parsed_url.username or parsed_url.password:
            raise ValueError("webhook_url must not contain embedded credentials")
        if parsed_url.fragment:
            raise ValueError("webhook_url must not contain a fragment")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        self.webhook_url = webhook_url
        self.timeout = timeout

    @classmethod
    def from_env(cls, timeout: Optional[float] = None) -> "N8nWebhookClient":
        """Create a client from the required N8N_WEBHOOK_URL setting."""
        webhook_url = os.environ.get("N8N_WEBHOOK_URL")
        if not webhook_url:
            raise ValueError("N8N_WEBHOOK_URL must be set")
        if timeout is None:
            try:
                timeout = float(os.getenv("N8N_WEBHOOK_TIMEOUT", "5"))
            except ValueError as exc:
                raise ValueError("N8N_WEBHOOK_TIMEOUT must be a positive number") from exc
        return cls(webhook_url=webhook_url, timeout=timeout)

    def send_alert(
        self,
        alert: DetectionAlert,
        response_package: Optional[Dict[str, Any]] = None,
    ) -> int:
        """POST one detection alert and return the HTTP response status."""
        return self.send_alert_record(alert.to_dict(), response_package)

    def send_alert_record(
        self,
        alert: Dict[str, Any],
        response_package: Optional[Dict[str, Any]] = None,
    ) -> int:
        """POST a serialized alert, including ones recovered from local JSONL."""
        payload = {
            "schema_version": SCHEMA_VERSION,
            "producer": SOC_PRODUCER,
            "source": SOC_PRODUCER,
            "alert": alert,
        }
        if response_package is not None:
            payload["response"] = response_package
        request = Request(
            self.webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        with urlopen(request, timeout=self.timeout) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(
                    f"n8n webhook returned unsuccessful status {response.status}"
                )
            return response.status

    def send_alerts(
        self,
        alerts: List[DetectionAlert],
        response_packages: Optional[List[Dict[str, Any]]] = None,
    ) -> List[int]:
        """POST alerts in order, preserving optional response evidence packages."""
        if response_packages is None:
            return [self.send_alert(alert) for alert in alerts]
        if len(response_packages) != len(alerts):
            raise ValueError("response_packages must match the alerts length")
        return [
            self.send_alert(alert, response_package)
            for alert, response_package in zip(alerts, response_packages)
        ]
