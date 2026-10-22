"""HTTP client for forwarding detection alerts to an n8n webhook."""

import json
import os
from typing import List
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from detection.detection_engine import DetectionAlert


class N8nWebhookClient:
    """Send detection alerts to an n8n webhook using HTTP POST."""

    def __init__(self, webhook_url: str, timeout: float = 5.0) -> None:
        parsed_url = urlsplit(webhook_url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
        ):
            raise ValueError("webhook_url must be an absolute HTTP or HTTPS URL")
        if parsed_url.username or parsed_url.password:
            raise ValueError("webhook_url must not contain embedded credentials")
        if parsed_url.fragment:
            raise ValueError("webhook_url must not contain a fragment")
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")

        self.webhook_url = webhook_url
        self.timeout = timeout

    @classmethod
    def from_env(cls, timeout: float = 5.0) -> "N8nWebhookClient":
        """Create a client from the required N8N_WEBHOOK_URL setting."""
        webhook_url = os.environ.get("N8N_WEBHOOK_URL")
        if not webhook_url:
            raise ValueError("N8N_WEBHOOK_URL must be set")
        return cls(webhook_url=webhook_url, timeout=timeout)

    def send_alert(self, alert: DetectionAlert) -> int:
        """POST one detection alert and return the HTTP response status."""
        payload = {
            "source": "ebpf-autonomous-threat-hunting-soc",
            "alert": alert.to_dict(),
        }
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
            return response.status

    def send_alerts(self, alerts: List[DetectionAlert]) -> List[int]:
        """POST each alert in order and return their HTTP response statuses."""
        return [self.send_alert(alert) for alert in alerts]
