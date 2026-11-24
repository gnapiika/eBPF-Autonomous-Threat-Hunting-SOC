"""Optional Elasticsearch indexing for normalized SOC events and alerts."""

import base64
import hashlib
import json
import os
import re
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from detection.detection_engine import DetectionAlert
from detection.event_schema import SecurityEvent


_INDEX_NAME = re.compile(r"^[a-z0-9._-]+$")


class ElasticsearchIngestionError(RuntimeError):
    """Raised when an Elasticsearch document cannot be indexed."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_type = error_type


class ElasticsearchIngestor:
    """Index canonical events and alerts through Elasticsearch's REST API."""

    def __init__(
        self,
        url: str,
        events_index: str = "security-events",
        alerts_index: str = "security-alerts",
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        parsed_url = urlsplit(url)
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
        ):
            raise ValueError("Elasticsearch URL must be absolute HTTP or HTTPS")
        if parsed_url.username or parsed_url.password:
            raise ValueError("Elasticsearch URL must not contain credentials")
        if parsed_url.query or parsed_url.fragment:
            raise ValueError("Elasticsearch URL must not contain query or fragment")
        if timeout <= 0:
            raise ValueError("timeout must be greater than 0")
        if (username is None) != (password is None):
            raise ValueError("Elasticsearch username and password must be paired")
        if api_key and (username is not None or password is not None):
            raise ValueError("Configure either an API key or basic auth, not both")

        self.url = url.rstrip("/")
        self.events_index = self._validate_index(events_index)
        self.alerts_index = self._validate_index(alerts_index)
        if self.events_index == self.alerts_index:
            raise ValueError("Elasticsearch events and alerts require separate indices")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.timeout = timeout
        self._mapped_indices = set()

    @classmethod
    def from_env(cls) -> Optional["ElasticsearchIngestor"]:
        """Create an ingestor when ELASTICSEARCH_URL is configured."""
        url = os.environ.get("ELASTICSEARCH_URL")
        if not url:
            return None
        return cls(
            url=url,
            events_index=os.environ.get(
                "ELASTICSEARCH_EVENTS_INDEX",
                "security-events",
            ),
            alerts_index=os.environ.get(
                "ELASTICSEARCH_ALERTS_INDEX",
                "security-alerts",
            ),
            username=os.environ.get("ELASTICSEARCH_USERNAME") or None,
            password=os.environ.get("ELASTICSEARCH_PASSWORD") or None,
            api_key=os.environ.get("ELASTICSEARCH_API_KEY") or None,
        )

    @staticmethod
    def _validate_index(index: str) -> str:
        if not _INDEX_NAME.fullmatch(index):
            raise ValueError(f"Invalid Elasticsearch index name: {index}")
        return index

    @staticmethod
    def deterministic_document_id(namespace: str, identity: str) -> str:
        """Create a URL-safe ID stable for the same source identity."""
        return hashlib.sha256(
            f"{namespace}:{identity}".encode("utf-8")
        ).hexdigest()

    def index_event(
        self,
        event: SecurityEvent,
        document_id: Optional[str] = None,
    ) -> int:
        """Index one normalized event in the security-events index."""
        document = event.to_dict()
        if not document.get("@timestamp"):
            raise ValueError("event must contain @timestamp")
        event_id = document.get("event_id")
        if not event_id:
            raise ValueError("event must contain event_id")

        stable_id = document_id or self.deterministic_document_id(
            "event",
            event_id,
        )
        return self._index_document(
            self.events_index,
            stable_id,
            document,
        )

    def index_alert(
        self,
        alert: DetectionAlert,
        response_package: Optional[Dict[str, Any]] = None,
        external_workflow: Optional[Dict[str, Any]] = None,
        document_id: Optional[str] = None,
    ) -> int:
        """Index a canonical alert and its optional response package."""
        document = alert.to_dict()
        if not document.get("@timestamp"):
            raise ValueError("alert must contain @timestamp")
        alert_id = document.get("alert_id")
        if not alert_id:
            raise ValueError("alert must contain alert_id")
        if not document.get("event_id"):
            raise ValueError("alert must contain event_id")

        if response_package is not None:
            document["response"] = response_package
            document["response_status"] = response_package.get(
                "response_status"
            )
            document["evidence_available"] = bool(
                response_package.get("evidence")
            )
        else:
            document["evidence_available"] = False

        document["external_workflow"] = external_workflow or {
            "provider": "n8n",
            "delivery_status": "not_configured",
            "result_received": False,
        }
        stable_id = document_id or self.deterministic_document_id(
            "alert",
            alert_id,
        )
        return self._index_document(
            self.alerts_index,
            stable_id,
            document,
        )

    def _index_document(
        self,
        index: str,
        document_id: str,
        document: Dict[str, Any],
    ) -> int:
        self._ensure_index_mapping(index)
        target_url = (
            f"{self.url}/{quote(index, safe='')}/_doc/"
            f"{quote(document_id, safe='')}"
        )
        return self._request("PUT", target_url, document)

    def ensure_indices(self) -> None:
        """Create mapped indices even when the first events produce no alerts."""
        for index in (self.events_index, self.alerts_index):
            self._ensure_index_mapping(index)

    def _ensure_index_mapping(self, index: str) -> None:
        if index in self._mapped_indices:
            return

        properties = (
            self._event_mapping()
            if index == self.events_index
            else self._alert_mapping()
        )
        try:
            self._request(
                "PUT",
                f"{self.url}/{quote(index, safe='')}",
                {"mappings": {"properties": properties}},
            )
        except ElasticsearchIngestionError as exc:
            if exc.error_type != "resource_already_exists_exception":
                raise
            self._request(
                "PUT",
                f"{self.url}/{quote(index, safe='')}/_mapping",
                {"properties": properties},
            )
        self._mapped_indices.add(index)

    @staticmethod
    def _process_mapping() -> Dict[str, Any]:
        return {
            "properties": {
                "pid": {"type": "long"},
                "ppid": {"type": "long"},
                "name": {"type": "keyword"},
                "executable": {"type": "keyword"},
                "command_line": {"type": "text"},
                "parent_name": {"type": "keyword"},
                "parent_executable": {"type": "keyword"},
            }
        }

    @classmethod
    def _event_mapping(cls) -> Dict[str, Any]:
        return {
            "schema_version": {"type": "keyword"},
            "producer": {"type": "keyword"},
            "synthetic": {"type": "boolean"},
            "event_id": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "source": {"type": "keyword"},
            "host": {"type": "keyword"},
            "@timestamp": {"type": "date"},
            "timestamp": {"type": "date"},
            "timestamp_source": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "process": cls._process_mapping(),
            "process_name": {"type": "keyword"},
            "user": {
                "properties": {
                    "uid": {"type": "long"},
                    "gid": {"type": "long"},
                    "username": {"type": "keyword"},
                }
            },
            "network": {
                "properties": {
                    "source_ip": {"type": "keyword"},
                    "source_port": {"type": "integer"},
                    "destination_ip": {"type": "keyword"},
                    "destination_port": {"type": "integer"},
                    "protocol": {"type": "keyword"},
                }
            },
            "file": {
                "properties": {
                    "path": {"type": "keyword"},
                    "operation": {"type": "keyword"},
                    "hash_sha256": {"type": "keyword"},
                }
            },
            "mitre": cls._mitre_mapping(),
            "mitre_tactics": {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "tags": {"type": "keyword"},
            "metadata": {"type": "object", "enabled": False},
            "raw_event": {"type": "object", "enabled": False},
        }

    @classmethod
    def _alert_mapping(cls) -> Dict[str, Any]:
        return {
            "schema_version": {"type": "keyword"},
            "producer": {"type": "keyword"},
            "synthetic": {"type": "boolean"},
            "alert_id": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "rule_name": {"type": "keyword"},
            "description": {"type": "text"},
            "event_id": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "source": {"type": "keyword"},
            "host": {"type": "keyword"},
            "@timestamp": {"type": "date"},
            "timestamp": {"type": "date"},
            "timestamp_source": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "process": cls._process_mapping(),
            "process_name": {"type": "keyword"},
            "mitre": cls._mitre_mapping(),
            "mitre_tactics": {"type": "keyword"},
            "mitre_techniques": {"type": "keyword"},
            "evidence": {"type": "object", "enabled": False},
            "response": {
                "properties": {
                    "alert_id": {"type": "keyword"},
                    "response_status": {"type": "keyword"},
                    "evidence": {"type": "object", "enabled": False},
                    "response_plan": {
                        "properties": {
                            "mode": {"type": "keyword"},
                            "approval_required": {"type": "boolean"},
                            "execution_performed": {"type": "boolean"},
                            "actions": {"type": "object", "enabled": False},
                        }
                    },
                }
            },
            "response_status": {"type": "keyword"},
            "evidence_available": {"type": "boolean"},
            "external_workflow": {
                "properties": {
                    "provider": {"type": "keyword"},
                    "delivery_status": {"type": "keyword"},
                    "result_received": {"type": "boolean"},
                }
            },
        }

    @staticmethod
    def _mitre_mapping() -> Dict[str, Any]:
        entry = {
            "properties": {
                "id": {"type": "keyword"},
                "name": {"type": "keyword"},
            }
        }
        return {
            "properties": {
                "tactics": entry,
                "techniques": entry,
            }
        }

    def _request(
        self,
        method: str,
        target_url: str,
        document: Optional[Dict[str, Any]] = None,
    ) -> int:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        elif self.username is not None and self.password is not None:
            credentials = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {credentials}"

        try:
            request = Request(
                target_url,
                data=(
                    json.dumps(document).encode("utf-8")
                    if document is not None
                    else None
                ),
                headers=headers,
                method=method,
            )
            with urlopen(request, timeout=self.timeout) as response:
                status = response.status
                if not 200 <= status < 300:
                    raise ElasticsearchIngestionError(
                        f"Elasticsearch returned HTTP {status}",
                        status_code=status,
                    )
                return status
        except HTTPError as exc:
            try:
                with exc:
                    body = json.loads(exc.read())
                error = body.get("error") if isinstance(body, dict) else None
                error_type = (
                    error.get("type") if isinstance(error, dict) else None
                )
            except (ValueError, OSError):
                error_type = None
            raise ElasticsearchIngestionError(
                f"Elasticsearch returned HTTP {exc.code}",
                status_code=exc.code,
                error_type=error_type,
            ) from exc
        except (URLError, OSError, TimeoutError) as exc:
            raise ElasticsearchIngestionError(
                f"Elasticsearch request failed: {exc}"
            ) from exc
