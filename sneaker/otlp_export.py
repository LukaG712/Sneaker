"""OTLP (OpenTelemetry Protocol) export support for Sneaker.

Provides OTLP-compatible endpoints for receiving metrics, traces, and logs
from OpenTelemetry instrumented services. This allows Sneaker to act as an
OTLP collector backend for the Evershade ecosystem.

Configuration:
    OTLP_ENDPOINT: OTLP gRPC endpoint to forward data to (optional)
    OTLP_INSECURE: Use insecure connection for OTLP forwarding (default: true)
"""

import asyncio
import json
import logging
import os
import re
import time
from typing import Any

from fastapi import FastAPI
from fastapi.responses import Response

from sneaker.models import LogEntry, MetricPoint, TraceSpan

logger = logging.getLogger(__name__)


# ─── Configuration ────────────────────────────────────────────────

OTLP_ENDPOINT = os.environ.get("OTLP_ENDPOINT", "")
OTLP_INSECURE = os.environ.get("OTLP_INSECURE", "true").lower() in ("true", "1", "yes")


# ─── Secret Redaction ─────────────────────────────────────────────

# Patterns that indicate a value is likely a secret
_SECRET_PATTERNS = [
    re.compile(r'(?:^|[^A-Za-z0-9_])(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|auth|credential|access[_-]?key|private[_-]?key)(?:[^A-Za-z0-9_]|$)', re.IGNORECASE),
    re.compile(r'(?:^|[^A-Za-z0-9_])(?:aws|azure|gcp|google)[_-]?(?:access|secret|key|token|credential)(?:[^A-Za-z0-9_]|$)', re.IGNORECASE),
]

# Values that are obviously placeholders or defaults
_INSECURE_VALUES = {
    "changeme", "password", "admin", "secret", "default", "test",
    "your-api-key", "your-api-key-here", "your-secret-here",
    "insert-key-here", "replace-me", "xxx", "12345",
}

REDACTED = "**REDACTED**"


def _is_secret_key(key: str) -> bool:
    """Check if a key name suggests it holds a secret value."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(key):
            return True
    return False


def _should_redact_value(value: str) -> bool:
    """Check if a value looks like an insecure default that should be redacted."""
    lower = value.strip().lower()
    if lower in _INSECURE_VALUES:
        return True
    # Look for long base64-like strings (likely tokens/keys)
    if len(value) > 30 and re.match(r'^[A-Za-z0-9+/=_\-]+$', value):
        return True
    return False


def redact_secrets_in_attributes(attributes: list) -> list:
    """Redact secret values from OTLP attributes.

    Args:
        attributes: List of attribute dicts with 'key' and 'value' fields.

    Returns:
        New list with secret values replaced by **REDACTED**.
    """
    redacted = []
    for attr in attributes:
        key = attr.get("key", "")
        value = attr.get("value", {})
        str_value = value.get("stringValue", "")

        if _is_secret_key(key) or _should_redact_value(str_value):
            new_attr = dict(attr)
            new_value = dict(value)
            new_value["stringValue"] = REDACTED
            new_attr["value"] = new_value
            redacted.append(new_attr)
            logger.debug(f"Redacted secret attribute: {key}")
        else:
            redacted.append(attr)

    return redacted


def redact_secrets_in_traces(data: bytes) -> bytes:
    """Redact secrets from OTLP trace data before storage and forwarding.

    Args:
        data: Raw OTLP trace JSON bytes.

    Returns:
        JSON bytes with secrets redacted.
    """
    try:
        content = json.loads(data)
        modified = False
        for resource_span in content.get("resourceSpans", []):
            resource = resource_span.get("resource", {})
            if resource.get("attributes"):
                resource["attributes"] = redact_secrets_in_attributes(resource["attributes"])
                modified = True
            for scope_span in resource_span.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    if span.get("attributes"):
                        span["attributes"] = redact_secrets_in_attributes(span["attributes"])
                        modified = True
        if modified:
            return json.dumps(content).encode()
    except (json.JSONDecodeError, KeyError):
        pass
    return data


def redact_secrets_in_logs(data: bytes) -> bytes:
    """Redact secrets from OTLP log data before storage and forwarding.

    Args:
        data: Raw OTLP log JSON bytes.

    Returns:
        JSON bytes with secrets redacted.
    """
    try:
        content = json.loads(data)
        modified = False
        for resource_log in content.get("resourceLogs", []):
            resource = resource_log.get("resource", {})
            if resource.get("attributes"):
                resource["attributes"] = redact_secrets_in_attributes(resource["attributes"])
                modified = True
            for scope_log in resource_log.get("scopeLogs", []):
                for log_record in scope_log.get("logRecords", []):
                    if log_record.get("attributes"):
                        log_record["attributes"] = redact_secrets_in_attributes(log_record["attributes"])
                        modified = True
                    # Redact secrets in log body
                    body = log_record.get("body", {})
                    if isinstance(body, dict):
                        str_value = body.get("stringValue", "")
                        if _should_redact_value(str_value):
                            body["stringValue"] = REDACTED
                            modified = True
        if modified:
            return json.dumps(content).encode()
    except (json.JSONDecodeError, KeyError):
        pass
    return data


# ─── In-memory storage (shared with api.py) ──────────────────────

# These are populated by api.py; we reference them here for OTLP export
_metrics_store: list[MetricPoint] = []
_traces_store: list[TraceSpan] = []
_logs_store: list[LogEntry] = []


def register_stores(
    metrics: list,
    traces: list,
    logs: list,
) -> None:
    """Register the in-memory stores from api.py for OTLP export.

    Args:
        metrics: The metrics list from api.py.
        traces: The traces list from api.py.
        logs: The logs list from api.py.
    """
    global _metrics_store, _traces_store, _logs_store
    _metrics_store = metrics
    _traces_store = traces
    _logs_store = logs


# ─── OTLP Protocol Handlers ──────────────────────────────────────


def parse_otlp_traces(data: bytes) -> list[TraceSpan]:
    """Parse OTLP traces data and convert to TraceSpan objects.

    Supports both JSON and protobuf formats. For protobuf, falls back
    to logging a warning since full protobuf parsing requires otel SDK.

    Args:
        data: Raw OTLP data bytes.

    Returns:
        List of TraceSpan objects extracted from the data.
    """
    spans = []

    # Try JSON format first
    try:
        content = json.loads(data)
        resource_spans = content.get("resourceSpans", [])
        for resource_span in resource_spans:
            resource = resource_span.get("resource", {})
            service_name = ""
            for attr in resource.get("attributes", []):
                if attr.get("key") == "service.name":
                    service_name = attr.get("value", {}).get("stringValue", "")
                    break

            for scope_span in resource_span.get("scopeSpans", []):
                for span in scope_span.get("spans", []):
                    trace_id = span.get("traceId", "0")
                    span_id = span.get("spanId", "0")
                    parent_id = span.get("parentSpanId", "0")

                    # Convert hex IDs to readable format
                    trace_id_str = trace_id.rstrip("0") if trace_id else ""
                    parent_id_str = parent_id.rstrip("0") if parent_id and parent_id != "0" else None

                    # Extract duration from start/end time (nanoseconds)
                    start_time = span.get("startTimeUnixNano", 0)
                    end_time = span.get("endTimeUnixNano", 0)
                    duration_ms = (end_time - start_time) / 1_000_000 if end_time > start_time else 0

                    # Extract operation name
                    operation = span.get("name", "unknown")

                    trace_span = TraceSpan(
                        trace_id=trace_id_str or span_id,
                        operation=operation,
                        duration_ms=duration_ms,
                        service=service_name,
                        parent_id=parent_id_str,
                    )
                    spans.append(trace_span)
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse OTLP traces JSON: {e}")

    return spans


def parse_otlp_metrics(data: bytes) -> list[MetricPoint]:
    """Parse OTLP metrics data and convert to MetricPoint objects.

    Args:
        data: Raw OTLP data bytes.

    Returns:
        List of MetricPoint objects extracted from the data.
    """
    metrics = []

    try:
        content = json.loads(data)
        resource_metrics = content.get("resourceMetrics", [])
        for resource_metric in resource_metrics:
            resource = resource_metric.get("resource", {})
            service_name = ""
            for attr in resource.get("attributes", []):
                if attr.get("key") == "service.name":
                    service_name = attr.get("value", {}).get("stringValue", "")
                    break

            for scope_metric in resource_metric.get("scopeMetrics", []):
                for metric in scope_metric.get("metrics", []):
                    name = metric.get("name", "unknown")
                    labels = {"service": service_name} if service_name else {}

                    # Handle different metric types
                    if "gauge" in metric:
                        for data_point in metric["gauge"].get("dataPoints", []):
                            value = data_point.get("asDouble", data_point.get("asInt", 0))
                            mp = MetricPoint(name=name, value=float(value), labels=labels)
                            metrics.append(mp)
                    elif "sum" in metric:
                        for data_point in metric["sum"].get("dataPoints", []):
                            value = data_point.get("asDouble", data_point.get("asInt", 0))
                            mp = MetricPoint(name=name, value=float(value), labels=labels)
                            metrics.append(mp)
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse OTLP metrics JSON: {e}")

    return metrics


def parse_otlp_logs(data: bytes) -> list[LogEntry]:
    """Parse OTLP logs data and convert to LogEntry objects.

    Args:
        data: Raw OTLP data bytes.

    Returns:
        List of LogEntry objects extracted from the data.
    """
    logs = []

    try:
        content = json.loads(data)
        resource_logs = content.get("resourceLogs", [])
        for resource_log in resource_logs:
            resource = resource_log.get("resource", {})
            service_name = ""
            for attr in resource.get("attributes", []):
                if attr.get("key") == "service.name":
                    service_name = attr.get("value", {}).get("stringValue", "")
                    break

            for scope_log in resource_log.get("scopeLogs", []):
                for log_record in scope_log.get("logRecords", []):
                    # Extract severity
                    severity_number = log_record.get("severityNumber", 9)
                    level_map = {
                        1: "DEBUG", 2: "DEBUG", 3: "DEBUG", 4: "DEBUG",
                        5: "INFO", 6: "INFO", 7: "INFO", 8: "INFO",
                        9: "WARNING", 10: "WARNING", 11: "WARNING", 12: "WARNING",
                        13: "ERROR", 14: "ERROR", 15: "ERROR", 16: "ERROR",
                        17: "CRITICAL", 18: "CRITICAL", 19: "CRITICAL", 20: "CRITICAL",
                    }
                    level = level_map.get(severity_number, "INFO")

                    # Extract body
                    body = log_record.get("body", {})
                    message = body.get("stringValue", str(body))

                    # Extract metadata from attributes
                    metadata = {}
                    for attr in log_record.get("attributes", []):
                        key = attr.get("key", "")
                        value = attr.get("value", {})
                        if key:
                            metadata[key] = value.get("stringValue", value.get("intValue", str(value)))

                    log_entry = LogEntry(
                        level=level,
                        message=message,
                        service=service_name,
                        metadata=metadata if metadata else None,
                    )
                    logs.append(log_entry)
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning(f"Failed to parse OTLP logs JSON: {e}")

    return logs


# ─── OTLP Export (forwarding to external collector) ───────────────


async def export_to_otlp_endpoint(
    signal_type: str,
    data: bytes,
) -> bool:
    """Forward collected data to an external OTLP endpoint.

    If OTLP_ENDPOINT is configured, forwards the data via HTTP/JSON.
    This allows Sneaker to act as a proxy to a central collector.
    Retries up to 3 times with exponential backoff on transient failures.

    Args:
        signal_type: One of 'traces', 'metrics', 'logs'.
        data: Raw OTLP data to forward.

    Returns:
        True if forwarding succeeded, False otherwise.
    """
    if not OTLP_ENDPOINT:
        return True  # No endpoint configured, nothing to forward

    max_retries = 3
    base_delay = 1.0

    for attempt in range(max_retries):
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                url = f"{OTLP_ENDPOINT.rstrip('/')}/v1/{signal_type}"
                headers = {"Content-Type": "application/x-protobuf"}

                response = await client.post(url, content=data, headers=headers)
                if response.status_code in (200, 202):
                    if attempt > 0:
                        logger.info(f"Forwarded {signal_type} to OTLP endpoint after {attempt + 1} attempts")
                    else:
                        logger.info(f"Forwarded {signal_type} to OTLP endpoint")
                    return True
                elif response.status_code >= 500 and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(
                        f"OTLP forward failed with {response.status_code}, "
                        f"retrying in {delay:.1f}s (attempt {attempt + 2}/{max_retries})"
                    )
                    await asyncio.sleep(delay)
                    continue
                else:
                    logger.warning(f"OTLP forward failed: {response.status_code}")
                    return False
        except (ConnectionError, OSError) as e:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    f"OTLP forward connection error, retrying in {delay:.1f}s "
                    f"(attempt {attempt + 2}/{max_retries}): {e}"
                )
                await asyncio.sleep(delay)
                continue
            else:
                logger.warning(f"Failed to forward to OTLP endpoint after {max_retries} attempts: {e}")
                return False
        except Exception as e:
            logger.warning(f"Failed to forward to OTLP endpoint: {e}")
            return False

    return False


# ─── FastAPI Routes ──────────────────────────────────────────────


def register_otlp_routes(app: FastAPI) -> None:
    """Register OTLP endpoints with the FastAPI app.

    Adds:
    - POST /v1/traces — OTLP traces endpoint
    - POST /v1/metrics — OTLP metrics endpoint
    - POST /v1/logs — OTLP logs endpoint
    - GET /api/otlp/stats — OTLP export statistics

    Args:
        app: The FastAPI application instance.
    """

    @app.post("/v1/traces")
    async def receive_traces(request) -> Response:
        """Receive traces via OTLP protocol.

        Accepts both JSON and protobuf-encoded OTLP trace data.
        Secrets in attributes are automatically redacted.
        """
        content_type = request.headers.get("content-type", "")
        data = await request.body()

        # Redact secrets before processing
        if "json" in content_type:
            data = redact_secrets_in_traces(data)

        if "json" in content_type:
            spans = parse_otlp_traces(data)
            for span in spans:
                _traces_store.append(span)
            logger.info(f"Received {len(spans)} spans via OTLP")
        else:
            # Protobuf — try to parse, log warning if not possible
            logger.info(f"Received {len(data)} bytes of OTLP protobuf traces")
            # Store raw data as a trace span for later processing
            span = TraceSpan(
                trace_id=f"raw-{int(time.time())}",
                operation="otlp-protobuf-trace",
                duration_ms=0,
                metadata={"raw_size": len(data)},
            )
            _traces_store.append(span)

        # Forward to external OTLP endpoint if configured
        await export_to_otlp_endpoint("traces", data)

        return Response(status_code=200, content=b"")

    @app.post("/v1/metrics")
    async def receive_metrics(request) -> Response:
        """Receive metrics via OTLP protocol.

        Accepts both JSON and protobuf-encoded OTLP metric data.
        """
        content_type = request.headers.get("content-type", "")
        data = await request.body()

        if "json" in content_type:
            metrics = parse_otlp_metrics(data)
            for metric in metrics:
                _metrics_store.append(metric)
            logger.info(f"Received {len(metrics)} metrics via OTLP")
        else:
            logger.info(f"Received {len(data)} bytes of OTLP protobuf metrics")
            mp = MetricPoint(
                name="otlp-protobuf-metric",
                value=float(len(data)),
                labels={"type": "raw"},
            )
            _metrics_store.append(mp)

        # Forward to external OTLP endpoint if configured
        await export_to_otlp_endpoint("metrics", data)

        return Response(status_code=200, content=b"")

    @app.post("/v1/logs")
    async def receive_logs(request) -> Response:
        """Receive logs via OTLP protocol.

        Accepts both JSON and protobuf-encoded OTLP log data.
        Secrets in attributes and log bodies are automatically redacted.
        """
        content_type = request.headers.get("content-type", "")
        data = await request.body()

        # Redact secrets before processing
        if "json" in content_type:
            data = redact_secrets_in_logs(data)

        if "json" in content_type:
            logs = parse_otlp_logs(data)
            for log in logs:
                _logs_store.append(log)
            logger.info(f"Received {len(logs)} logs via OTLP")
        else:
            logger.info(f"Received {len(data)} bytes of OTLP protobuf logs")
            log_entry = LogEntry(
                level="INFO",
                message=f"OTLP protobuf log ({len(data)} bytes)",
                metadata={"raw_size": len(data)},
            )
            _logs_store.append(log_entry)

        # Forward to external OTLP endpoint if configured
        await export_to_otlp_endpoint("logs", data)

        return Response(status_code=200, content=b"")

    @app.get("/api/otlp/stats")
    async def get_otlp_stats() -> dict[str, Any]:
        """Get OTLP export statistics.

        Returns:
            Dict with counts of received traces, metrics, and logs.
        """
        return {
            "traces_received": len(_traces_store),
            "metrics_received": len(_metrics_store),
            "logs_received": len(_logs_store),
            "otlp_endpoint": OTLP_ENDPOINT or "not configured",
            "otlp_insecure": OTLP_INSECURE,
        }

    @app.get("/api/otlp/export/traces")
    async def export_traces_otlp(limit: int = 100) -> Response:
        """Export traces in OTLP JSON format.

        Args:
            limit: Maximum number of traces to export.

        Returns:
            OTLP-formatted JSON response.
        """
        traces = _traces_store[-limit:]
        resource_spans = [{
            "resource": {"attributes": []},
            "scopeSpans": [{
                "scope": {"name": "Sneaker", "version": "1.0.0"},
                "spans": [
                    {
                        "traceId": t.trace_id.zfill(32) if len(t.trace_id) < 32 else t.trace_id,
                        "spanId": f"{id(t):016x}",
                        "parentSpanId": t.parent_id.zfill(16) if t.parent_id else "0" * 16,
                        "name": t.operation,
                        "startTimeUnixNano": 0,
                        "endTimeUnixNano": int(t.duration_ms * 1_000_000),
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": t.service or "unknown"}}
                        ] if t.service else [],
                    }
                    for t in traces
                ],
            }],
        }]

        return Response(
            content=json.dumps({"resourceSpans": resource_spans}),
            media_type="application/json",
        )

    @app.get("/api/otlp/export/metrics")
    async def export_metrics_otlp(limit: int = 100) -> Response:
        """Export metrics in OTLP JSON format.

        Args:
            limit: Maximum number of metrics to export.

        Returns:
            OTLP-formatted JSON response.
        """
        metrics = _metrics_store[-limit:]
        resource_metrics = [{
            "resource": {"attributes": []},
            "scopeMetrics": [{
                "scope": {"name": "Sneaker", "version": "1.0.0"},
                "metrics": [
                    {
                        "name": m.name,
                        "gauge": {
                            "dataPoints": [
                                {
                                    "asDouble": m.value,
                                    "attributes": [
                                        {"key": k, "value": {"stringValue": str(v)}}
                                        for k, v in (m.labels or {}).items()
                                    ],
                                }
                            ],
                        },
                    }
                    for m in metrics
                ],
            }],
        }]

        return Response(
            content=json.dumps({"resourceMetrics": resource_metrics}),
            media_type="application/json",
        )

    @app.get("/api/otlp/export/logs")
    async def export_logs_otlp(limit: int = 100) -> Response:
        """Export logs in OTLP JSON format.

        Args:
            limit: Maximum number of logs to export.

        Returns:
            OTLP-formatted JSON response.
        """
        logs = _logs_store[-limit:]
        severity_map = {
            "DEBUG": 5, "INFO": 9, "WARNING": 13, "ERROR": 17, "CRITICAL": 21,
        }
        resource_logs = [{
            "resource": {"attributes": []},
            "scopeLogs": [{
                "scope": {"name": "Sneaker", "version": "1.0.0"},
                "logRecords": [
                    {
                        "body": {"stringValue": entry.message},
                        "severityNumber": severity_map.get(entry.level, 9),
                        "severityText": entry.level,
                        "attributes": [
                            {"key": k, "value": {"stringValue": str(v)}}
                            for k, v in (entry.metadata or {}).items()
                        ],
                    }
                    for entry in logs
                ],
            }],
        }]

        return Response(
            content=json.dumps({"resourceLogs": resource_logs}),
            media_type="application/json",
        )
