"""FastAPI application for Sneaker observability service."""

import hmac
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException

from sneaker import otlp_export
from sneaker.models import LogEntry, MetricPoint, TraceSpan

app = FastAPI(
    title="Sneaker",
    description="Observability service for the Evershade ecosystem",
    version="1.0.0",
)

API_KEY = os.getenv("API_KEY", "Sneaker-dev-key-change-me")

# In-memory storage
_metrics: list[MetricPoint] = []
_traces: list[TraceSpan] = []
_logs: list[LogEntry] = []

# Register stores with OTLP export module
otlp_export.register_stores(_metrics, _traces, _logs)

# Register OTLP routes
otlp_export.register_otlp_routes(app)


def verify_bearer(authorization: str | None = Header(None)) -> None:
    """Verify Bearer token in Authorization header."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
    else:
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header. Use: Authorization: Bearer <key>")
    if not hmac.compare_digest(token, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "Sneaker"}


@app.get("/api/capabilities")
async def capabilities() -> dict:
    """Report the capabilities supported by this Sneaker instance."""
    return {
        "service": "Sneaker",
        "version": "1.1.0",
        "features": {
            "structured_logging": {
                "supported": True,
                "description": "JSON structured log aggregation",
            },
            "otlp_traces": {
                "supported": True,
                "description": "OpenTelemetry trace ingestion and export",
            },
            "otlp_metrics": {
                "supported": True,
                "description": "OpenTelemetry metric ingestion and export",
            },
            "otlp_logs": {
                "supported": True,
                "description": "OpenTelemetry log ingestion and export",
            },
            "alerting": {
                "supported": True,
                "description": "Configurable alerting rules and notifications",
            },
            "dashboards": {
                "supported": True,
                "description": "Observability dashboards",
            },
            "external_otlp_forwarding": {
                "supported": True,
                "description": "Forward telemetry to external OTLP collectors",
            },
            "persistent_storage": {
                "supported": True,
                "description": "SQLite persistent telemetry storage",
            },
        },
        "api_versions": ["v1"],
    }


# ─── Metrics ────────────────────────────────────────────────────

@app.post("/api/metrics")
async def record_metric(data: dict[str, Any], authorization: str | None = Header(None)) -> dict[str, Any]:
    verify_bearer(authorization)
    metric = MetricPoint(name=data["name"], value=float(data["value"]), labels=data.get("labels"))
    _metrics.append(metric)
    return metric.to_dict()


@app.get("/api/metrics")
async def query_metrics(
    name: str | None = None,
    limit: int = 100,
    authorization: str | None = Header(None),
) -> list[dict[str, Any]]:
    verify_bearer(authorization)
    results = _metrics
    if name:
        results = [m for m in results if m.name == name]
    return [m.to_dict() for m in results[-limit:]]


@app.get("/api/metrics/summary")
async def metrics_summary(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Return a summary of key metrics including latency percentiles and error counts.

    This endpoint provides aggregated metrics for dashboards and monitoring:
    - Request latency percentiles (p50, p95, p99) from trace durations
    - Error counts by service from logs
    - Queue depth (pending traces, metrics, logs)
    - Task duration statistics
    """
    verify_bearer(authorization)

    # Calculate latency percentiles from traces
    durations = [t.duration_ms for t in _traces if t.duration_ms > 0]
    durations.sort()
    n = len(durations)

    def percentile(data, p):
        if not data:
            return 0.0
        k = (len(data) - 1) * (p / 100.0)
        f = int(k)
        c = f + 1 if f + 1 < len(data) else f
        d = k - f
        return data[f] + d * (data[c] - data[f])

    # Count errors by service from logs
    errors_by_service = {}
    for entry in _logs:
        if entry.level in ("ERROR", "CRITICAL"):
            svc = entry.service or "unknown"
            errors_by_service[svc] = errors_by_service.get(svc, 0) + 1

    # Queue depths
    queue_depth = {
        "pending_traces": len(_traces),
        "pending_metrics": len(_metrics),
        "pending_logs": len(_logs),
    }

    return {
        "latency": {
            "p50_ms": round(percentile(durations, 50), 2),
            "p95_ms": round(percentile(durations, 95), 2),
            "p99_ms": round(percentile(durations, 99), 2),
            "min_ms": round(durations[0], 2) if durations else 0,
            "max_ms": round(durations[-1], 2) if durations else 0,
            "count": n,
        },
        "errors": {
            "total": sum(errors_by_service.values()),
            "by_service": errors_by_service,
        },
        "queue_depth": queue_depth,
        "task_duration": {
            "avg_ms": round(sum(durations) / n, 2) if n > 0 else 0,
            "total_traces": len(_traces),
        },
    }


# ─── Traces ─────────────────────────────────────────────────────

@app.post("/api/traces")
async def record_trace(data: dict[str, Any], authorization: str | None = Header(None)) -> dict[str, Any]:
    verify_bearer(authorization)
    span = TraceSpan(
        trace_id=data["trace_id"],
        operation=data["operation"],
        duration_ms=float(data.get("duration_ms", 0)),
        service=data.get("service"),
        parent_id=data.get("parent_id"),
    )
    _traces.append(span)
    return span.to_dict()


@app.get("/api/traces")
async def query_traces(
    trace_id: str | None = None,
    service: str | None = None,
    limit: int = 100,
    authorization: str | None = Header(None),
) -> list[dict[str, Any]]:
    verify_bearer(authorization)
    results = _traces
    if trace_id:
        results = [t for t in results if t.trace_id == trace_id]
    if service:
        results = [t for t in results if t.service == service]
    return [t.to_dict() for t in results[-limit:]]


# ─── Logs ───────────────────────────────────────────────────────

@app.post("/api/logs")
async def record_log(data: dict[str, Any], authorization: str | None = Header(None)) -> dict[str, Any]:
    verify_bearer(authorization)
    entry = LogEntry(
        level=data["level"],
        message=data["message"],
        service=data.get("service"),
        metadata=data.get("metadata"),
    )
    _logs.append(entry)
    return entry.to_dict()


@app.get("/api/logs")
async def query_logs(
    service: str | None = None,
    level: str | None = None,
    limit: int = 100,
    authorization: str | None = Header(None),
) -> list[dict[str, Any]]:
    verify_bearer(authorization)
    results = _logs
    if service:
        results = [entry for entry in results if entry.service == service]
    if level:
        results = [entry for entry in results if entry.level == level.upper()]
    return [entry.to_dict() for entry in results[-limit:]]
