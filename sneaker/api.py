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
