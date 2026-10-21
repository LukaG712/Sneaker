"""FastAPI application for Sneaker observability service."""

import os
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query

from sneaker.models import MetricPoint, TraceSpan, LogEntry


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


def verify_key(x_key: Optional[str] = Query(None)) -> None:
    if x_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "Sneaker"}


# ─── Metrics ────────────────────────────────────────────────────

@app.post("/api/metrics")
async def record_metric(data: dict[str, Any], x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
    metric = MetricPoint(name=data["name"], value=float(data["value"]), labels=data.get("labels"))
    _metrics.append(metric)
    return metric.to_dict()


@app.get("/api/metrics")
async def query_metrics(
    name: Optional[str] = None,
    limit: int = 100,
    x_key: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    verify_key(x_key)
    results = _metrics
    if name:
        results = [m for m in results if m.name == name]
    return [m.to_dict() for m in results[-limit:]]


# ─── Traces ─────────────────────────────────────────────────────

@app.post("/api/traces")
async def record_trace(data: dict[str, Any], x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
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
    trace_id: Optional[str] = None,
    service: Optional[str] = None,
    limit: int = 100,
    x_key: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    verify_key(x_key)
    results = _traces
    if trace_id:
        results = [t for t in results if t.trace_id == trace_id]
    if service:
        results = [t for t in results if t.service == service]
    return [t.to_dict() for t in results[-limit:]]


# ─── Logs ───────────────────────────────────────────────────────

@app.post("/api/logs")
async def record_log(data: dict[str, Any], x_key: Optional[str] = Query(None)) -> dict[str, Any]:
    verify_key(x_key)
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
    service: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 100,
    x_key: Optional[str] = Query(None),
) -> list[dict[str, Any]]:
    verify_key(x_key)
    results = _logs
    if service:
        results = [l for l in results if l.service == service]
    if level:
        results = [l for l in results if l.level == level.upper()]
    return [l.to_dict() for l in results[-limit:]]
