"""Data models for Creeper observability service."""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID, uuid4


class MetricPoint:
    def __init__(
        self,
        name: str,
        value: float,
        labels: Optional[dict[str, str]] = None,
        timestamp: Optional[datetime] = None,
        id: Optional[UUID] = None,
    ):
        self.id = id or uuid4()
        self.name = name
        self.value = value
        self.labels = labels or {}
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "name": self.name,
            "value": self.value,
            "labels": self.labels,
            "timestamp": self.timestamp.isoformat(),
        }


class TraceSpan:
    def __init__(
        self,
        trace_id: str,
        operation: str,
        duration_ms: float,
        service: Optional[str] = None,
        parent_id: Optional[str] = None,
        span_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
    ):
        self.span_id = span_id or str(uuid4())
        self.trace_id = trace_id
        self.operation = operation
        self.duration_ms = duration_ms
        self.service = service
        self.parent_id = parent_id
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "span_id": self.span_id,
            "trace_id": self.trace_id,
            "operation": self.operation,
            "duration_ms": self.duration_ms,
            "service": self.service,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp.isoformat(),
        }


class LogEntry:
    def __init__(
        self,
        level: str,
        message: str,
        service: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        id: Optional[UUID] = None,
    ):
        self.id = id or uuid4()
        self.level = level.upper()
        self.message = message
        self.service = service
        self.metadata = metadata or {}
        self.timestamp = timestamp or datetime.utcnow()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "level": self.level,
            "message": self.message,
            "service": self.service,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }
