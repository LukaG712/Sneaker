"""Tests for Sneaker observability service."""

import os
import pytest
from fastapi.testclient import TestClient

from sneaker.api import app, _metrics, _traces, _logs


@pytest.fixture(autouse=True)
def clear_data():
    _metrics.clear()
    _traces.clear()
    _logs.clear()
    os.environ["API_KEY"] = "test-key"
    yield


client = TestClient(app)


class TestHealth:
    def test_health(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "Sneaker"


class TestMetrics:
    def test_record_metric(self):
        response = client.post(
            "/api/metrics",
            json={"name": "requests_total", "value": 42, "labels": {"method": "GET"}},
            params={"x_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "requests_total"
        assert data["value"] == 42.0

    def test_query_metrics(self):
        client.post("/api/metrics", json={"name": "cpu", "value": 1.5}, params={"x_key": "test-key"})
        response = client.get("/api/metrics", params={"x_key": "test-key", "name": "cpu"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestTraces:
    def test_record_trace(self):
        response = client.post(
            "/api/traces",
            json={"trace_id": "t1", "operation": "GET /api", "duration_ms": 120.5, "service": "Greenie"},
            params={"x_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["trace_id"] == "t1"

    def test_query_traces(self):
        client.post(
            "/api/traces",
            json={"trace_id": "t2", "operation": "POST /api", "duration_ms": 50},
            params={"x_key": "test-key"},
        )
        response = client.get("/api/traces", params={"x_key": "test-key", "trace_id": "t2"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestLogs:
    def test_record_log(self):
        response = client.post(
            "/api/logs",
            json={"level": "info", "message": "Server started", "service": "Gobber"},
            params={"x_key": "test-key"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["level"] == "INFO"

    def test_query_logs(self):
        client.post(
            "/api/logs",
            json={"level": "error", "message": "DB connection failed", "service": "Gobber"},
            params={"x_key": "test-key"},
        )
        response = client.get("/api/logs", params={"x_key": "test-key", "level": "error"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestAuth:
    def test_invalid_key(self):
        response = client.get("/api/metrics", params={"x_key": "wrong"})
        assert response.status_code == 401
