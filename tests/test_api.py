"""Tests for Sneaker observability service."""

import os
import pytest
from fastapi.testclient import TestClient

# Set API_KEY BEFORE importing the app module
os.environ["API_KEY"] = "test-key"

from sneaker.api import app


client = TestClient(app)
HEADERS = {"Authorization": "Bearer test-key"}


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
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "requests_total"
        assert data["value"] == 42.0

    def test_query_metrics(self):
        client.post("/api/metrics", json={"name": "cpu", "value": 1.5}, headers=HEADERS)
        response = client.get("/api/metrics", headers=HEADERS, params={"name": "cpu"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestTraces:
    def test_record_trace(self):
        response = client.post(
            "/api/traces",
            json={"trace_id": "t1", "operation": "GET /api", "duration_ms": 120.5, "service": "Greenie"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["trace_id"] == "t1"

    def test_query_traces(self):
        client.post(
            "/api/traces",
            json={"trace_id": "t2", "operation": "POST /api", "duration_ms": 50},
            headers=HEADERS,
        )
        response = client.get("/api/traces", headers=HEADERS, params={"trace_id": "t2"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestLogs:
    def test_record_log(self):
        response = client.post(
            "/api/logs",
            json={"level": "info", "message": "Server started", "service": "Gobber"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["level"] == "INFO"

    def test_query_logs(self):
        client.post(
            "/api/logs",
            json={"level": "error", "message": "DB connection failed", "service": "Gobber"},
            headers=HEADERS,
        )
        response = client.get("/api/logs", headers=HEADERS, params={"level": "error"})
        assert response.status_code == 200
        assert len(response.json()) == 1


class TestAuth:
    def test_invalid_key(self):
        response = client.get("/api/metrics", headers={"Authorization": "Bearer wrong"})
        assert response.status_code == 401

    def test_missing_auth(self):
        response = client.get("/api/metrics")
        assert response.status_code == 401

    def test_query_param_rejected(self):
        response = client.get("/api/metrics", params={"x_key": "test-key"})
        assert response.status_code == 401
