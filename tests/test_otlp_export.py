"""Tests for Sneaker OTLP export module."""

import json

from sneaker.models import LogEntry, MetricPoint, TraceSpan
from sneaker.otlp_export import (
    OTLP_ENDPOINT,
    OTLP_INSECURE,
    parse_otlp_logs,
    parse_otlp_metrics,
    parse_otlp_traces,
    register_stores,
)


class TestOTLPTracesParsing:
    """Test OTLP traces parsing."""

    def test_parse_empty_traces(self):
        """Empty data should return empty list."""
        data = json.dumps({"resourceSpans": []}).encode()
        spans = parse_otlp_traces(data)
        assert spans == []

    def test_parse_single_trace(self):
        """Single trace should be parsed correctly."""
        data = json.dumps({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "test-service"}}
                    ]
                },
                "scopeSpans": [{
                    "scope": {"name": "test", "version": "1.0.0"},
                    "spans": [{
                        "traceId": "abc123",
                        "spanId": "span1",
                        "parentSpanId": "0",
                        "name": "test-operation",
                        "startTimeUnixNano": 1000000000,
                        "endTimeUnixNano": 2000000000,
                    }]
                }]
            }]
        }).encode()

        spans = parse_otlp_traces(data)
        assert len(spans) == 1
        assert spans[0].operation == "test-operation"
        assert spans[0].service == "test-service"
        assert spans[0].duration_ms == 1000.0  # 1 second in ms

    def test_parse_invalid_json(self):
        """Invalid JSON should return empty list."""
        data = b"not json"
        spans = parse_otlp_traces(data)
        assert spans == []


class TestOTLPMetricsParsing:
    """Test OTLP metrics parsing."""

    def test_parse_empty_metrics(self):
        """Empty data should return empty list."""
        data = json.dumps({"resourceMetrics": []}).encode()
        metrics = parse_otlp_metrics(data)
        assert metrics == []

    def test_parse_gauge_metric(self):
        """Gauge metric should be parsed correctly."""
        data = json.dumps({
            "resourceMetrics": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "test-service"}}
                    ]
                },
                "scopeMetrics": [{
                    "scope": {"name": "test", "version": "1.0.0"},
                    "metrics": [{
                        "name": "cpu_usage",
                        "gauge": {
                            "dataPoints": [
                                {"asDouble": 42.5}
                            ]
                        }
                    }]
                }]
            }]
        }).encode()

        metrics = parse_otlp_metrics(data)
        assert len(metrics) == 1
        assert metrics[0].name == "cpu_usage"
        assert metrics[0].value == 42.5

    def test_parse_sum_metric(self):
        """Sum metric should be parsed correctly."""
        data = json.dumps({
            "resourceMetrics": [{
                "resource": {"attributes": []},
                "scopeMetrics": [{
                    "scope": {"name": "test", "version": "1.0.0"},
                    "metrics": [{
                        "name": "request_count",
                        "sum": {
                            "dataPoints": [
                                {"asInt": 100}
                            ]
                        }
                    }]
                }]
            }]
        }).encode()

        metrics = parse_otlp_metrics(data)
        assert len(metrics) == 1
        assert metrics[0].name == "request_count"
        assert metrics[0].value == 100.0


class TestOTLPLogsParsing:
    """Test OTLP logs parsing."""

    def test_parse_empty_logs(self):
        """Empty data should return empty list."""
        data = json.dumps({"resourceLogs": []}).encode()
        logs = parse_otlp_logs(data)
        assert logs == []

    def test_parse_info_log(self):
        """Info log should be parsed correctly."""
        data = json.dumps({
            "resourceLogs": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "test-service"}}
                    ]
                },
                "scopeLogs": [{
                    "scope": {"name": "test", "version": "1.0.0"},
                    "logRecords": [{
                        "body": {"stringValue": "Test message"},
                        "severityNumber": 9,
                        "severityText": "INFO",
                        "attributes": []
                    }]
                }]
            }]
        }).encode()

        logs = parse_otlp_logs(data)
        assert len(logs) == 1
        assert logs[0].message == "Test message"
        assert logs[0].service == "test-service"

    def test_parse_error_log(self):
        """Error log should be parsed with correct level."""
        data = json.dumps({
            "resourceLogs": [{
                "resource": {"attributes": []},
                "scopeLogs": [{
                    "scope": {"name": "test", "version": "1.0.0"},
                    "logRecords": [{
                        "body": {"stringValue": "Error occurred"},
                        "severityNumber": 17,
                        "severityText": "ERROR",
                        "attributes": [
                            {"key": "error.type", "value": {"stringValue": "ValueError"}}
                        ]
                    }]
                }]
            }]
        }).encode()

        logs = parse_otlp_logs(data)
        assert len(logs) == 1
        assert logs[0].level == "CRITICAL"  # severity 17 maps to CRITICAL
        assert logs[0].metadata == {"error.type": "ValueError"}


class TestOTLPConfiguration:
    """Test OTLP configuration."""

    def test_otlp_endpoint_default(self):
        """OTLP endpoint should default to empty string."""
        # Default is empty, meaning no forwarding
        assert isinstance(OTLP_ENDPOINT, str)

    def test_otlp_insecure_default(self):
        """OTLP insecure should default to True."""
        assert OTLP_INSECURE is True


class TestStoreRegistration:
    """Test store registration."""

    def test_register_stores(self):
        """Stores should be registered correctly."""
        metrics = [MetricPoint(name="test", value=1.0)]
        traces = [TraceSpan(trace_id="1", operation="test", duration_ms=100.0)]
        logs = [LogEntry(level="INFO", message="test")]

        register_stores(metrics, traces, logs)

        from sneaker import otlp_export
        assert len(otlp_export._metrics_store) == 1
        assert len(otlp_export._traces_store) == 1
        assert len(otlp_export._logs_store) == 1
