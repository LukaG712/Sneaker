"""Alerting system for Sneaker observability service.

Provides basic alert rules evaluated by Sneaker and delivered through Poltergeist:
- A required service is down or unready
- A workflow or scheduled run failed
- Disk usage on data volumes is above a threshold
- A budget or usage limit was reached
- Repeated authentication failures or other security events

Alerts have deduplication, cooldown, severity levels, and per-rule enable/disable.
If Poltergeist is absent, alerts still appear in the dashboard.
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_DIR = os.getenv("SNEAKER_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
ALERTS_DB_PATH = os.getenv("SNEAKER_ALERTS_DB_PATH", os.path.join(DATA_DIR, "alerts.db"))


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AlertRule:
    """Definition of an alert rule."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    enabled: bool = True
    cooldown_seconds: int = 300  # Minimum time between alerts for same rule
    threshold: float = 1.0
    condition: str = ""  # e.g., "service_down", "disk_usage_high", "auth_failures"
    channels: list[str] = field(default_factory=lambda: ["all"])


@dataclass
class Alert:
    """A fired alert."""
    id: str
    rule_id: str
    name: str
    severity: AlertSeverity
    message: str
    triggered_at: str
    count: int = 1
    dedup_key: str = ""
    acknowledged: bool = False


# Default alert rules
DEFAULT_RULES = [
    AlertRule(
        id="service_down",
        name="Service Down",
        description="A required service is down or unready",
        severity=AlertSeverity.CRITICAL,
        condition="service_down",
        cooldown_seconds=120,
    ),
    AlertRule(
        id="workflow_failed",
        name="Workflow Failed",
        description="A workflow or scheduled run failed",
        severity=AlertSeverity.WARNING,
        condition="workflow_failed",
        cooldown_seconds=60,
    ),
    AlertRule(
        id="disk_usage_high",
        name="Disk Usage High",
        description="Disk usage on data volumes is above threshold",
        severity=AlertSeverity.WARNING,
        condition="disk_usage_high",
        threshold=85.0,
        cooldown_seconds=600,
    ),
    AlertRule(
        id="auth_failures",
        name="Authentication Failures",
        description="Repeated authentication failures detected",
        severity=AlertSeverity.CRITICAL,
        condition="auth_failures",
        threshold=5.0,
        cooldown_seconds=300,
    ),
    AlertRule(
        id="budget_exceeded",
        name="Budget Exceeded",
        description="A budget or usage limit was reached",
        severity=AlertSeverity.WARNING,
        condition="budget_exceeded",
        cooldown_seconds=600,
    ),
]


def _get_connection():
    Path(ALERTS_DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_tables():
    conn = _get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS alert_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                cooldown_seconds INTEGER DEFAULT 300,
                threshold REAL DEFAULT 1.0,
                condition TEXT,
                channels TEXT DEFAULT '["all"]'
            );

            CREATE TABLE IF NOT EXISTS alert_fired (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT,
                triggered_at TEXT NOT NULL,
                count INTEGER DEFAULT 1,
                dedup_key TEXT,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alert_triggered ON alert_fired(triggered_at);
            CREATE INDEX IF NOT EXISTS idx_alert_rule ON alert_fired(rule_id);
            CREATE INDEX IF NOT EXISTS idx_alert_dedup ON alert_fired(dedup_key);
        """)
        conn.commit()

        # Seed default rules
        for rule in DEFAULT_RULES:
            conn.execute("""
                INSERT OR IGNORE INTO alert_rules
                (id, name, description, severity, enabled, cooldown_seconds, threshold, condition, channels)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.id, rule.name, rule.description, rule.severity.value,
                1 if rule.enabled else 0, rule.cooldown_seconds, rule.threshold,
                rule.condition, json.dumps(rule.channels),
            ))
        conn.commit()
    finally:
        conn.close()


_ensure_tables()


class AlertManager:
    """Manages alert rules, evaluation, deduplication, and delivery."""

    def __init__(self):
        self._last_fired: dict[str, float] = {}  # dedup_key -> timestamp

    def list_rules(self) -> list[dict]:
        conn = _get_connection()
        try:
            rows = conn.execute("SELECT * FROM alert_rules ORDER BY severity, name").fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_rule(self, rule_id: str) -> dict | None:
        conn = _get_connection()
        try:
            row = conn.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def update_rule(self, rule_id: str, **kwargs):
        if not kwargs:
            return
        # Whitelist allowed columns to prevent SQL injection
        allowed_columns = {"enabled", "cooldown_seconds", "threshold", "channels", "name", "severity", "condition"}
        sets = []
        values = []
        for key, value in kwargs.items():
            if key not in allowed_columns:
                continue
            if key in ("enabled",):
                sets.append(f"{key} = ?")
                values.append(1 if value else 0)
            elif key == "channels":
                sets.append("channels = ?")
                values.append(json.dumps(value) if isinstance(value, list) else value)
            else:
                sets.append(f"{key} = ?")
                values.append(value)
        if not sets:
            return
        values.append(rule_id)
        conn = _get_connection()
        try:
            conn.execute(f"UPDATE alert_rules SET {', '.join(sets)} WHERE id = ?", values)
            conn.commit()
        finally:
            conn.close()

    def evaluate(self, condition: str, value: float = 1.0, context: dict = None) -> Alert | None:
        """Evaluate alert rules against a condition and value.

        Returns a fired alert if any rule matches, None otherwise.
        """
        conn = _get_connection()
        try:
            rules = conn.execute(
                "SELECT * FROM alert_rules WHERE enabled = 1 AND condition = ?",
                (condition,),
            ).fetchall()
        finally:
            conn.close()

        for rule_row in rules:
            rule = dict(rule_row)
            threshold = rule.get("threshold", 1.0)
            if value < threshold:
                continue

            # Deduplication
            dedup_key = f"{rule['id']}:{condition}"
            if context:
                ctx_key = ":".join(f"{k}={v}" for k, v in sorted(context.items())[:3])
                dedup_key = f"{dedup_key}:{ctx_key}"

            dedup_hash = hashlib.md5(dedup_key.encode()).hexdigest()[:12]

            cooldown = rule.get("cooldown_seconds", 300)
            now = time.time()
            last_fired = self._last_fired.get(dedup_hash, 0)

            if now - last_fired < cooldown:
                # Increment count but don't fire new alert
                # Use a subquery to find the most recent entry since SQLite doesn't support
                # ORDER BY/LIMIT in UPDATE statements
                conn = _get_connection()
                try:
                    conn.execute("""
                        UPDATE alert_fired SET count = count + 1
                        WHERE id = (
                            SELECT id FROM alert_fired
                            WHERE rule_id = ? AND dedup_key = ?
                            ORDER BY triggered_at DESC LIMIT 1
                        )
                    """, (rule["id"], dedup_hash))
                    conn.commit()
                finally:
                    conn.close()
                continue

            # Fire the alert
            self._last_fired[dedup_hash] = now
            alert = Alert(
                id=str(uuid.uuid4()),
                rule_id=rule["id"],
                name=rule["name"],
                severity=AlertSeverity(rule["severity"]),
                message=f"{rule['name']}: {context or {}}",
                triggered_at=datetime.now(UTC).isoformat(),
                dedup_key=dedup_hash,
            )

            # Store in DB
            conn = _get_connection()
            try:
                conn.execute("""
                    INSERT INTO alert_fired (id, rule_id, name, severity, message, triggered_at, count, dedup_key)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (
                    alert.id, alert.rule_id, alert.name, alert.severity.value,
                    alert.message, alert.triggered_at, dedup_hash,
                ))
                conn.commit()
            finally:
                conn.close()

            # Deliver via Poltergeist
            self._deliver(alert)

            return alert

        return None

    def _deliver(self, alert: Alert):
        """Deliver alert via Poltergeist if available."""
        poltergeist_url = os.getenv("EVERSHADE_POLTERGEIST_URL", "http://Poltergeist:8088")
        poltergeist_key = os.getenv("EVERSHADE_POLTERGEIST_API_KEY", "")
        if not poltergeist_key:
            return

        try:
            import httpx
            with httpx.Client(timeout=5) as client:
                client.post(
                    f"{poltergeist_url}/api/notifications",
                    headers={"Authorization": f"Bearer {poltergeist_key}"},
                    json={
                        "title": f"Alert: {alert.name}",
                        "message": alert.message,
                        "severity": alert.severity.value,
                        "channels": ["all"],
                    },
                )
        except Exception as e:
            logger.warning(f"Failed to deliver alert via Poltergeist: {e}")

    def list_alerts(self, limit: int = 50, severity: str = None) -> list[dict]:
        # Validate severity to prevent SQL injection
        valid_severities = {s.value for s in AlertSeverity}
        if severity and severity not in valid_severities:
            severity = None

        conditions = []
        params = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        where = f"WHERE {' AND '.join(conditions)} " if conditions else ""

        conn = _get_connection()
        try:
            rows = conn.execute(
                f"SELECT * FROM alert_fired {where}ORDER BY triggered_at DESC LIMIT ?",
                params + [limit],
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def acknowledge(self, alert_id: str):
        conn = _get_connection()
        try:
            conn.execute(
                "UPDATE alert_fired SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            conn.commit()
        finally:
            conn.close()

    def stats(self) -> dict:
        conn = _get_connection()
        try:
            total = conn.execute("SELECT COUNT(*) as c FROM alert_fired").fetchone()["c"]
            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as c FROM alert_fired GROUP BY severity"
            ).fetchall():
                by_severity[row["severity"]] = row["c"]

            unacknowledged = conn.execute(
                "SELECT COUNT(*) as c FROM alert_fired WHERE acknowledged = 0"
            ).fetchone()["c"]

            return {
                "total_alerts": total,
                "unacknowledged": unacknowledged,
                "by_severity": by_severity,
            }
        finally:
            conn.close()


# Global singleton
alert_manager = AlertManager()
