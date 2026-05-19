"""API integration tests for the Incident Response Copilot."""

from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.api import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def test_health() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "healthy"
    assert "version" in body


# ---------------------------------------------------------------------------
# POST /v1/analyze — database incident
# ---------------------------------------------------------------------------


def test_analyze_database_incident() -> None:
    payload = {
        "incident": "PostgreSQL connection pool exhausted; queries timing out on primary",
        "alerts": [],
        "events": [],
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["pattern_name"] == "database"
    assert body["confidence"] > 0.4
    assert isinstance(body["remediation_steps"], list)
    assert len(body["remediation_steps"]) >= 3
    assert "request_id" in body
    assert "timestamp" in body


# ---------------------------------------------------------------------------
# POST /v1/analyze — network incident
# ---------------------------------------------------------------------------


def test_analyze_network_incident() -> None:
    payload = {
        "incident": "High packet loss on VPC, DNS resolution failing, firewall rule changed",
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["pattern_name"] == "network"
    assert body["root_cause_category"] == "network"
    assert isinstance(body["runbooks"], list)
    assert len(body["runbooks"]) >= 1


# ---------------------------------------------------------------------------
# POST /v1/analyze — deployment incident
# ---------------------------------------------------------------------------


def test_analyze_deployment_incident() -> None:
    payload = {
        "incident": "Pods entering CrashLoopBackOff after new container image deployed, rollback needed",
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["pattern_name"] == "deployment"
    assert any("rollback" in step.lower() for step in body["remediation_steps"])


# ---------------------------------------------------------------------------
# POST /v1/analyze — with alerts (correlation)
# ---------------------------------------------------------------------------


def test_analyze_with_alert_correlation() -> None:
    payload = {
        "incident": "Service degraded",
        "alerts": [
            "database connection pool exhausted",
            "postgres slow query detected",
            "db replication lag high",
        ],
        "events": [],
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["correlated_root_causes"], list)
    assert "database" in body["correlated_root_causes"]


# ---------------------------------------------------------------------------
# POST /v1/analyze — with events (timeline)
# ---------------------------------------------------------------------------


def test_analyze_with_events_timeline() -> None:
    payload = {
        "incident": "Production outage",
        "alerts": [],
        "events": [
            "2024-03-15T10:30:00 Deploy pushed to production",
            "2024-03-15T10:35:00 Error rate spiked to 50%",
            "2024-03-15T10:40:00 Customers reporting 500 errors",
        ],
    }
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["timeline"], list)
    assert len(body["timeline"]) >= 3
    for entry in body["timeline"]:
        assert "timestamp" in entry
        assert "event" in entry
        assert "causal_role" in entry


# ---------------------------------------------------------------------------
# POST /v1/analyze — severity mapping
# ---------------------------------------------------------------------------


def test_analyze_returns_severity() -> None:
    payload = {"incident": "production down, complete outage for all users"}
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    assert r.json()["severity"] == "P1"


def test_analyze_severity_p2_degraded() -> None:
    payload = {"incident": "service degraded, elevated error rate for many users"}
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    assert r.json()["severity"] == "P2"


# ---------------------------------------------------------------------------
# POST /v1/analyze — MTTR field
# ---------------------------------------------------------------------------


def test_analyze_returns_mttr() -> None:
    payload = {"incident": "disk filesystem partition full on production nodes"}
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "estimated_mttr_minutes" in body
    assert isinstance(body["estimated_mttr_minutes"], int)
    assert body["estimated_mttr_minutes"] > 0


# ---------------------------------------------------------------------------
# POST /v1/analyze — validation
# ---------------------------------------------------------------------------


def test_analyze_rejects_empty_incident() -> None:
    r = client.post("/v1/analyze", json={"incident": ""})
    assert r.status_code == 422


def test_analyze_rejects_missing_incident() -> None:
    r = client.post("/v1/analyze", json={})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# GET /v1/runbooks
# ---------------------------------------------------------------------------


def test_runbooks_endpoint() -> None:
    r = client.get("/v1/runbooks")
    assert r.status_code == 200
    body = r.json()
    assert "runbook_categories" in body
    assert isinstance(body["runbook_categories"], list)
    assert len(body["runbook_categories"]) >= 5
    assert "database/connection-pool" in body["runbook_categories"]


# ---------------------------------------------------------------------------
# Legacy endpoint backwards compatibility
# ---------------------------------------------------------------------------


def test_legacy_analyze_endpoint() -> None:
    payload = {"incident": "500 errors spiking on API gateway"}
    r = client.post("/v1/incidents/analyze", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert "top_hypothesis" in body
    assert "confidence" in body
    assert "remediation_steps" in body


# ---------------------------------------------------------------------------
# Auth (tested without API_KEY env var — should pass as no-op in dev)
# ---------------------------------------------------------------------------


def test_analyze_no_auth_key_dev_mode() -> None:
    """Without API_KEY set, auth middleware is a no-op and request succeeds."""
    # Ensure API_KEY is not set
    os.environ.pop("API_KEY", None)
    payload = {"incident": "memory heap exhausted, OOM killer triggered"}
    r = client.post("/v1/analyze", json=payload)
    assert r.status_code == 200
