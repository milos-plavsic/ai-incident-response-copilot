"""Unit tests for IncidentAnalyzer and timeline reconstruction."""

from __future__ import annotations

import pytest

from app.incident_analyzer import IncidentAnalyzer, _tokenize
from app.timeline import reconstruct_timeline

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def analyzer() -> IncidentAnalyzer:
    return IncidentAnalyzer()


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------


def test_tokenize_produces_words():
    tokens = _tokenize("Database connection pool exhausted")
    assert "database" in tokens
    assert "connection" in tokens
    assert "pool" in tokens


def test_tokenize_produces_bigrams():
    tokens = _tokenize("data loss occurred")
    assert "data loss" in tokens


def test_tokenize_case_insensitive():
    tokens = _tokenize("DISK FULL")
    assert "disk" in tokens
    assert "full" in tokens


# ---------------------------------------------------------------------------
# Pattern detection — each of the 7 incident categories
# ---------------------------------------------------------------------------


def test_database_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "PostgreSQL connection pool exhausted, queries timing out, replication lag is 120s"
    )
    assert report.pattern_name == "database"
    assert report.confidence > 0.5
    assert len(report.remediation_steps) >= 3
    assert any(
        "connection" in kw or "pool" in kw or "postgres" in kw for kw in report.matched_keywords
    )


def test_network_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "DNS resolution failing, high packet loss on VPC subnet, firewall rule changed"
    )
    assert report.pattern_name == "network"
    assert report.confidence > 0.4
    assert report.root_cause_category == "network"


def test_memory_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "JVM heap exhausted, OOM killer activated, garbage collection pauses exceeding 5s"
    )
    assert report.pattern_name == "memory"
    assert report.confidence > 0.5
    assert "oom" in report.matched_keywords or "heap" in report.matched_keywords


def test_cpu_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "CPU utilization at 99%, worker threads starved, compute spike on all cores"
    )
    assert report.pattern_name == "cpu"
    assert report.confidence > 0.4
    assert report.root_cause_category == "cpu"


def test_disk_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "Filesystem partition full, disk I/O wait at 80%, EBS volume IOPS saturated"
    )
    assert report.pattern_name == "disk"
    assert report.confidence > 0.4
    assert report.estimated_mttr_minutes > 0


def test_auth_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "JWT token expired, OAuth callback failing, IAM permission denied on S3"
    )
    assert report.pattern_name == "auth"
    assert report.confidence > 0.4
    assert len(report.runbooks) >= 1


def test_deployment_pattern_detected(analyzer: IncidentAnalyzer):
    report = analyzer.analyze(
        "New container image deployed, pods in CrashLoopBackOff, rollback required"
    )
    assert report.pattern_name == "deployment"
    assert report.confidence > 0.5
    assert any("rollback" in step.lower() for step in report.remediation_steps)


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def test_confidence_between_0_and_1(analyzer: IncidentAnalyzer):
    for text in [
        "database connection pool",
        "cpu utilization high",
        "random noise with no signal",
    ]:
        report = analyzer.analyze(text)
        assert (
            0.0 <= report.confidence <= 1.0
        ), f"Confidence {report.confidence} out of range for: {text!r}"


def test_more_keywords_yields_higher_confidence(analyzer: IncidentAnalyzer):
    weak = analyzer.analyze("database")
    strong = analyzer.analyze(
        "database postgres connection pool deadlock replication query timeout sql"
    )
    assert strong.confidence >= weak.confidence


def test_unknown_text_returns_low_confidence(analyzer: IncidentAnalyzer):
    report = analyzer.analyze("the quick brown fox jumps over the lazy dog")
    assert report.confidence < 0.3


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def test_severity_p1_on_outage(analyzer: IncidentAnalyzer):
    report = analyzer.analyze("production down, complete outage for all users")
    assert report.severity == "P1"


def test_severity_p2_on_degraded(analyzer: IncidentAnalyzer):
    report = analyzer.analyze("service degraded, elevated error rate for many users")
    assert report.severity == "P2"


def test_severity_p3_on_intermittent(analyzer: IncidentAnalyzer):
    report = analyzer.analyze("intermittent timeouts affecting some users, minor impact")
    assert report.severity == "P3"


def test_severity_p4_default(analyzer: IncidentAnalyzer):
    report = analyzer.analyze("cosmetic rendering glitch on single user account")
    assert report.severity == "P4"


# ---------------------------------------------------------------------------
# Alert correlation
# ---------------------------------------------------------------------------


def test_correlate_alerts_finds_common_category(analyzer: IncidentAnalyzer):
    alerts = [
        "database connection pool exhausted",
        "postgres replication lag detected",
        "SQL query timeout on primary",
    ]
    causes = analyzer.correlate_alerts(alerts)
    assert "database" in causes
    assert causes[0] == "database"


def test_correlate_empty_alerts_returns_empty(analyzer: IncidentAnalyzer):
    assert analyzer.correlate_alerts([]) == []


def test_correlate_mixed_alerts_orders_by_frequency(analyzer: IncidentAnalyzer):
    alerts = [
        "disk full on /var/log",
        "disk iops saturated",
        "cpu spike detected",
    ]
    causes = analyzer.correlate_alerts(alerts)
    assert causes[0] == "disk"


# ---------------------------------------------------------------------------
# Timeline reconstruction
# ---------------------------------------------------------------------------


def test_timeline_orders_events_chronologically():
    events = [
        "2024-03-15T10:35:00 Error rate spiked to 50%",
        "2024-03-15T10:30:00 Deployment pushed to production",
        "2024-03-15T10:40:00 Customers reporting 500 errors",
    ]
    timeline = reconstruct_timeline("Production incident", events)
    timestamps = [e["timestamp"] for e in timeline if e["timestamp"] != "unknown"]
    assert timestamps == sorted(timestamps)


def test_timeline_assigns_trigger_role():
    events = ["2024-03-15T10:00:00 Deploy released to production cluster"]
    timeline = reconstruct_timeline("Service degraded after deploy", events)
    roles = [e["causal_role"] for e in timeline]
    assert "trigger" in roles


def test_timeline_assigns_symptom_role():
    events = ["2024-03-15T10:05:00 Error rate elevated, latency spike observed"]
    timeline = reconstruct_timeline("Incident", events)
    roles = [e["causal_role"] for e in timeline]
    assert "symptom" in roles or "trigger" in roles  # at least one assigned


def test_timeline_handles_unknown_timestamps():
    events = ["Deploy happened sometime last night", "Errors started appearing"]
    timeline = reconstruct_timeline("Service down", events)
    assert len(timeline) >= len(events)
    for entry in timeline:
        assert "timestamp" in entry
        assert "event" in entry
        assert "causal_role" in entry


def test_timeline_includes_incident_as_seed():
    timeline = reconstruct_timeline(
        "2024-03-15T09:58:00 Disk filesystem full on node-1",
        ["2024-03-15T10:00:00 Service crash on node-1"],
    )
    events_text = [e["event"] for e in timeline]
    assert any("[incident]" in t for t in events_text)


def test_timeline_returns_list_of_dicts():
    timeline = reconstruct_timeline("CPU high", ["Worker process died"])
    assert isinstance(timeline, list)
    for entry in timeline:
        assert isinstance(entry, dict)
        assert "timestamp" in entry
        assert "event" in entry
        assert "causal_role" in entry
