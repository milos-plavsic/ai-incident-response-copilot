"""Incident analysis engine with pattern matching and hypothesis generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class IncidentReport:
    """Full analysis result returned by IncidentAnalyzer.analyze()."""

    pattern_name: str
    hypothesis: str
    confidence: float  # 0.0 - 1.0
    severity: str  # P1 / P2 / P3 / P4
    remediation_steps: list[str]
    runbooks: list[str]
    estimated_mttr_minutes: int
    matched_keywords: list[str]
    root_cause_category: str


@dataclass
class TimelineEvent:
    """A single reconstructed timeline entry."""

    timestamp: str
    event: str
    causal_role: str  # "trigger" | "symptom" | "impact" | "unknown"


# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------


@dataclass
class IncidentPattern:
    """Definition of a known incident type."""

    name: str
    keywords: list[str]
    hypothesis: str
    remediation_steps: list[str]
    runbooks: list[str]
    base_confidence: float
    estimated_mttr_minutes: int
    root_cause_category: str

    def score(self, tokens: list[str]) -> tuple[float, list[str]]:
        """Return (confidence, matched_keywords) for this pattern against ``tokens``."""
        matched = [kw for kw in self.keywords if kw in tokens]
        if not matched:
            return 0.0, []
        ratio = len(matched) / len(self.keywords)
        # Confidence grows with coverage but is bounded by base_confidence
        raw = self.base_confidence * (0.5 + 0.5 * ratio)
        confidence = min(1.0, round(raw, 4))
        return confidence, matched


_PATTERNS: list[IncidentPattern] = [
    IncidentPattern(
        name="database",
        keywords=[
            "database",
            "db",
            "connection",
            "pool",
            "postgres",
            "mysql",
            "mongodb",
            "query",
            "deadlock",
            "replication",
            "replica",
            "slave",
            "primary",
            "timeout",
            "sql",
            "transaction",
        ],
        hypothesis=(
            "Database connectivity or performance degradation — likely connection-pool "
            "exhaustion, slow queries, or replication lag"
        ),
        remediation_steps=[
            "Check current connection-pool utilization (SHOW STATUS LIKE 'Threads_connected')",
            "Identify long-running queries and kill blocking sessions",
            "Review slow-query log for recent regressions",
            "Scale connection pool size or add a PgBouncer tier",
            "Check disk I/O and table-lock contention metrics",
            "Verify replication lag on read replicas",
            "Rotate database credentials if breach is suspected",
        ],
        runbooks=[
            "https://runbooks.example.com/database/connection-pool",
            "https://runbooks.example.com/database/slow-query",
        ],
        base_confidence=0.90,
        estimated_mttr_minutes=45,
        root_cause_category="database",
    ),
    IncidentPattern(
        name="network",
        keywords=[
            "network",
            "latency",
            "packet",
            "loss",
            "dns",
            "tcp",
            "udp",
            "firewall",
            "vpc",
            "subnet",
            "route",
            "bgp",
            "timeout",
            "unreachable",
            "connect",
            "refused",
            "ssl",
            "tls",
            "certificate",
        ],
        hypothesis=(
            "Network-layer failure — packet loss, DNS resolution failure, "
            "firewall rule change, or TLS/certificate issue"
        ),
        remediation_steps=[
            "Run traceroute and mtr to identify the failing hop",
            "Check DNS resolution from affected hosts",
            "Verify firewall and security-group rules were not recently changed",
            "Test TLS certificate validity and expiry",
            "Confirm BGP routes are stable if cross-region traffic is involved",
            "Review CDN/load-balancer health checks",
        ],
        runbooks=[
            "https://runbooks.example.com/network/latency",
            "https://runbooks.example.com/network/dns",
        ],
        base_confidence=0.88,
        estimated_mttr_minutes=30,
        root_cause_category="network",
    ),
    IncidentPattern(
        name="memory",
        keywords=[
            "memory",
            "oom",
            "out of memory",
            "heap",
            "leak",
            "swap",
            "ram",
            "gc",
            "garbage collection",
            "jvm",
            "rss",
            "allocation",
            "malloc",
        ],
        hypothesis=(
            "Memory exhaustion — potential memory leak, OOM kill, or misconfigured "
            "heap/JVM settings"
        ),
        remediation_steps=[
            "Capture heap dump / memory profile from affected process",
            "Restart affected services to restore capacity immediately",
            "Increase container memory limits as a short-term mitigation",
            "Profile allocation hotspots with a memory profiler (py-spy, jmap)",
            "Check for missing object-cache eviction policies",
            "Review recent deployments for changes to data-loading behaviour",
        ],
        runbooks=[
            "https://runbooks.example.com/memory/oom",
            "https://runbooks.example.com/memory/leak",
        ],
        base_confidence=0.87,
        estimated_mttr_minutes=60,
        root_cause_category="memory",
    ),
    IncidentPattern(
        name="cpu",
        keywords=[
            "cpu",
            "processor",
            "compute",
            "load",
            "throttle",
            "spike",
            "utilization",
            "core",
            "thread",
            "concurrency",
            "starved",
            "busy",
            "process",
            "worker",
        ],
        hypothesis=(
            "CPU saturation — runaway process, sudden traffic spike, or poorly "
            "optimised computation consuming all available cores"
        ),
        remediation_steps=[
            "Identify top CPU-consuming processes (top/htop/pidstat)",
            "Profile hot code paths to find tight loops or expensive operations",
            "Scale out horizontally if workload is distributable",
            "Enable or tune CPU throttling limits in container runtime",
            "Check for recent changes that removed caching or batching",
            "Shed load via rate limiting if traffic spike is the root cause",
        ],
        runbooks=[
            "https://runbooks.example.com/cpu/saturation",
            "https://runbooks.example.com/cpu/profiling",
        ],
        base_confidence=0.86,
        estimated_mttr_minutes=30,
        root_cause_category="cpu",
    ),
    IncidentPattern(
        name="disk",
        keywords=[
            "disk",
            "storage",
            "volume",
            "iops",
            "io",
            "filesystem",
            "partition",
            "space",
            "full",
            "quota",
            "mount",
            "nfs",
            "ebs",
            "block",
        ],
        hypothesis=(
            "Disk or storage failure — filesystem full, I/O saturation, "
            "or storage volume detachment"
        ),
        remediation_steps=[
            "Check disk usage on all nodes (df -h)",
            "Identify and rotate or purge large log files immediately",
            "Expand storage volume or attach a new one",
            "Review I/O wait metrics and identify the heaviest writers",
            "Enable log-rotation policies if absent",
            "Monitor NFS/EBS mount state and remount if disconnected",
        ],
        runbooks=[
            "https://runbooks.example.com/disk/full",
            "https://runbooks.example.com/disk/iops",
        ],
        base_confidence=0.89,
        estimated_mttr_minutes=25,
        root_cause_category="disk",
    ),
    IncidentPattern(
        name="auth",
        keywords=[
            "auth",
            "authentication",
            "authorization",
            "token",
            "jwt",
            "oauth",
            "saml",
            "sso",
            "credential",
            "password",
            "secret",
            "key",
            "access",
            "permission",
            "forbidden",
            "unauthorized",
            "login",
            "logout",
        ],
        hypothesis=(
            "Authentication or authorization failure — expired token, rotated "
            "credentials, misconfigured IAM policy, or service-account key issue"
        ),
        remediation_steps=[
            "Verify token expiry and refresh-token validity",
            "Check IAM policies and role bindings for recent changes",
            "Rotate service-account credentials if a leak is suspected",
            "Confirm OAuth/SAML IdP is reachable and returning correct assertions",
            "Review audit logs for unauthorized access patterns",
            "Re-issue API keys if compromised",
        ],
        runbooks=[
            "https://runbooks.example.com/auth/token-expiry",
            "https://runbooks.example.com/auth/iam-policy",
        ],
        base_confidence=0.88,
        estimated_mttr_minutes=20,
        root_cause_category="auth",
    ),
    IncidentPattern(
        name="deployment",
        keywords=[
            "deploy",
            "deployment",
            "release",
            "rollout",
            "canary",
            "version",
            "image",
            "container",
            "pod",
            "crash",
            "restart",
            "configmap",
            "environment",
            "variable",
            "rollback",
            "helm",
            "kubectl",
        ],
        hypothesis=(
            "Deployment regression — a recent release introduced a bug, bad "
            "configuration, or incompatible dependency"
        ),
        remediation_steps=[
            "Identify the exact build/commit deployed in the last change window",
            "Initiate rollback to the last known-good version immediately",
            "Compare environment variables and ConfigMaps between versions",
            "Review container startup logs for crash-loop root cause",
            "Check readiness and liveness probe configuration",
            "Run smoke-test suite against the rollback version before re-enabling traffic",
        ],
        runbooks=[
            "https://runbooks.example.com/deployment/rollback",
            "https://runbooks.example.com/deployment/canary",
        ],
        base_confidence=0.91,
        estimated_mttr_minutes=20,
        root_cause_category="deployment",
    ),
]

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_P1_KEYWORDS = frozenset(
    [
        "down",
        "outage",
        "unavailable",
        "data loss",
        "breach",
        "all users",
        "production down",
        "complete failure",
        "critical",
        "sev1",
        "p1",
    ]
)
_P2_KEYWORDS = frozenset(
    [
        "degraded",
        "partial",
        "many users",
        "elevated",
        "high",
        "major",
        "sev2",
        "p2",
    ]
)
_P3_KEYWORDS = frozenset(
    [
        "intermittent",
        "some users",
        "minor",
        "warning",
        "sev3",
        "p3",
    ]
)
_P4_KEYWORDS = frozenset(
    [
        "cosmetic",
        "single user",
        "low",
        "informational",
        "sev4",
        "p4",
    ]
)


def _severity_from_text(text: str) -> str:
    lower = text.lower()
    if any(kw in lower for kw in _P1_KEYWORDS):
        return "P1"
    if any(kw in lower for kw in _P2_KEYWORDS):
        return "P2"
    if any(kw in lower for kw in _P3_KEYWORDS):
        return "P3"
    return "P4"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> list[str]:
    """Lower-case, split on non-alphanumeric boundaries, keep multi-word tokens."""
    lower = text.lower()
    # Extract single words
    words = re.findall(r"[a-z0-9]+", lower)
    # Also try two-word bigrams for phrases like "data loss", "out of memory"
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)]
    trigrams = [f"{words[i]} {words[i+1]} {words[i+2]}" for i in range(len(words) - 2)]
    return words + bigrams + trigrams


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class IncidentAnalyzer:
    """Analyse incident text and return structured hypotheses and remediation."""

    PATTERNS: ClassVar[list[IncidentPattern]] = _PATTERNS

    def analyze(self, incident: str) -> IncidentReport:
        """Score the incident description against all known patterns.

        Returns the best-match :class:`IncidentReport`.  If no pattern matches
        at all, returns a generic unknown-type report with low confidence.
        """
        tokens = _tokenize(incident)
        best_pattern: IncidentPattern | None = None
        best_confidence = 0.0
        best_matched: list[str] = []

        for pattern in self.PATTERNS:
            conf, matched = pattern.score(tokens)
            if conf > best_confidence:
                best_confidence = conf
                best_pattern = pattern
                best_matched = matched

        severity = _severity_from_text(incident)

        if best_pattern is None or best_confidence < 0.05:
            return IncidentReport(
                pattern_name="unknown",
                hypothesis="Unable to classify incident — insufficient signal",
                confidence=0.0,
                severity=severity,
                remediation_steps=[
                    "Gather more details: which services, error messages, and timings",
                    "Check dashboards for correlated metric anomalies",
                    "Escalate to on-call SRE with full context",
                ],
                runbooks=["https://runbooks.example.com/general/incident-response"],
                estimated_mttr_minutes=60,
                matched_keywords=[],
                root_cause_category="unknown",
            )

        return IncidentReport(
            pattern_name=best_pattern.name,
            hypothesis=best_pattern.hypothesis,
            confidence=best_confidence,
            severity=severity,
            remediation_steps=best_pattern.remediation_steps,
            runbooks=best_pattern.runbooks,
            estimated_mttr_minutes=best_pattern.estimated_mttr_minutes,
            matched_keywords=best_matched,
            root_cause_category=best_pattern.root_cause_category,
        )

    def correlate_alerts(self, alerts: list[str]) -> list[str]:
        """Find common root-cause categories across a list of alert strings.

        Returns deduplicated list of root-cause categories sorted by frequency,
        most likely cause first.
        """
        if not alerts:
            return []

        category_counts: dict[str, int] = {}
        for alert in alerts:
            report = self.analyze(alert)
            cat = report.root_cause_category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Sort by frequency descending; unknown last
        sorted_cats = sorted(
            category_counts.items(),
            key=lambda kv: (kv[0] == "unknown", -kv[1]),
        )
        return [cat for cat, _ in sorted_cats]
