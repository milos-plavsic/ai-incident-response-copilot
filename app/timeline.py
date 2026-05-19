"""Timeline reconstruction for incident events."""

from __future__ import annotations

import re
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# Timestamp extraction
# ---------------------------------------------------------------------------

# Patterns tried in order from most- to least-specific
_TS_PATTERNS: list[tuple[str, str]] = [
    # ISO 8601 with optional timezone
    (
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        "%Y-%m-%dT%H:%M:%S",
    ),
    # Date only: 2024-03-15
    (r"\d{4}-\d{2}-\d{2}", "%Y-%m-%d"),
    # Common log format: 15/Mar/2024:10:30:00
    (r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}", "%d/%b/%Y:%H:%M:%S"),
    # Epoch seconds (10 digits)
    (r"\b1[6-9]\d{8}\b", "epoch"),
    # Time only: 10:30:45
    (r"\b\d{2}:\d{2}:\d{2}\b", "time_only"),
]

_CAUSAL_TRIGGERS = frozenset(
    [
        "deploy",
        "release",
        "restart",
        "config",
        "change",
        "push",
        "rollout",
        "migration",
        "upgrade",
        "scale",
        "cronjob",
        "job",
    ]
)
_CAUSAL_SYMPTOMS = frozenset(
    [
        "error",
        "exception",
        "fail",
        "latency",
        "slow",
        "timeout",
        "spike",
        "alarm",
        "alert",
        "high",
        "elevated",
        "warning",
    ]
)
_CAUSAL_IMPACTS = frozenset(
    [
        "down",
        "outage",
        "unavailable",
        "degraded",
        "page",
        "customer",
        "revenue",
        "sla",
        "breach",
    ]
)


def _extract_timestamp(text: str) -> datetime | None:
    """Try to parse a datetime from free-form text.  Returns None if no match."""
    for pattern, fmt in _TS_PATTERNS:
        m = re.search(pattern, text, re.IGNORECASE)
        if not m:
            continue
        raw = m.group(0)
        try:
            if fmt == "epoch":
                return datetime.fromtimestamp(int(raw), tz=UTC)
            if fmt == "time_only":
                # Default to today's date; good enough for ordering
                today = datetime.now(tz=UTC).date()
                t = datetime.strptime(raw, "%H:%M:%S").time()
                return datetime.combine(today, t, tzinfo=UTC)
            # Strip sub-second and tz for strptime then re-attach UTC
            raw_clean = re.sub(r"\.\d+", "", raw)
            raw_clean = re.sub(r"Z$", "", raw_clean)
            raw_clean = re.sub(r"[+-]\d{2}:?\d{2}$", "", raw_clean)
            raw_clean = raw_clean.replace(" ", "T")
            return datetime.strptime(raw_clean, fmt).replace(tzinfo=UTC)
        except (ValueError, OSError):
            continue
    return None


def _classify_causal_role(text: str) -> str:
    lower = text.lower()
    words = set(re.findall(r"[a-z]+", lower))
    if words & _CAUSAL_TRIGGERS:
        return "trigger"
    if words & _CAUSAL_IMPACTS:
        return "impact"
    if words & _CAUSAL_SYMPTOMS:
        return "symptom"
    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def reconstruct_timeline(incident: str, events: list[str]) -> list[dict]:
    """Order *events* chronologically and label each with a causal role.

    Also attempts to extract a trigger event from the *incident* description
    itself and prepends it if a timestamp is found.

    Returns a list of dicts with keys:
        - ``timestamp``: ISO-8601 string or ``"unknown"``
        - ``event``: original event string
        - ``causal_role``: ``"trigger"`` | ``"symptom"`` | ``"impact"`` | ``"unknown"``
    """
    parsed: list[tuple[datetime | None, str]] = []

    # Optionally include the incident description as a seed event
    inc_ts = _extract_timestamp(incident)
    _classify_causal_role(incident)
    if inc_ts is not None:
        parsed.append((inc_ts, f"[incident] {incident.strip()}"))
    elif incident.strip():
        # No timestamp but still include as first "unknown" event
        parsed.append((None, f"[incident] {incident.strip()}"))

    for ev in events:
        ts = _extract_timestamp(ev)
        parsed.append((ts, ev.strip()))

    # Sort: events with timestamps first (chronological), then unknown
    def sort_key(item: tuple[datetime | None, str]):
        ts, _ = item
        if ts is None:
            return (1, datetime.min.replace(tzinfo=UTC))
        return (0, ts)

    parsed.sort(key=sort_key)

    result: list[dict] = []
    seen_roles: list[str] = []
    for ts, ev_text in parsed:
        role = _classify_causal_role(ev_text)
        # Promote to causal chain: first trigger seen anchors everything
        if role == "trigger" and "trigger" in seen_roles:
            role = "symptom"
        seen_roles.append(role)
        result.append(
            {
                "timestamp": ts.isoformat() if ts is not None else "unknown",
                "event": ev_text,
                "causal_role": role,
            }
        )

    return result
