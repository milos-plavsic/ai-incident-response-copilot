from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ParsedSignal:
    lines: list[str]
    error_count: int
    warn_count: int


def parse_log_lines(events: list[str]) -> ParsedSignal:
    """Normalize raw log lines for downstream pattern analysis."""
    lines = [ln.strip() for ln in events if ln and ln.strip()]
    errors = sum(1 for ln in lines if re.search(r"\b(error|fatal|panic)\b", ln, re.I))
    warns = sum(1 for ln in lines if re.search(r"\bwarn(ing)?\b", ln, re.I))
    return ParsedSignal(lines=lines, error_count=errors, warn_count=warns)


def enrich_incident_text(incident: str, events: list[str]) -> str:
    """Append structured log statistics to the incident narrative."""
    if not events:
        return incident
    sig = parse_log_lines(events)
    summary = (
        f"\n\n[Log summary] lines={len(sig.lines)} errors={sig.error_count} "
        f"warnings={sig.warn_count}"
    )
    tail = "\n".join(sig.lines[-8:])
    return incident + summary + "\n" + tail
