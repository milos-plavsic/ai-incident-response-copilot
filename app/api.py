"""Incident Response API — production-ready with real analysis logic."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from ml_core import configure_logging, install_middleware
from ml_core import lifespan as _app_lifespan
from ml_core.exceptions import ApplicationError
from ml_core.observability import metrics_router, observe_request
from pydantic import BaseModel, Field

from app.elastic_ingest import fetch_logs
from app.incident_analyzer import IncidentAnalyzer
from app.log_ingest import enrich_incident_text, parse_log_lines
from app.timeline import reconstruct_timeline

logger = configure_logging("incident-response")

app = FastAPI(
    title="Incident Response Copilot",
    version="1.0.0",
    description="Intelligent incident classification and response generation",
)

# Wire lifespan, middleware, and observability.
try:
    app.router.lifespan_context = _app_lifespan  # type: ignore[attr-defined]
except (AttributeError, TypeError):
    pass

install_middleware(app, cors_allow_origins=("*",), cors_allow_credentials=False)


@app.middleware("http")
async def _observability_middleware(request: Request, call_next: Any) -> Any:
    """Record request metrics for every HTTP call."""
    return await observe_request(request, call_next)


app.include_router(metrics_router)

_ui = Path(__file__).resolve().parent / "static"
if _ui.is_dir():
    app.mount("/ui", StaticFiles(directory=str(_ui), html=True), name="incident-ui")

# ---------------------------------------------------------------------------
# Rate limiter — thin wrapper that avoids requiring ml_core installed at import
# ---------------------------------------------------------------------------

try:
    from ml_core.ratelimit import RateLimiter
    from ml_core.ratelimit import RateLimitExceeded as _RateLimitExceeded

    _limiter = RateLimiter(rate=float(os.environ.get("RATE_LIMIT_RPS", "20")), burst=40)
    _RL_ENABLED = True
except ImportError:  # pragma: no cover — ml_core optional in standalone dev
    _limiter = None  # type: ignore[assignment]
    _RateLimitExceeded = Exception  # type: ignore[assignment, misc]
    _RL_ENABLED = False

# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

try:
    from ml_core.auth import APIKeyMiddleware  # noqa: F401 (side-effect import)

    _API_KEY: str | None = os.environ.get("API_KEY", "").strip() or None
    _AUTH_ENABLED = bool(_API_KEY)

    # Install at module-level so FastAPI picks it up
    if _AUTH_ENABLED:
        from starlette.middleware.base import BaseHTTPMiddleware

        class _AuthMiddleware(BaseHTTPMiddleware):
            _PUBLIC = frozenset(["/health", "/metrics", "/docs", "/openapi.json", "/v1/runbooks"])

            async def dispatch(self, request: Request, call_next: Any) -> Any:
                if request.url.path in self._PUBLIC:
                    return await call_next(request)
                provided = request.headers.get("X-API-Key", "").strip()
                if provided != _API_KEY:
                    return JSONResponse(
                        {"error": "Unauthorized", "detail": "Invalid or missing X-API-Key"},
                        status_code=401,
                    )
                return await call_next(request)

        app.add_middleware(_AuthMiddleware)

except ImportError:  # pragma: no cover
    _AUTH_ENABLED = False

# ---------------------------------------------------------------------------
# Shared analyzer instance
# ---------------------------------------------------------------------------

_analyzer = IncidentAnalyzer()

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

_RUNBOOK_CATEGORIES = [
    "database/connection-pool",
    "database/slow-query",
    "network/latency",
    "network/dns",
    "memory/oom",
    "memory/leak",
    "cpu/saturation",
    "cpu/profiling",
    "disk/full",
    "disk/iops",
    "auth/token-expiry",
    "auth/iam-policy",
    "deployment/rollback",
    "deployment/canary",
    "general/incident-response",
]


class AnalyzeRequest(BaseModel):
    """Request payload for POST /v1/analyze."""

    incident: str = Field(
        ..., min_length=1, max_length=8000, description="Free-text incident description"
    )
    alerts: list[str] = Field(
        default_factory=list, description="Optional list of related alert strings"
    )
    events: list[str] = Field(
        default_factory=list, description="Optional list of raw event log lines"
    )


class AnalyzeResponse(BaseModel):
    """Analysis result."""

    request_id: str
    timestamp: str
    pattern_name: str
    hypothesis: str
    confidence: float
    severity: str
    remediation_steps: list[str]
    runbooks: list[str]
    estimated_mttr_minutes: int
    matched_keywords: list[str]
    root_cause_category: str
    correlated_root_causes: list[str]
    timeline: list[dict]


# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(ApplicationError)
async def app_exception_handler(_request: Request, exc: ApplicationError) -> JSONResponse:
    logger.error("ApplicationError: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content={"error": str(exc)})


@app.exception_handler(Exception)
async def generic_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(status_code=500, content={"error": "Internal server error"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/v1/runbooks")
async def list_runbooks() -> dict[str, object]:
    """Return the list of available runbook categories."""
    return {
        "runbook_categories": _RUNBOOK_CATEGORIES,
        "base_url": "https://runbooks.example.com",
    }


@app.post("/v1/analyze", response_model=AnalyzeResponse)
async def analyze_incident(request: Request, body: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze an incident description and return structured hypotheses.

    - Applies real pattern matching against 7 incident categories.
    - Correlates root-causes across any additional ``alerts``.
    - Reconstructs a chronological ``timeline`` from ``events``.
    - Rate-limits by client IP if ml-core is installed.
    """
    # Rate limiting
    if _RL_ENABLED and _limiter is not None:
        client_ip = request.client.host if request.client else "unknown"
        try:
            _limiter.acquire(client_ip)
        except _RateLimitExceeded:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

    try:
        narrative = enrich_incident_text(body.incident, body.events)
        report = _analyzer.analyze(narrative)
        correlated = _analyzer.correlate_alerts(body.alerts) if body.alerts else []
        timeline = reconstruct_timeline(body.incident, body.events) if body.events else []

        response = AnalyzeResponse(
            request_id=f"INC-{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(UTC).isoformat(),
            pattern_name=report.pattern_name,
            hypothesis=report.hypothesis,
            confidence=report.confidence,
            severity=report.severity,
            remediation_steps=report.remediation_steps,
            runbooks=report.runbooks,
            estimated_mttr_minutes=report.estimated_mttr_minutes,
            matched_keywords=report.matched_keywords,
            root_cause_category=report.root_cause_category,
            correlated_root_causes=correlated,
            timeline=timeline,
        )
        logger.info(
            "Incident analyzed",
            extra={
                "request_id": response.request_id,
                "pattern": report.pattern_name,
                "confidence": report.confidence,
                "severity": report.severity,
            },
        )
        return response

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to analyze incident: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to analyze incident") from exc


# ---------------------------------------------------------------------------
# Legacy / backwards-compatible endpoints
# ---------------------------------------------------------------------------


class ElasticIngestRequest(BaseModel):
    host: str = Field(..., description="Elasticsearch or OpenSearch base URL")
    index: str = Field(..., description="Index pattern, e.g. logs-*")
    query: str = Field(default="level:error OR message:*exception*")
    incident: str = Field(default="")
    size: int = Field(default=50, ge=1, le=500)
    minutes: int = Field(default=60, ge=1, le=1440)


@app.post("/v1/ingest/logs")
async def ingest_logs(body: AnalyzeRequest) -> dict:
    """Parse log lines and return signal statistics without full analysis."""
    sig = parse_log_lines(body.events)
    return {
        "line_count": len(sig.lines),
        "error_count": sig.error_count,
        "warn_count": sig.warn_count,
        "preview": sig.lines[-5:],
    }


@app.post("/v1/ingest/elasticsearch")
async def ingest_elasticsearch(body: ElasticIngestRequest) -> dict:
    """Pull recent log lines from Elasticsearch/OpenSearch and optionally analyze."""
    try:
        lines = fetch_logs(
            host=body.host,
            index=body.index,
            query=body.query,
            size=body.size,
            minutes=body.minutes,
        )
    except Exception as exc:
        logger.warning("elastic ingest failed: %s", exc)
        raise HTTPException(status_code=502, detail="Failed to query search cluster") from exc

    sig = parse_log_lines(lines)
    result: dict[str, object] = {
        "line_count": len(sig.lines),
        "error_count": sig.error_count,
        "warn_count": sig.warn_count,
        "preview": sig.lines[-8:],
        "events": lines,
    }
    if body.incident.strip():
        narrative = enrich_incident_text(body.incident, lines)
        report = _analyzer.analyze(narrative)
        result["analysis"] = {
            "pattern_name": report.pattern_name,
            "hypothesis": report.hypothesis,
            "confidence": report.confidence,
            "severity": report.severity,
        }
    return result


@app.post("/v1/incidents/analyze")
async def analyze_incident_legacy(body: AnalyzeRequest) -> dict:
    """Backwards-compatible endpoint; delegates to /v1/analyze logic."""
    report = _analyzer.analyze(body.incident)
    return {
        "top_hypothesis": report.hypothesis,
        "confidence": report.confidence,
        "severity": report.severity,
        "pattern_name": report.pattern_name,
        "remediation_steps": report.remediation_steps,
        "estimated_mttr_minutes": report.estimated_mttr_minutes,
        "runbooks": report.runbooks,
    }
