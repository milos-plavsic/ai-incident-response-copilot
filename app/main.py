import os

from ml_core import configure_logging

logger = configure_logging(__name__)


def investigate(incident: str) -> dict:
    """Execute the investigate routine."""
    return {
        "incident": incident,
        "top_hypothesis": "database connection pool exhaustion",
        "confidence": 0.77,
        "next_action": "scale pool and tune timeouts",
    }


def main() -> None:
    """Execute the main routine."""
    incident = os.getenv("DEMO_INCIDENT", "API p95 latency spike")
    result = investigate(incident)
    logger.info("AI Incident Response Copilot")
    for k, v in result.items():
        logger.info(f"{k}: {v}")


if __name__ == "__main__":
    main()
