import os


def investigate(incident: str) -> dict:
    return {
        "incident": incident,
        "top_hypothesis": "database connection pool exhaustion",
        "confidence": 0.77,
        "next_action": "scale pool and tune timeouts",
    }


def main() -> None:
    incident = os.getenv("DEMO_INCIDENT", "API p95 latency spike")
    result = investigate(incident)
    print("AI Incident Response Copilot")
    for k, v in result.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
