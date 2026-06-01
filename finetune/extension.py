"""Fine-tuning strategies for ops copilots (domain adapters, structured outputs)."""

from ml_core import configure_logging

logger = configure_logging(__name__)


def incident_training_guide() -> dict:
    """Return notes for incident-classification model fine-tuning."""
    return {
        "adapter_finetune": [
            "Train a small LoRA on internal postmortems → structured hypothesis JSON.",
            "Distill a large model into a tiny classifier for severity triage.",
        ],
        "hybrid": [
            "Keep sklearn anomaly detectors frozen; fine-tune only the narrative generator.",
        ],
        "eval": "Human-rated usefulness of remediation steps on replayed incidents.",
    }


def main() -> None:
    """Main."""
    import json

    logger.info(json.dumps(incident_training_guide(), indent=2))


if __name__ == "__main__":
    main()
