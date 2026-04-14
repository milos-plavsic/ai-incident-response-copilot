"""Fine-tuning strategies for ops copilots (domain adapters, structured outputs)."""


def describe_incident_llm_finetune_playbook() -> dict:
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
    import json

    print(json.dumps(describe_incident_llm_finetune_playbook(), indent=2))


if __name__ == "__main__":
    main()
