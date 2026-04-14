from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.main import investigate
from finetune.extension import describe_incident_llm_finetune_playbook

app = FastAPI(title="AI Incident Response Copilot", version="0.1.0")


class IncidentRequest(BaseModel):
    incident: str = Field(..., min_length=1, description="Short incident description")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/incidents/analyze")
def analyze_incident(body: IncidentRequest) -> dict:
    return investigate(body.incident)


@app.get("/v1/finetune/playbook")
def finetune_playbook() -> dict:
    return describe_incident_llm_finetune_playbook()
