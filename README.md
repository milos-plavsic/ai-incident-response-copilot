# 05 - AI Incident Response Copilot

[![CI](https://github.com/milos-plavsic/ai-incident-response-copilot/actions/workflows/ci.yml/badge.svg)](https://github.com/milos-plavsic/ai-incident-response-copilot/actions/workflows/ci.yml)
[![Python3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)

An operations-focused AI system that ingests logs and telemetry, builds root-cause hypothesis graphs, and proposes remediation steps with confidence estimates.

## System architecture

| Component | Description |
|-----------|-------------|
| Pattern engine | Keyword and runbook catalog with severity classification |
| Log ingestion | `POST /v1/ingest/logs` parses events and enriches narratives |
| Search cluster | `POST /v1/ingest/elasticsearch` pulls recent lines from Elasticsearch/OpenSearch |
| Timeline | Chronological reconstruction from supplied events |
| Synthesis | Text refinement when `LLM_API_KEY` is configured |
| UI | `/ui` incident review console |

Libraries: [ml-core](https://github.com/milos-plavsic/ml-core), [agent-core](https://github.com/milos-plavsic/agent-core).

## Quickstart

```bash
make install
make run
make api
make test
```

Docker API: `make docker-api`.

## API

- OpenAPI docs: `http://127.0.0.1:8000/docs`
- Health: `GET /health`
- Incident analysis: `POST /v1/incidents/analyze` with JSON body `{"incident":"..."}`

## Architecture

```mermaid
flowchart LR
  L[Logs/metrics] --> A[Anomalies]
  A --> C[Correlation]
  C --> H[Hypotheses]
  H --> R[Remediation]
  R --> P[Postmortem]
```

## Core Capabilities

- Log/metric ingestion from synthetic or real traces.
- Temporal anomaly detection and correlation clustering.
- Root-cause hypothesis graph construction.
- Remediation suggestion ranking with rationale.
- Postmortem draft generation from incident timeline.

## Architecture (Graph)

`ingest_signals -> anomaly_detector -> correlation_engine -> hypothesis_builder -> remediation_planner -> confidence_scorer -> postmortem_writer`
