"""Elasticsearch / OpenSearch log ingestion helpers."""

from __future__ import annotations

import os
from typing import Any

import httpx


def _auth_headers() -> dict[str, str]:
    api_key = os.environ.get("ELASTIC_API_KEY", "").strip()
    if api_key:
        return {"Authorization": f"ApiKey {api_key}"}
    user = os.environ.get("ELASTIC_USER", "").strip()
    password = os.environ.get("ELASTIC_PASSWORD", "").strip()
    if user and password:
        return {}
    return {}


def fetch_logs(
    *,
    host: str,
    index: str,
    query: str,
    size: int = 50,
    minutes: int = 60,
) -> list[str]:
    """Query Elasticsearch or OpenSearch and return message lines."""
    host = host.rstrip("/")
    url = f"{host}/{index}/_search"
    body: dict[str, Any] = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}],
            }
        },
    }
    user = os.environ.get("ELASTIC_USER", "").strip()
    password = os.environ.get("ELASTIC_PASSWORD", "").strip()
    auth = (user, password) if user and password else None
    headers = {"Content-Type": "application/json", **_auth_headers()}

    with httpx.Client(timeout=30.0, verify=True) as client:
        resp = client.post(url, json=body, headers=headers, auth=auth)
        resp.raise_for_status()
        payload = resp.json()

    lines: list[str] = []
    for hit in payload.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        msg = src.get("message") or src.get("log") or src.get("msg")
        if isinstance(msg, str) and msg.strip():
            lines.append(msg.strip())
        else:
            lines.append(str(src)[:500])
    return lines
