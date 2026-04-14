from fastapi.testclient import TestClient

from app.api import app

client = TestClient(app)


def test_health() -> None:
    assert client.get("/health").status_code == 200


def test_incident() -> None:
    r = client.post("/v1/incidents/analyze", json={"incident": "500 errors"})
    assert r.status_code == 200
    assert "top_hypothesis" in r.json()
