"""The API end to end, against the stub model so no torch or download is needed."""

import importlib
import json
import sys

import pytest
from fastapi.testclient import TestClient

KEY = {"X-API-Key": "test-key"}


@pytest.fixture
def make_client(tmp_path, monkeypatch):
    """Build a fresh app with the given configuration.

    The API reads its configuration when the module is imported, so each test
    sets the environment and then imports a clean copy.
    """
    def build(response_mode="full", budget=0, blocked=None):
        monkeypatch.setenv("MODEL_STUB", "1")
        monkeypatch.setenv("LOG_PATH", str(tmp_path / "requests.jsonl"))
        monkeypatch.setenv("BLOCKLIST_PATH", str(tmp_path / "blocked.json"))
        monkeypatch.setenv("RESPONSE_MODE", response_mode)
        monkeypatch.setenv("QUERY_BUDGET", str(budget))
        if blocked is not None:
            (tmp_path / "blocked.json").write_text(json.dumps({"blocked": blocked}),
                                                   encoding="utf-8")
        for name in ("api.main", "defences", "stub"):
            sys.modules.pop(name, None)
        return TestClient(importlib.import_module("api.main").app)
    return build


def logged(tmp_path):
    path = tmp_path / "requests.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_health_reports_the_model_is_loaded(make_client):
    with make_client() as client:
        assert client.get("/health").json() == {"status": "ok", "model_loaded": True}


def test_valid_request_is_answered_and_logged_with_six_fields(make_client, tmp_path):
    with make_client() as client:
        r = client.post("/predict", headers=KEY, json={"input": "a great film"})
    assert r.status_code == 200
    assert r.json()["label"] == "POSITIVE"
    assert 0 <= r.json()["confidence"] <= 1
    lines = logged(tmp_path)
    assert len(lines) == 1
    assert set(lines[0]) == {"ts", "api_key", "input", "predicted_label", "confidence", "latency_ms"}


@pytest.mark.parametrize("headers", [{}, {"X-API-Key": ""}, {"X-API-Key": "   "}])
def test_missing_or_empty_key_is_401(make_client, headers):
    with make_client() as client:
        assert client.post("/predict", headers=headers, json={"input": "hello there"}).status_code == 401


@pytest.mark.parametrize("body", [
    {"text": "wrong field"},
    {"input": None},
    {"input": 42},
    {"input": ["a list"]},
    {"input": ""},
    {"input": "   "},
    {"input": "a" * 2001},
])
def test_invalid_input_is_422_and_never_logged(make_client, tmp_path, body):
    with make_client() as client:
        assert client.post("/predict", headers=KEY, json=body).status_code == 422
    assert logged(tmp_path) == []


def test_malformed_json_is_422(make_client):
    with make_client() as client:
        r = client.post("/predict", headers={**KEY, "Content-Type": "application/json"},
                        content=b'{"input": broken')
    assert r.status_code == 422


def test_input_exactly_at_the_limit_is_accepted(make_client):
    with make_client() as client:
        assert client.post("/predict", headers=KEY, json={"input": "a " * 1000}).status_code == 200


def test_blocked_key_gets_429_without_leaking_reasons_and_others_are_unaffected(make_client):
    blocked = {"test-key": {"why": ["sends many near-identical queries"]}}
    with make_client(blocked=blocked) as client:
        r = client.post("/predict", headers=KEY, json={"input": "a great film"})
        other = client.post("/predict", headers={"X-API-Key": "someone-else"},
                            json={"input": "a great film"})
    assert r.status_code == 429
    assert r.json() == {"error": "api key throttled: suspected model extraction"}
    assert "near-identical" not in r.text
    assert other.status_code == 200


def test_log_lines_are_written_with_fsync_disabled(make_client, tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_FSYNC", "0")
    with make_client() as client:
        assert client.post("/predict", headers=KEY, json={"input": "a great film"}).status_code == 200
    assert len(logged(tmp_path)) == 1


def test_budget_refuses_after_the_limit_and_ignores_malformed_requests(make_client):
    with make_client(budget=2) as client:
        assert client.post("/predict", headers=KEY, json={"input": ""}).status_code == 422
        codes = [client.post("/predict", headers=KEY, json={"input": "good film"}).status_code
                 for _ in range(3)]
    assert codes == [200, 200, 429]


@pytest.mark.parametrize("mode,fields", [
    ("full", {"label", "confidence"}),
    ("rounded", {"label", "confidence"}),
    ("label", {"label"}),
])
def test_response_modes_shape_the_answer(make_client, mode, fields):
    with make_client(response_mode=mode) as client:
        r = client.post("/predict", headers=KEY, json={"input": "a great film"})
    assert set(r.json()) == fields


def test_unknown_response_mode_refuses_to_start(make_client):
    with pytest.raises(RuntimeError):
        make_client(response_mode="fuzzy")
