"""Offline tests for the FastAPI layer. The provider is faked, so no key or network is needed."""

import json

import pytest
from fastapi.testclient import TestClient

import ai_engine
import main
from mock_db import get_compliance_state

client = TestClient(main.app)

REGULATION = ai_engine._DEMO_REGULATION


def finding(**overrides):
    item = {
        "title": "Data retention period too short",
        "category": "data_retention",
        "severity": "high",
        "gap_type": "non_compliant",
        "regulation_requirement": "Retain transaction records for 90 days.",
        "regulation_excerpt": "must retain customer transaction records for a minimum of 90 days",
        "current_state": "data_retention_days = 30",
        "gap_description": "Retention is 30 days, the regulation requires 90.",
        "recommended_remediation": "Raise retention to 90 days.",
    }
    item.update(overrides)
    return item


@pytest.fixture
def fake_provider(monkeypatch):
    calls = []

    def install(*outputs):
        queue = list(outputs)

        def fake(prompt, system_message, json_mode, schema, temperature, max_tokens, *, api_key=None):
            calls.append({"json_mode": json_mode, "api_key": api_key, "prompt": prompt})
            out = queue.pop(0) if len(queue) > 1 else queue[0]
            if isinstance(out, Exception):
                raise out
            return out

        monkeypatch.setattr(ai_engine, "_provider_complete", fake)
        return calls

    return install


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_system_state_returns_mock_profile():
    response = client.get("/api/system-state")
    assert response.status_code == 200
    assert response.json() == get_compliance_state()


def test_analyze_uses_mock_state_and_returns_contract_list(fake_provider):
    calls = fake_provider(json.dumps({"anomalies": [finding(severity="low"), finding(title="No DPO", severity="critical")]}))
    response = client.post("/api/analyze-regulation", json={"text": REGULATION})
    assert response.status_code == 200
    body = response.json()
    assert [a["id"] for a in body] == ["ANOM-001", "ANOM-002"]
    assert body[0]["title"] == "No DPO"
    assert '"data_retention_days": 30' in calls[0]["prompt"]  # mock state was sent
    assert calls[0]["api_key"] is None


def test_analyze_accepts_custom_company_state(fake_provider):
    calls = fake_provider('{"anomalies": []}')
    response = client.post(
        "/api/analyze-regulation", json={"text": REGULATION, "company_state": {"retention_days": 365}}
    )
    assert response.status_code == 200 and response.json() == []
    assert '"retention_days": 365' in calls[0]["prompt"]


def test_byok_header_reaches_the_provider(fake_provider):
    calls = fake_provider('{"anomalies": []}')
    response = client.post(
        "/api/analyze-regulation", json={"text": REGULATION}, headers={"X-Anthropic-Api-Key": " user-key "}
    )
    assert response.status_code == 200
    assert calls[0]["api_key"] == "user-key"


def test_generate_audit_from_text_runs_analysis_then_audit(fake_provider):
    calls = fake_provider(json.dumps({"anomalies": [finding()]}), "not a valid audit log")
    response = client.post("/api/generate-audit", json={"text": REGULATION})
    assert response.status_code == 200
    body = response.json()
    assert body["anomalies"][0]["id"] == "ANOM-001"
    assert body["markdown"].startswith("# Compliance Audit Log")  # fallback renderer
    assert "### ANOM-001" in body["markdown"]
    assert [c["json_mode"] for c in calls] == [True, False, False]


def test_generate_audit_from_anomalies_skips_analysis(fake_provider):
    calls = fake_provider("garbage")
    anomalies = [{"id": "ANOM-001", **finding()}]
    response = client.post("/api/generate-audit", json={"anomalies": anomalies})
    assert response.status_code == 200
    assert response.json()["anomalies"] == anomalies
    assert all(c["json_mode"] is False for c in calls)


def test_generate_audit_empty_anomalies_needs_no_llm(fake_provider):
    calls = fake_provider("unused")
    response = client.post("/api/generate-audit", json={"anomalies": []})
    assert response.status_code == 200
    assert "No compliance gaps detected" in response.json()["markdown"]
    assert calls == []


def test_generate_audit_requires_text_or_anomalies():
    assert client.post("/api/generate-audit", json={}).status_code == 422


@pytest.mark.parametrize("body", [{}, {"text": ""}, {"text": "x" * 100_001}, {"text": 5}])
def test_analyze_rejects_bad_body(body):
    assert client.post("/api/analyze-regulation", json=body).status_code == 422


def test_engine_value_error_maps_to_422(fake_provider):
    fake_provider('{"anomalies": []}')
    response = client.post("/api/analyze-regulation", json={"text": "   ", "company_state": {"a": 1}})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "INVALID_INPUT"


def test_bad_anomaly_shape_maps_to_422(fake_provider):
    fake_provider("unused")
    response = client.post("/api/generate-audit", json={"anomalies": [{"title": "no gap description"}]})
    assert response.status_code == 422


def test_missing_key_maps_to_401(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    response = client.post("/api/analyze-regulation", json={"text": REGULATION})
    assert response.status_code == 401
    assert "X-Anthropic-Api-Key" in response.json()["detail"]["message"]


def test_provider_failure_maps_to_502(fake_provider):
    fake_provider(ai_engine.LLMError("provider error: HTTP 529"))
    response = client.post("/api/analyze-regulation", json={"text": REGULATION})
    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "LLM_UNAVAILABLE"


def test_persistent_bad_output_maps_to_502(fake_provider):
    fake_provider("garbage")
    assert client.post("/api/analyze-regulation", json={"text": REGULATION}).status_code == 502


def test_api_key_is_not_echoed_in_errors(fake_provider):
    fake_provider(ai_engine.LLMConfigError("the API key was rejected by the provider (AuthenticationError)"))
    response = client.post(
        "/api/analyze-regulation", json={"text": REGULATION}, headers={"X-Anthropic-Api-Key": "sk-ant-secret"}
    )
    assert response.status_code == 401
    assert "sk-ant-secret" not in response.text


def test_cors_allows_the_key_header():
    response = client.options(
        "/api/analyze-regulation",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-anthropic-api-key,content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
