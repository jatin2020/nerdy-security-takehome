from fastapi.testclient import TestClient
from src.agent import TriageAgent
from src.config import get_settings
from src.fixtures_loader import get_fixtures_store
from src.llm import BaseLLMClient, LLMMessage, LLMResponse
from src.models import ProviderTimeoutException, TriageRequest
from src.tools import get_tool_registry


def test_unknown_alert_returns_404(client: TestClient):
    """AC5: Unknown alert ID returns controlled 404 without raw stack traces."""
    response = client.post(
        "/triage",
        json={
            "alert_id": "alt-nonexistent-9999",
            "actor_id": "usr-sec-prod-01",
            "alert_description": "Alert not in fixtures",
        },
    )
    assert response.status_code == 404
    data = response.json()
    assert data["error"] == "ALERT_NOT_FOUND"
    assert "alt-nonexistent-9999" in data["message"]
    assert "traceback" not in data


def test_actor_alert_mismatch_returns_422(client: TestClient):
    """AC5: Attempting to triage alert with mismatched actor ID is rejected."""
    # alt-high-01 actually belongs to usr-sec-prod-01, not usr-student-02
    response = client.post(
        "/triage",
        json={
            "alert_id": "alt-high-01",
            "actor_id": "usr-student-02",
            "alert_description": "Mismatched actor triage attempt",
        },
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "ACTOR_ALERT_MISMATCH"
    assert "usr-sec-prod-01" in data["message"]


def test_malformed_input_returns_422(client: TestClient):
    """AC5: Malformed schema payload returns controlled 422 validation error."""
    response = client.post(
        "/triage",
        json={
            "alert_id": "",  # Empty
            "actor_id": "usr-1",
        },
    )
    assert response.status_code == 422
    data = response.json()
    assert data["error"] == "VALIDATION_ERROR"
    assert "validation_errors" in data["details"]


def test_provider_timeout_simulation_returns_504(client: TestClient):
    """AC5: Provider timeout produces controlled 504 without exposing secrets or raw stack traces."""
    class TimingOutLLMClient(BaseLLMClient):
        def generate(self, messages: list[LLMMessage], tools: list) -> LLMResponse:
            raise ProviderTimeoutException("OpenAI-Compatible", timeout=15.0)

    from unittest.mock import patch
    with patch("src.main.get_llm_client", return_value=TimingOutLLMClient()):
        response = client.post(
            "/triage",
            json={
                "alert_id": "alt-high-01",
                "actor_id": "usr-sec-prod-01",
                "alert_description": "Normal alert",
            },
        )
        assert response.status_code == 504
        data = response.json()
        assert data["error"] == "PROVIDER_TIMEOUT"
        assert "timed out after 15.0 seconds" in data["message"]
        assert "traceback" not in data
