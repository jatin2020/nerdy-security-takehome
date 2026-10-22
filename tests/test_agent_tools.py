import json
import pytest
from src.agent import TriageAgent
from src.config import get_settings
from src.fixtures_loader import get_fixtures_store
from src.llm import BaseLLMClient, LLMMessage, LLMResponse
from src.models import (
    EvidenceValidationException,
    ToolExecutionException,
    TriageRequest,
)
from src.tools import get_tool_registry


def test_tool_registry_rejects_unapproved_tools():
    """AC3 & Scope: Out-of-scope tools are rejected by strict allowlist."""
    registry = get_tool_registry()

    with pytest.raises(ToolExecutionException) as exc_info:
        registry.execute_tool("disable_account", {"actor_id": "usr-sec-prod-01"})
    assert "not in the authorized read-only allowlist" in exc_info.value.message

    with pytest.raises(ToolExecutionException) as exc_info:
        registry.execute_tool("revoke_active_tokens", {"actor_id": "usr-sec-prod-01"})
    assert "not in the authorized read-only allowlist" in exc_info.value.message


def test_tool_registry_validates_arguments():
    """Tool arguments must be present and correctly typed."""
    registry = get_tool_registry()

    with pytest.raises(ToolExecutionException) as exc_info:
        registry.execute_tool("get_identity_context", {})
    assert "Missing or invalid 'actor_id'" in exc_info.value.message


def test_model_output_with_fabricated_evidence_fails_validation():
    """AC3: Fabricated or unobserved evidence IDs produce controlled failure."""
    class FabricatingLLMClient(BaseLLMClient):
        def generate(self, messages: list[LLMMessage], tools: list) -> LLMResponse:
            for msg in messages:
                if msg.role == "tool":
                    # Tool returned legitimate evidence; model fabricates fake reference
                    hallucinated_json = {
                        "explanation": "Observed suspicious login from unauthorized country.",
                        "evidence_references": [
                            "identity:usr-sec-prod-01",
                            "event:evt-FAKE-HALLUCINATED-999"  # Nonexistent reference!
                        ],
                        "uncertainties": [],
                        "recommended_next_steps": ["Review access."],
                    }
                    return LLMResponse(content=json.dumps(hallucinated_json))

            return LLMResponse(
                tool_calls=[{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_identity_context", "arguments": json.dumps({"actor_id": "usr-sec-prod-01"})},
                }]
            )

    agent = TriageAgent(
        llm_client=FabricatingLLMClient(),
        tool_registry=get_tool_registry(),
        fixtures_store=get_fixtures_store(),
        settings=get_settings(),
    )

    req = TriageRequest(
        alert_id="alt-high-01",
        actor_id="usr-sec-prod-01",
        alert_description="Anomalous login alert",
    )

    with pytest.raises(EvidenceValidationException) as exc_info:
        agent.triage_alert(req)
    assert "event:evt-FAKE-HALLUCINATED-999" in exc_info.value.details["fabricated_references"]
