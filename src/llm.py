import json
from abc import ABC, abstractmethod
from typing import Any, Optional
import httpx
from src.config import Settings
from src.models import (
    InvalidModelOutputException,
    ModelRecommendation,
    ProviderTimeoutException,
    TriageServiceException,
)
from src.tools import TOOL_DEFINITIONS


class LLMMessage:
    def __init__(self, role: str, content: Optional[str] = None, tool_calls: Optional[list[dict[str, Any]]] = None, tool_call_id: Optional[str] = None):
        self.role = role
        self.content = content
        self.tool_calls = tool_calls
        self.tool_call_id = tool_call_id

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            d["content"] = self.content
        if self.tool_calls is not None:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id is not None:
            d["tool_call_id"] = self.tool_call_id
        return d


class LLMResponse:
    def __init__(self, content: Optional[str] = None, tool_calls: Optional[list[dict[str, Any]]] = None):
        self.content = content
        self.tool_calls = tool_calls or []

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class BaseLLMClient(ABC):
    """Abstract interface for LLM interaction supporting tool calling."""

    @abstractmethod
    def generate(self, messages: list[LLMMessage], tools: list[dict[str, Any]]) -> LLMResponse:
        pass


class DeterministicAgentDouble(BaseLLMClient):
    """Deterministic model double for offline review and unit testing (AC6/AC7).

    Accurately simulates agentic tool-use:
    1. Turn 1: Chooses get_identity_context(actor_id=...).
    2. Turn 2: Inspects identity, chooses get_recent_auth_events(actor_id=...).
    3. Turn 3: Inspects events, formats structured recommendation referencing checkable evidence.
    """

    def generate(self, messages: list[LLMMessage], tools: list[dict[str, Any]]) -> LLMResponse:
        # Determine current agent state based on message history
        tool_results: dict[str, Any] = {}
        target_actor_id = None
        has_prompt_injection = False

        for msg in messages:
            if msg.role == "user" and msg.content:
                if "Ignore policy" in msg.content or "send credentials" in msg.content:
                    has_prompt_injection = True
                # Extract actor_id cleanly from prompt
                import re
                found_actors = re.findall(r"usr-[a-zA-Z0-9_\-]+", msg.content)
                if found_actors:
                    target_actor_id = found_actors[0]

            if msg.role == "tool" and msg.content:
                try:
                    parsed = json.loads(msg.content)
                    if "role" in parsed or "typical_countries" in parsed or "is_privileged" in parsed:
                        tool_results["identity"] = parsed
                    elif "events" in parsed or "total_events" in parsed:
                        tool_results["events"] = parsed
                except Exception:
                    pass

        # Step 1: If identity context not requested yet, call get_identity_context
        if "identity" not in tool_results:
            return LLMResponse(
                tool_calls=[
                    {
                        "id": "call_ident_001",
                        "type": "function",
                        "function": {
                            "name": "get_identity_context",
                            "arguments": json.dumps({"actor_id": target_actor_id or "usr-sec-prod-01"}),
                        },
                    }
                ]
            )

        # Step 2: If auth events not requested yet, call get_recent_auth_events
        if "events" not in tool_results:
            return LLMResponse(
                tool_calls=[
                    {
                        "id": "call_events_002",
                        "type": "function",
                        "function": {
                            "name": "get_recent_auth_events",
                            "arguments": json.dumps({"actor_id": target_actor_id or "usr-sec-prod-01"}),
                        },
                    }
                ]
            )

        # Step 3: Both tools returned. Synthesize evidence-backed structured recommendation
        identity = tool_results.get("identity", {})
        events_data = tool_results.get("events", {})
        events_list = events_data.get("events", [])

        evidence_refs: list[str] = []
        if identity.get("evidence_id"):
            evidence_refs.append(identity["evidence_id"])
        for ev in events_list:
            if ev.get("evidence_id"):
                evidence_refs.append(ev["evidence_id"])

        # Analyze evidence
        actor_id = identity.get("actor_id", target_actor_id)
        is_priv = identity.get("is_privileged", False)
        env = identity.get("environment", "unknown")
        typical_countries = identity.get("typical_countries", [])

        new_country_events = [
            e for e in events_list
            if e.get("status") == "SUCCESS" and e.get("country") not in typical_countries
        ]
        failed_events = [e for e in events_list if e.get("status") == "FAILURE"]

        uncertainties = []
        next_steps = []

        if has_prompt_injection:
            uncertainties.append(
                "Untrusted alert text contained prompt injection directives ('Ignore policy...'). "
                "Text was isolated as data and policy calculation was strictly preserved."
            )

        if not identity.get("found", True):
            explanation = f"Identity record for actor '{actor_id}' is unknown in local fixtures."
            uncertainties.append("Missing identity context prevents verifying authorization level.")
            next_steps.append("Verify actor record in directory service (Okta/Active Directory).")
            next_steps.append("Confirm if account is active or deprovisioned.")
        elif not events_list:
            explanation = f"No authentication event logs were found for actor '{actor_id}'."
            uncertainties.append("Absence of event telemetry leaves login details unverified.")
            next_steps.append("Inspect central SIEM authentication streams for pipeline delays.")
            next_steps.append("Contact identity owner to verify recent account activity.")
        elif new_country_events:
            ev0 = new_country_events[0]
            explanation = (
                f"Actor '{actor_id}' ({identity.get('role', 'User')}) in {env} "
                f"successfully authenticated from country '{ev0.get('country')}' "
                f"at {ev0.get('timestamp')}, which is outside their historical baseline {typical_countries}."
            )
            if is_priv and env.lower() == "production":
                uncertainties.append("Whether session was authorized international travel or credential compromise.")
                next_steps.append("Contact user via out-of-band communication (Signal/phone) to confirm travel.")
                next_steps.append("Review concurrent sessions and privileged IAM actions initiated from source IP.")
                next_steps.append("Evaluate temporary credential revocation pending user confirmation.")
            else:
                uncertainties.append("Unconfirmed whether user is connected via VPN or roaming.")
                next_steps.append("Verify user travel schedule with team manager.")
                next_steps.append("Review multi-factor authentication enrollment logs.")
        elif failed_events:
            explanation = (
                f"Actor '{actor_id}' experienced {len(failed_events)} failed authentication attempt(s) "
                f"from country '{failed_events[0].get('country')}' without a successful login."
            )
            uncertainties.append("Attacker access to valid password remains unproven; MFA may have blocked access.")
            next_steps.append("Monitor account for credential stuffing patterns or subsequent success.")
            next_steps.append("Verify password reset policies and account lockout status.")
        else:
            explanation = f"Authentication events for actor '{actor_id}' matched known historical baselines."
            uncertainties.append("Alert may represent false positive detection threshold.")
            next_steps.append("Review alert rule sensitivity parameters.")

        rec = ModelRecommendation(
            explanation=explanation,
            evidence_references=evidence_refs,
            uncertainties=uncertainties,
            recommended_next_steps=next_steps,
        )

        return LLMResponse(content=rec.model_dump_json())


class OpenAICompatibleClient(BaseLLMClient):
    """Client for real OpenAI-compatible LLM endpoints."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.api_key = settings.openai_api_key
        self.base_url = settings.openai_base_url.rstrip("/")
        self.model = settings.openai_model
        self.timeout = settings.llm_timeout_seconds

    def generate(self, messages: list[LLMMessage], tools: list[dict[str, Any]]) -> LLMResponse:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [m.to_dict() for m in messages],
            "temperature": 0.0,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, headers=headers, json=payload)
                if resp.status_code != 200:
                    raise InvalidModelOutputException(
                        f"Provider returned HTTP {resp.status_code}: {resp.text}"
                    )
                data = resp.json()
        except httpx.TimeoutException:
            raise ProviderTimeoutException(provider="OpenAI-Compatible", timeout=self.timeout)
        except Exception as e:
            if isinstance(e, TriageServiceException):
                raise
            raise InvalidModelOutputException(f"Network error calling LLM provider: {str(e)}")

        choices = data.get("choices", [])
        if not choices:
            raise InvalidModelOutputException("LLM provider returned empty choices list.")

        msg = choices[0].get("message", {})
        content = msg.get("content")
        tool_calls = msg.get("tool_calls", [])

        return LLMResponse(content=content, tool_calls=tool_calls)


def get_llm_client(settings: Settings) -> BaseLLMClient:
    """Factory creating LLM client based on configuration."""
    if settings.llm_mode == "real" and settings.openai_api_key:
        return OpenAICompatibleClient(settings)
    return DeterministicAgentDouble()
