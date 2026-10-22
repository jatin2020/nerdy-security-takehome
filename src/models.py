from enum import Enum
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyPriority(str, Enum):
    """Investigation priority assigned strictly by deterministic code policy (AC2)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEEDS_REVIEW = "needs_review"


class IdentityContext(BaseModel):
    """Normalized identity and asset context retrieved via tool."""

    model_config = ConfigDict(extra="ignore")

    actor_id: str
    username: str
    role: str
    is_privileged: bool
    environment: str
    owner: str
    affected_service: str
    typical_countries: list[str] = Field(default_factory=list)


class AuthEvent(BaseModel):
    """Normalized authentication event record retrieved via tool."""

    model_config = ConfigDict(extra="ignore")

    event_id: str
    actor_id: str
    timestamp: str
    status: Literal["SUCCESS", "FAILURE"]
    country: str
    ip_address: str
    mfa_evidence: dict[str, Any] = Field(default_factory=dict)
    failure_reason: Optional[str] = None
    user_agent: Optional[str] = None


class TriageRequest(BaseModel):
    """Payload for POST /triage."""

    alert_id: str = Field(..., min_length=1, max_length=128, description="Unique identifier of the alert")
    actor_id: str = Field(..., min_length=1, max_length=128, description="Identifier of the actor under review")
    alert_description: str = Field(..., min_length=1, max_length=4000, description="Raw alert text from detection system")

    @field_validator("alert_id", "actor_id")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("Field cannot be empty or whitespace only.")
        return s


class ModelRecommendation(BaseModel):
    """Structured output expected from the language model."""

    model_config = ConfigDict(extra="ignore")

    explanation: str = Field(..., description="Evidence-backed investigative narrative")
    evidence_references: list[str] = Field(default_factory=list, description="IDs of observed fixture/event evidence")
    uncertainties: list[str] = Field(default_factory=list, description="Visible gaps or ambiguities in evidence")
    recommended_next_steps: list[str] = Field(..., description="Actionable human investigation steps")


class TriageResponse(BaseModel):
    """Evidence-backed triage response (AC1)."""

    alert_id: str
    actor_id: str
    priority: PolicyPriority
    evidence_references: list[str]
    explanation: str
    uncertainties: list[str]
    recommended_next_steps: list[str]
    tools_invoked: list[str] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    """Controlled error representation without raw stack traces or internal secrets."""

    error: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


# Domain Exceptions
class TriageServiceException(Exception):
    """Base exception for triage service errors."""

    def __init__(self, message: str, code: str = "BAD_REQUEST", status_code: int = 400, details: Optional[dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}


class UnauthorizedException(TriageServiceException):
    def __init__(self, message: str = "Invalid or missing API token"):
        super().__init__(message, code="UNAUTHORIZED", status_code=401)


class AlertNotFoundException(TriageServiceException):
    def __init__(self, alert_id: str):
        super().__init__(
            message=f"Alert with ID '{alert_id}' was not found in fixture store.",
            code="ALERT_NOT_FOUND",
            status_code=404,
            details={"alert_id": alert_id},
        )


class ActorAlertMismatchException(TriageServiceException):
    def __init__(self, alert_id: str, requested_actor: str, actual_actor: str):
        super().__init__(
            message=f"Alert '{alert_id}' is associated with actor '{actual_actor}', not requested actor '{requested_actor}'.",
            code="ACTOR_ALERT_MISMATCH",
            status_code=422,
            details={"alert_id": alert_id, "requested_actor": requested_actor, "actual_actor": actual_actor},
        )


class EvidenceValidationException(TriageServiceException):
    def __init__(self, fabricated_references: list[str]):
        super().__init__(
            message="Model output referenced nonexistent or unobserved evidence IDs.",
            code="FABRICATED_EVIDENCE",
            status_code=422,
            details={"fabricated_references": fabricated_references},
        )


class InvalidModelOutputException(TriageServiceException):
    def __init__(self, reason: str, raw_output: Optional[str] = None):
        super().__init__(
            message=f"Model output failed validation or policy constraints: {reason}",
            code="INVALID_MODEL_OUTPUT",
            status_code=502,
            details={"reason": reason},
        )


class ToolExecutionException(TriageServiceException):
    def __init__(self, tool_name: str, reason: str):
        super().__init__(
            message=f"Tool '{tool_name}' execution failed: {reason}",
            code="TOOL_EXECUTION_ERROR",
            status_code=500,
            details={"tool_name": tool_name, "reason": reason},
        )


class ProviderTimeoutException(TriageServiceException):
    def __init__(self, provider: str, timeout: float):
        super().__init__(
            message=f"LLM provider '{provider}' timed out after {timeout} seconds.",
            code="PROVIDER_TIMEOUT",
            status_code=504,
            details={"provider": provider, "timeout_seconds": timeout},
        )
