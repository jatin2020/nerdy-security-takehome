from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import Depends, FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.auth import verify_api_token
from src.config import Settings, get_settings
from src.fixtures_loader import get_fixtures_store
from src.llm import get_llm_client
from src.models import (
    ActorAlertMismatchException,
    AlertNotFoundException,
    EvidenceValidationException,
    InvalidModelOutputException,
    ProviderTimeoutException,
    ToolExecutionException,
    TriageRequest,
    TriageResponse,
    TriageServiceException,
    UnauthorizedException,
)
from src.policy import PriorityPolicyEngine
from src.agent import TriageAgent
from src.tools import get_tool_registry

settings = get_settings()
HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Warm up fixture stores and verify local environment on startup."""
    get_fixtures_store()
    yield


app = FastAPI(
    title=settings.project_name,
    version=settings.version,
    description=(
        "Production-grade security triage service that gathers identity and authentication evidence "
        "for anomalous new-country login alerts, calculates deterministic investigation priorities, "
        "and uses bounded agentic tool-use to recommend human next steps."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


# Exception Handlers (Controlled failure responses without secrets or raw stack traces)
@app.exception_handler(UnauthorizedException)
async def unauthorized_handler(request: Request, exc: UnauthorizedException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(AlertNotFoundException)
async def alert_not_found_handler(request: Request, exc: AlertNotFoundException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(ActorAlertMismatchException)
async def mismatch_handler(request: Request, exc: ActorAlertMismatchException) -> JSONResponse:
    return JSONResponse(
        status_code=HTTP_422,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(EvidenceValidationException)
async def evidence_validation_handler(request: Request, exc: EvidenceValidationException) -> JSONResponse:
    return JSONResponse(
        status_code=HTTP_422,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(InvalidModelOutputException)
async def invalid_model_output_handler(request: Request, exc: InvalidModelOutputException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_502_BAD_GATEWAY,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(ProviderTimeoutException)
async def provider_timeout_handler(request: Request, exc: ProviderTimeoutException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_504_GATEWAY_TIMEOUT,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(ToolExecutionException)
async def tool_execution_handler(request: Request, exc: ToolExecutionException) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(TriageServiceException)
async def triage_domain_handler(request: Request, exc: TriageServiceException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "message": exc.message, "details": exc.details},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(e) for e in err.get("loc", []))
        errors.append({"field": loc, "issue": err.get("msg")})
    return JSONResponse(
        status_code=HTTP_422,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Malformed request payload. Check 'details' for field-level issues.",
            "details": {"validation_errors": errors},
        },
    )


@app.exception_handler(Exception)
async def global_fallback_handler(request: Request, exc: Exception) -> JSONResponse:
    # Controlled fallback: never leak raw stack traces or internal secrets (AC5)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected server error occurred during alert triage. Check server logs.",
            "details": {},
        },
    )


# System Endpoints
@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    """Service health check endpoint."""
    return {
        "status": "healthy",
        "service": settings.project_name,
        "version": settings.version,
        "llm_mode": settings.llm_mode,
    }


# Core Triage Endpoint
@app.post(
    "/triage",
    response_model=TriageResponse,
    status_code=status.HTTP_200_OK,
    tags=["Security Triage"],
    summary="Triage an anomalous login alert",
    description=(
        "Collects identity and auth events via read-only tools, applies deterministic policy "
        "to compute investigation priority, and uses bounded agentic LLM analysis to suggest next steps."
    ),
)
def triage_alert(
    request: TriageRequest,
    _auth_token: str = Depends(verify_api_token),
) -> TriageResponse:
    app_settings = get_settings()
    fixtures_store = get_fixtures_store()
    tool_registry = get_tool_registry()
    llm_client = get_llm_client(app_settings)

    agent = TriageAgent(
        llm_client=llm_client,
        tool_registry=tool_registry,
        fixtures_store=fixtures_store,
        settings=app_settings,
    )

    return agent.triage_alert(request)
