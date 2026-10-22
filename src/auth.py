import hmac
from typing import Optional
from fastapi import Header, Request
from src.config import get_settings
from src.models import UnauthorizedException


def extract_token_from_header(
    x_api_token: Optional[str] = Header(None, alias="X-API-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Optional[str]:
    """Extract token from either X-API-Token header or Authorization: Bearer <token>."""
    if x_api_token:
        return x_api_token.strip()

    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        elif len(parts) == 1:
            return parts[0].strip()

    return None


def verify_api_token(request: Request) -> str:
    """Dependency that validates shared secret API token against configured secret."""
    settings = get_settings()
    configured_token = settings.triage_api_token.strip()

    x_api_token = request.headers.get("X-API-Token")
    authorization = request.headers.get("Authorization")

    provided_token = extract_token_from_header(x_api_token, authorization)

    if not provided_token:
        raise UnauthorizedException("Missing authentication token. Provide header 'X-API-Token' or 'Authorization: Bearer <token>'.")

    # Constant time comparison to prevent timing side channels
    if not hmac.compare_digest(provided_token.encode("utf-8"), configured_token.encode("utf-8")):
        raise UnauthorizedException("Invalid authentication token.")

    return provided_token
