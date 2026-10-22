import os
from functools import lru_cache
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for Security Triage Service."""

    project_name: str = "Security Triage Service"
    version: str = "1.0.0"

    # API Token Authentication (Shared secret)
    # Default is provided for easy local review; in production set via TRIAGE_API_TOKEN
    triage_api_token: str = "sec-token-nerdy-local-2026"
    api_token_header_name: str = "X-API-Token"

    # LLM Settings
    llm_mode: Literal["mock", "real"] = "mock"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 15.0
    max_agent_turns: int = 4

    # Fixtures location
    fixtures_dir: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
