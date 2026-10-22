import json
import os
from functools import lru_cache
from typing import Any, Optional
from src.config import get_settings
from src.models import (
    ActorAlertMismatchException,
    AlertNotFoundException,
    AuthEvent,
    IdentityContext,
)


class FixturesStore:
    """Manages reading and querying of local synthetic fixtures."""

    def __init__(self, fixtures_dir: Optional[str] = None):
        settings = get_settings()
        self.fixtures_dir = fixtures_dir or settings.fixtures_dir
        self._alerts: dict[str, dict[str, Any]] = {}
        self._identities: dict[str, dict[str, Any]] = {}
        self._auth_events: dict[str, list[dict[str, Any]]] = {}
        self._load_fixtures()

    def _load_fixtures(self) -> None:
        alerts_path = os.path.join(self.fixtures_dir, "alerts.json")
        identities_path = os.path.join(self.fixtures_dir, "identities.json")
        events_path = os.path.join(self.fixtures_dir, "auth_events.json")

        if os.path.exists(alerts_path):
            with open(alerts_path, "r", encoding="utf-8") as f:
                self._alerts = json.load(f)

        if os.path.exists(identities_path):
            with open(identities_path, "r", encoding="utf-8") as f:
                self._identities = json.load(f)

        if os.path.exists(events_path):
            with open(events_path, "r", encoding="utf-8") as f:
                self._auth_events = json.load(f)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        """Fetch alert record by ID or raise AlertNotFoundException."""
        if alert_id not in self._alerts:
            raise AlertNotFoundException(alert_id)
        return self._alerts[alert_id]

    def validate_alert_actor(self, alert_id: str, requested_actor_id: str) -> None:
        """Verify that requested alert ID maps to the provided actor ID (AC5)."""
        alert = self.get_alert(alert_id)
        expected_actor = alert.get("actor_id")
        if expected_actor != requested_actor_id:
            raise ActorAlertMismatchException(
                alert_id=alert_id,
                requested_actor=requested_actor_id,
                actual_actor=expected_actor or "unknown",
            )

    def get_identity(self, actor_id: str) -> Optional[IdentityContext]:
        """Return IdentityContext if found, else None."""
        raw = self._identities.get(actor_id)
        if not raw:
            return None
        return IdentityContext.model_validate(raw)

    def get_auth_events(self, actor_id: str) -> list[AuthEvent]:
        """Return list of recent AuthEvents for actor_id."""
        raw_list = self._auth_events.get(actor_id, [])
        return [AuthEvent.model_validate(item) for item in raw_list]


@lru_cache
def get_fixtures_store() -> FixturesStore:
    """Singleton cached fixtures store."""
    return FixturesStore()
