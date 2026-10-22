from typing import Any, Callable
from src.fixtures_loader import FixturesStore, get_fixtures_store
from src.models import ToolExecutionException

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_identity_context",
            "description": "Retrieves identity role, privilege level, deployment environment, asset owner, and affected service for an actor ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor_id": {
                        "type": "string",
                        "description": "Unique actor identifier (e.g. usr-sec-prod-01)",
                    }
                },
                "required": ["actor_id"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_recent_auth_events",
            "description": "Retrieves recent authentication events including status (SUCCESS/FAILURE), MFA evidence, timestamps, and observed countries for an actor ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "actor_id": {
                        "type": "string",
                        "description": "Unique actor identifier (e.g. usr-sec-prod-01)",
                    }
                },
                "required": ["actor_id"],
                "additionalProperties": False,
            },
        },
    },
]


class ToolRegistry:
    """Strict allowlist registry for read-only investigative tools."""

    def __init__(self, store: FixturesStore):
        self.store = store
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "get_identity_context": self._execute_get_identity_context,
            "get_recent_auth_events": self._execute_get_recent_auth_events,
        }

    def execute_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Validate tool name against strict allowlist and execute with validated parameters."""
        if tool_name not in self._tools:
            raise ToolExecutionException(
                tool_name=tool_name,
                reason=f"Tool '{tool_name}' is not in the authorized read-only allowlist.",
            )

        handler = self._tools[tool_name]
        return handler(arguments)

    def _execute_get_identity_context(self, arguments: dict[str, Any]) -> dict[str, Any]:
        actor_id = arguments.get("actor_id")
        if not actor_id or not isinstance(actor_id, str):
            raise ToolExecutionException("get_identity_context", "Missing or invalid 'actor_id' argument.")

        identity = self.store.get_identity(actor_id.strip())
        if not identity:
            return {
                "found": False,
                "actor_id": actor_id,
                "message": f"Identity context not found for actor '{actor_id}'.",
            }

        return {
            "found": True,
            "evidence_id": f"identity:{identity.actor_id}",
            "actor_id": identity.actor_id,
            "username": identity.username,
            "role": identity.role,
            "is_privileged": identity.is_privileged,
            "environment": identity.environment,
            "owner": identity.owner,
            "affected_service": identity.affected_service,
            "typical_countries": identity.typical_countries,
        }

    def _execute_get_recent_auth_events(self, arguments: dict[str, Any]) -> dict[str, Any]:
        actor_id = arguments.get("actor_id")
        if not actor_id or not isinstance(actor_id, str):
            raise ToolExecutionException("get_recent_auth_events", "Missing or invalid 'actor_id' argument.")

        events = self.store.get_auth_events(actor_id.strip())
        event_dicts = []
        for e in events:
            event_dicts.append({
                "evidence_id": f"event:{e.event_id}",
                "event_id": e.event_id,
                "timestamp": e.timestamp,
                "status": e.status,
                "country": e.country,
                "ip_address": e.ip_address,
                "mfa_evidence": e.mfa_evidence,
                "failure_reason": e.failure_reason,
            })

        return {
            "actor_id": actor_id,
            "total_events": len(event_dicts),
            "events": event_dicts,
        }


def get_tool_registry() -> ToolRegistry:
    return ToolRegistry(get_fixtures_store())
