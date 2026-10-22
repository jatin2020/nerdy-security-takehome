from fastapi.testclient import TestClient


def test_missing_api_token_returns_401(unauthenticated_client: TestClient):
    response = unauthenticated_client.post(
        "/triage",
        json={
            "alert_id": "alt-high-01",
            "actor_id": "usr-sec-prod-01",
            "alert_description": "Test alert",
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "UNAUTHORIZED"
    assert "Missing authentication token" in data["message"]


def test_invalid_api_token_returns_401(unauthenticated_client: TestClient):
    response = unauthenticated_client.post(
        "/triage",
        headers={"X-API-Token": "completely-invalid-secret-token"},
        json={
            "alert_id": "alt-high-01",
            "actor_id": "usr-sec-prod-01",
            "alert_description": "Test alert",
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"] == "UNAUTHORIZED"
    assert "Invalid authentication token" in data["message"]


def test_bearer_authorization_header_succeeds(unauthenticated_client: TestClient):
    from src.config import get_settings
    token = get_settings().triage_api_token

    response = unauthenticated_client.post(
        "/triage",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "alert_id": "alt-high-01",
            "actor_id": "usr-sec-prod-01",
            "alert_description": "Legitimate new country alert",
        },
    )
    assert response.status_code == 200
    assert response.json()["alert_id"] == "alt-high-01"


def test_health_check_does_not_require_auth(unauthenticated_client: TestClient):
    response = unauthenticated_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
