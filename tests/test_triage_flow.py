from fastapi.testclient import TestClient


def test_triage_flow_high_priority_case(client: TestClient):
    """Case 1: Privileged production identity with successful new-country login -> HIGH priority."""
    payload = {
        "alert_id": "alt-high-01",
        "actor_id": "usr-sec-prod-01",
        "alert_description": "New country login detected for alex.chen from Germany (DE).",
    }
    response = client.post("/triage", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["alert_id"] == "alt-high-01"
    assert data["actor_id"] == "usr-sec-prod-01"
    assert data["priority"] == "high"
    assert "identity:usr-sec-prod-01" in data["evidence_references"]
    assert "event:evt-1001" in data["evidence_references"]
    assert len(data["recommended_next_steps"]) > 0
    assert len(data["tools_invoked"]) >= 2


def test_triage_flow_low_priority_case(client: TestClient):
    """Case 2: Nonprivileged identity with failed attempts only -> LOW priority."""
    payload = {
        "alert_id": "alt-low-02",
        "actor_id": "usr-student-02",
        "alert_description": "Multiple failed logins from Russia (RU).",
    }
    response = client.post("/triage", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["alert_id"] == "alt-low-02"
    assert data["actor_id"] == "usr-student-02"
    assert data["priority"] == "low"
    assert "identity:usr-student-02" in data["evidence_references"]
    assert "event:evt-2001" in data["evidence_references"]


def test_triage_flow_medium_priority_case(client: TestClient):
    """Case 3: Nonprivileged identity with successful new-country login -> MEDIUM priority."""
    payload = {
        "alert_id": "alt-medium-04",
        "actor_id": "usr-tutor-04",
        "alert_description": "New country login detected for sam.martinez from Brazil (BR).",
    }
    response = client.post("/triage", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["alert_id"] == "alt-medium-04"
    assert data["actor_id"] == "usr-tutor-04"
    assert data["priority"] == "medium"
    assert "identity:usr-tutor-04" in data["evidence_references"]
    assert "event:evt-4001" in data["evidence_references"]


def test_triage_flow_missing_events_is_needs_review(client: TestClient):
    """Case 4: Identity with no events -> NEVER invent low-risk, assign NEEDS_REVIEW (AC2)."""
    payload = {
        "alert_id": "alt-missing-05",
        "actor_id": "usr-no-events-05",
        "alert_description": "Login anomaly flagged, but zero telemetry records found.",
    }
    response = client.post("/triage", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["alert_id"] == "alt-missing-05"
    assert data["actor_id"] == "usr-no-events-05"
    assert data["priority"] == "needs_review"
    assert len(data["uncertainties"]) > 0
