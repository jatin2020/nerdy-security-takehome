import pytest
from src.models import AuthEvent, IdentityContext, PolicyPriority
from src.policy import PriorityPolicyEngine


def test_privileged_prod_new_country_is_high_priority():
    identity = IdentityContext(
        actor_id="usr-1",
        username="lead.arch",
        role="Principal Architect",
        is_privileged=True,
        environment="production",
        owner="sec@example.com",
        affected_service="auth",
        typical_countries=["US", "CA"],
    )
    events = [
        AuthEvent(
            event_id="evt-1",
            actor_id="usr-1",
            timestamp="2026-10-22T08:00:00Z",
            status="SUCCESS",
            country="DE",  # Germany is not in US/CA -> new country
            ip_address="198.51.100.1",
        )
    ]
    p = PriorityPolicyEngine.calculate_priority(identity, events)
    assert p == PolicyPriority.HIGH


def test_nonprivileged_prod_new_country_is_medium_priority():
    identity = IdentityContext(
        actor_id="usr-2",
        username="student.sam",
        role="Student",
        is_privileged=False,
        environment="production",
        owner="support@example.com",
        affected_service="portal",
        typical_countries=["US"],
    )
    events = [
        AuthEvent(
            event_id="evt-2",
            actor_id="usr-2",
            timestamp="2026-10-22T08:00:00Z",
            status="SUCCESS",
            country="FR",  # New country
            ip_address="198.51.100.2",
        )
    ]
    p = PriorityPolicyEngine.calculate_priority(identity, events)
    assert p == PolicyPriority.MEDIUM


def test_failed_attempts_without_new_country_login_is_low_priority():
    identity = IdentityContext(
        actor_id="usr-3",
        username="analyst.pat",
        role="Analyst",
        is_privileged=False,
        environment="production",
        owner="analytics@example.com",
        affected_service="reporting",
        typical_countries=["US"],
    )
    events = [
        AuthEvent(
            event_id="evt-3a",
            actor_id="usr-3",
            timestamp="2026-10-22T07:00:00Z",
            status="FAILURE",
            country="RU",
            ip_address="203.0.113.10",
        ),
        AuthEvent(
            event_id="evt-3b",
            actor_id="usr-3",
            timestamp="2026-10-22T07:05:00Z",
            status="FAILURE",
            country="RU",
            ip_address="203.0.113.10",
        ),
    ]
    p = PriorityPolicyEngine.calculate_priority(identity, events)
    assert p == PolicyPriority.LOW


def test_unknown_identity_context_is_needs_review():
    events = [
        AuthEvent(
            event_id="evt-4",
            actor_id="usr-unknown",
            timestamp="2026-10-22T08:00:00Z",
            status="SUCCESS",
            country="DE",
            ip_address="198.51.100.4",
        )
    ]
    p = PriorityPolicyEngine.calculate_priority(identity=None, events=events)
    assert p == PolicyPriority.NEEDS_REVIEW


def test_insufficient_events_is_needs_review():
    identity = IdentityContext(
        actor_id="usr-5",
        username="dev.dan",
        role="Developer",
        is_privileged=True,
        environment="production",
        owner="dev@example.com",
        affected_service="api",
        typical_countries=["US"],
    )
    p = PriorityPolicyEngine.calculate_priority(identity=identity, events=[])
    assert p == PolicyPriority.NEEDS_REVIEW
