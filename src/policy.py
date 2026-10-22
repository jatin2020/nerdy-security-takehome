from typing import Optional
from src.models import AuthEvent, IdentityContext, PolicyPriority


class PriorityPolicyEngine:
    """Enforces deterministic triage prioritization via ordinary application code (AC2).

    The language model CANNOT override or lower this calculation.
    """

    @staticmethod
    def calculate_priority(
        identity: Optional[IdentityContext],
        events: list[AuthEvent],
    ) -> PolicyPriority:
        """Calculate investigation priority according to strict AC2 rules.

        Rules:
        - high: Successful new-country login for a privileged production identity.
        - medium: Another successful new-country login.
        - low: Failed attempts without a successful new-country login.
        - needs_review: Unknown identity context or insufficient events; never invent low-risk.
        """
        # Rule: Unknown identity context or insufficient events -> needs_review
        if not identity:
            return PolicyPriority.NEEDS_REVIEW

        if not events or len(events) == 0:
            return PolicyPriority.NEEDS_REVIEW

        typical_countries = set(c.upper() for c in identity.typical_countries)

        # Identify successful logins from new countries
        successful_new_country_events = [
            e for e in events
            if e.status == "SUCCESS" and e.country.upper() not in typical_countries
        ]

        if successful_new_country_events:
            is_priv_prod = (
                identity.is_privileged is True
                and identity.environment.lower() == "production"
            )
            if is_priv_prod:
                return PolicyPriority.HIGH
            else:
                return PolicyPriority.MEDIUM

        # Rule: Failed attempts without a successful new-country login -> low
        failed_attempts = [e for e in events if e.status == "FAILURE"]
        if failed_attempts:
            return PolicyPriority.LOW

        # If no new-country logins and no failures, but events exist, check if baseline
        # is sufficient or if unexpected state requires human review
        return PolicyPriority.NEEDS_REVIEW
