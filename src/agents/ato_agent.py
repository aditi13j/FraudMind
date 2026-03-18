"""
ATO Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes MockATOSignals, applies weighted rules, returns SpecialistScore.
"""

from src.schemas.ato_schemas import MockATOSignals
from src.schemas.specialist_score import SpecialistScore


def score_ato(signals: MockATOSignals) -> SpecialistScore:
    """
    Score a login session for Account Takeover risk.

    Weight rationale
    ----------------
    is_new_device (0.25)
        The single strongest ATO indicator. Fraudsters always operate from
        devices the victim has never used. No legitimate explanation reduces
        this weight.

    geo_mismatch (0.20)
        Login from a country or region inconsistent with account history.
        Combined with a new device this approaches certainty.

    email_change_attempted (0.20)
        The goal of most ATOs is credential takeover. An email change attempt
        within the same session as a new-device login is near-conclusive.

    immediate_high_value_action (0.15)
        Fraudsters move fast to extract value before detection. A payout,
        booking, or large purchase within 5 minutes of login is a strong
        urgency signal.

    password_change_attempted (0.10)
        Like email change, but weighted slightly lower because legitimate
        users also reset passwords after account recovery.

    support_ticket_language_mismatch (0.05)
        Writing style inconsistency is a soft signal -- useful corroboration
        but too noisy to carry heavy weight alone.

    dormant_account_reactivated (0.05)
        An account inactive for 30+ days suddenly logging in with other risk
        signals present is consistent with credential-stuffing use of old
        leaked passwords.
    """
    contributions: list[tuple[str, float]] = []

    if signals.is_new_device:
        contributions.append(("is_new_device", 0.25))

    if signals.geo_mismatch:
        contributions.append(("geo_mismatch", 0.20))

    if signals.email_change_attempted:
        contributions.append(("email_change_attempted", 0.20))

    if signals.immediate_high_value_action:
        contributions.append(("immediate_high_value_action", 0.15))

    if signals.password_change_attempted:
        contributions.append(("password_change_attempted", 0.10))

    if not signals.support_ticket_language_match:
        contributions.append(("support_ticket_language_mismatch", 0.05))

    if signals.time_since_last_login_days > 30:
        contributions.append(("dormant_account_reactivated", 0.05))

    total_signals = 7
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
