"""
Identity Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes IdentitySignals, applies weighted rules, returns SpecialistScore.
"""

from src.schemas.identity_schemas import IdentitySignals
from src.schemas.specialist_score import SpecialistScore


def score_identity(signals: IdentitySignals) -> SpecialistScore:
    """
    Score an account for synthetic identity and fake account creation risk.

    Weight rationale
    ----------------
    pii_seen_on_other_accounts (up to 0.25)
        PII reuse across accounts is the clearest synthetic identity signal.
        Legitimate people have unique PII. Graduated:
        >= 5 = 0.25, >= 3 = 0.18, >= 1 = 0.10.

    not document_verification_passed (0.20)
        A real person can always produce a real document. Failure here
        directly contradicts legitimacy. High weight, no graduation needed.

    is_disposable_email (0.15)
        Disposable email domains are a deliberate choice to avoid identity
        tracing. Combined with any other signal, this is highly indicative.

    name_dob_mismatch (0.15)
        Name and date-of-birth inconsistency implies fabricated credentials.
        Cannot happen accidentally for a real person entering their own data.

    accounts_created_from_same_device (up to 0.10)
        A device used to create many accounts is a factory signal. Graduated:
        >= 10 = 0.10, >= 5 = 0.07, >= 3 = 0.04.

    signup_velocity_same_ip_24h (up to 0.08)
        High signup velocity from the same IP in 24 hours reveals coordinated
        account manufacturing. Graduated: >= 5 = 0.08, >= 3 = 0.05.

    not phone_country_matches_ip_country (0.05)
        Country mismatch between phone and signup IP is a soft signal --
        common in fraud but also occurs with travellers using foreign SIMs.

    address_is_commercial (0.02)
        A UPS store or virtual mailbox address is a weak standalone signal
        but corroborates synthetic identity when combined with stronger ones.
    """
    contributions: list[tuple[str, float]] = []

    # PII reuse -- graduated
    pii = signals.pii_seen_on_other_accounts
    if pii >= 5:
        contributions.append(("pii_seen_on_other_accounts", 0.25))
    elif pii >= 3:
        contributions.append(("pii_seen_on_other_accounts", 0.18))
    elif pii >= 1:
        contributions.append(("pii_seen_on_other_accounts", 0.10))

    if not signals.document_verification_passed:
        contributions.append(("document_verification_failed", 0.20))

    if signals.is_disposable_email:
        contributions.append(("is_disposable_email", 0.15))

    if signals.name_dob_mismatch:
        contributions.append(("name_dob_mismatch", 0.15))

    # Device factory -- graduated
    dev = signals.accounts_created_from_same_device
    if dev >= 10:
        contributions.append(("accounts_created_from_same_device", 0.10))
    elif dev >= 5:
        contributions.append(("accounts_created_from_same_device", 0.07))
    elif dev >= 3:
        contributions.append(("accounts_created_from_same_device", 0.04))

    # Signup velocity -- graduated
    vel = signals.signup_velocity_same_ip_24h
    if vel >= 5:
        contributions.append(("signup_velocity_same_ip_24h", 0.08))
    elif vel >= 3:
        contributions.append(("signup_velocity_same_ip_24h", 0.05))

    if not signals.phone_country_matches_ip_country:
        contributions.append(("phone_country_ip_country_mismatch", 0.05))

    if signals.address_is_commercial:
        contributions.append(("address_is_commercial", 0.02))

    total_signals = 8
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
