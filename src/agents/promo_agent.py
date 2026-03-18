"""
Promo Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes PromoSignals, applies weighted rules, returns SpecialistScore.
"""

from src.schemas.promo_schemas import PromoSignals
from src.schemas.specialist_score import SpecialistScore


def score_promo(signals: PromoSignals) -> SpecialistScore:
    """
    Score a promo redemption for incentive abuse risk.

    Weight rationale
    ----------------
    device_shared_with_referrer (0.30)
        The clearest self-referral signal. Two accounts sharing a device
        and a referral relationship are overwhelmingly operated by the same
        person. Near-conclusive on its own.

    payout_requested_immediately (0.25)
        Requesting a payout or credit export within 10 minutes of promo
        redemption is the canonical cancel-after-export pattern. Legitimate
        users explore the platform; fraudsters extract value and leave.

    order_cancelled_after_promo (0.20)
        Prior orders cancelled post-redemption is historical evidence of
        the same pattern. Multiple occurrences on one account are definitive.

    accounts_linked_same_device (up to 0.12)
        Multiple accounts using this promo code from the same device reveals
        an organized ring, not coincidence. Graduated:
        >= 5 = 0.12, >= 3 = 0.08, >= 2 = 0.04.

    new_account_high_promo_use (0.08)
        Account under 7 days old with more than 3 promo uses is created
        specifically to exploit incentives, not to use the platform.

    email_domain_pattern_suspicious (0.06)
        Synthetic email variation patterns (user+1@, user+2@) reveal
        deliberate account farm construction.

    young_referrer_account (0.05)
        A referrer account under 14 days old has not established legitimacy.
        Combined with device sharing, this confirms a self-referral ring.

    promo_uses_same_code (up to 0.04)
        Using the same specific code more than once suggests probing or
        systematic abuse rather than accidental re-use.
        >= 3 = 0.04, >= 2 = 0.02.
    """
    contributions: list[tuple[str, float]] = []

    if signals.device_shared_with_referrer:
        contributions.append(("device_shared_with_referrer", 0.30))

    if signals.payout_requested_immediately:
        contributions.append(("payout_requested_immediately", 0.25))

    if signals.order_cancelled_after_promo:
        contributions.append(("order_cancelled_after_promo", 0.20))

    # Device clustering -- graduated
    dev = signals.accounts_linked_same_device
    if dev >= 5:
        contributions.append(("accounts_linked_same_device", 0.12))
    elif dev >= 3:
        contributions.append(("accounts_linked_same_device", 0.08))
    elif dev >= 2:
        contributions.append(("accounts_linked_same_device", 0.04))

    if signals.account_age_days < 7 and signals.promo_uses_this_account > 3:
        contributions.append(("new_account_high_promo_use", 0.08))

    if signals.email_domain_pattern_suspicious:
        contributions.append(("email_domain_pattern_suspicious", 0.06))

    ref_age = signals.referrer_account_age_days
    if ref_age is not None and ref_age < 14:
        contributions.append(("young_referrer_account", 0.05))

    # Repeat use of same code -- graduated
    same_code = signals.promo_uses_same_code
    if same_code >= 3:
        contributions.append(("promo_uses_same_code", 0.04))
    elif same_code >= 2:
        contributions.append(("promo_uses_same_code", 0.02))

    total_signals = 8
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
