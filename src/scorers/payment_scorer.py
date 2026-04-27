"""
Payment Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes PaymentSignals, applies weighted rules, returns SpecialistScore.
"""

from src.schemas.payment_schemas import PaymentSignals
from src.schemas.specialist_score import SpecialistScore

_HIGH_RISK_CATEGORIES = {"cryptocurrency", "wire_transfer", "gift_cards", "gaming_topup"}
_MEDIUM_RISK_CATEGORIES = {"electronics", "luxury", "travel"}


def score_payment(signals: PaymentSignals) -> SpecialistScore:
    """
    Score a transaction for payment fraud risk.

    Weight rationale
    ----------------
    amount_vs_avg_ratio (up to 0.25)
        The most reliable single fraud signal in payment data. Fraudsters
        using stolen cards maximize spend immediately. Graduated:
        >= 10x = 0.25, >= 5x = 0.18, >= 3x = 0.12, >= 2x = 0.06.

    velocity_last_1h (up to 0.20)
        Card testing and rapid spend-out produce bursts within one hour.
        Graduated: >= 10 = 0.20, >= 7 = 0.14, >= 5 = 0.08, >= 3 = 0.04.

    is_international (0.15)
        Cross-border card-not-present transactions have significantly higher
        fraud rates. Combined with amount anomaly this is a strong pair.

    not card_present (0.10)
        Card-not-present (online) transactions can't verify the physical card.
        Lower weight than amount because CNP is common in legitimate e-commerce.

    new_account (0.10)
        Accounts under 30 days old have not established spending patterns.
        Fraudsters create throwaway accounts to burn stolen card details.

    is_first_transaction (0.10)
        The first transaction on any account is the highest-risk moment.
        There is no baseline to compare against.

    merchant_category_risk (0.05 or 0.10)
        High-risk categories (crypto, gift cards, wire transfer, gaming topups)
        are preferred by fraudsters for their liquidity and irreversibility.
        Medium-risk categories (electronics, luxury, travel) carry a lower premium.
    """
    contributions: list[tuple[str, float]] = []

    # Amount vs average ratio -- graduated
    ratio = signals.amount_vs_avg_ratio
    if ratio >= 10:
        contributions.append(("amount_vs_avg_ratio", 0.25))
    elif ratio >= 5:
        contributions.append(("amount_vs_avg_ratio", 0.18))
    elif ratio >= 3:
        contributions.append(("amount_vs_avg_ratio", 0.12))
    elif ratio >= 2:
        contributions.append(("amount_vs_avg_ratio", 0.06))

    # Velocity in last hour -- graduated
    v1h = signals.transactions_last_1h
    if v1h >= 10:
        contributions.append(("velocity_last_1h", 0.20))
    elif v1h >= 7:
        contributions.append(("velocity_last_1h", 0.14))
    elif v1h >= 5:
        contributions.append(("velocity_last_1h", 0.08))
    elif v1h >= 3:
        contributions.append(("velocity_last_1h", 0.04))

    if signals.is_international:
        contributions.append(("is_international", 0.15))

    if not signals.card_present:
        contributions.append(("card_not_present", 0.10))

    if signals.days_since_account_creation < 30:
        contributions.append(("new_account", 0.10))

    if signals.is_first_transaction:
        contributions.append(("is_first_transaction", 0.10))

    cat = signals.merchant_category.lower()
    if cat in _HIGH_RISK_CATEGORIES:
        contributions.append(("high_risk_merchant_category", 0.10))
    elif cat in _MEDIUM_RISK_CATEGORIES:
        contributions.append(("medium_risk_merchant_category", 0.05))

    total_signals = 7
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
