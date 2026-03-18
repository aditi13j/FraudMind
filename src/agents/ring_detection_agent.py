"""
Ring Detection Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes RingSignals, applies weighted rules, returns SpecialistScore.

This scorer always runs regardless of routing tier.
"""

from src.schemas.ring_schemas import RingSignals
from src.schemas.specialist_score import SpecialistScore


def score_ring(signals: RingSignals) -> SpecialistScore:
    """
    Score an entity for fraud ring membership and network-level risk.

    Weight rationale
    ----------------
    known_ring_signature_match (0.40)
        The highest-weight signal in the entire system. A match against a
        known ring signature means the entity's behavioral or structural
        fingerprint has been previously confirmed as fraudulent. This alone
        brings the score above most block thresholds. No single clean signal
        can meaningfully offset this.

    confirmed_fraud_in_graph (up to 0.25)
        Linked accounts with confirmed fraud (chargebacks, manual review)
        are direct evidence of shared-ring operation. Graduated:
        >= 3 = 0.25, >= 2 = 0.18, >= 1 = 0.12.

    graph_proximity_to_fraud (up to 0.15)
        Short path in the transaction graph to a confirmed fraud node.
        0 hops (direct) = 0.15, 1 hop = 0.10, 2 hops = 0.05.
        3+ hops is too weak to score.

    accounts_sharing_device (up to 0.10)
        A device shared by many accounts is a factory signal. Fraudsters
        use the same device or emulator to create accounts at scale.
        >= 10 = 0.10, >= 5 = 0.07, >= 3 = 0.04.

    linked_blocks (up to 0.08)
        Linked accounts carrying active block verdicts are part of the
        same cluster and reflect current, not historical, fraud activity.
        >= 3 = 0.08, >= 1 = 0.04.

    ip_creation_velocity (up to 0.07)
        High account-creation velocity from the same IP in 7 days is an
        account factory signal. >= 10 = 0.07, >= 5 = 0.05, >= 3 = 0.03.

    accounts_sharing_ip (up to 0.05)
        IP sharing alone is weaker than device sharing (NAT, VPNs, shared
        wifi are legitimate). Graduated: >= 10 = 0.05, >= 5 = 0.03.

    shared_payment_method (up to 0.04)
        A payment method appearing on multiple accounts is a linking signal.
        payment_method_account_count >= 3 = 0.04, >= 2 = 0.02.
    """
    contributions: list[tuple[str, float]] = []

    if signals.known_ring_signature_match:
        contributions.append(("known_ring_signature_match", 0.40))

    # Confirmed fraud in linked accounts -- graduated
    confirmed = signals.linked_accounts_with_fraud_confirmed
    if confirmed >= 3:
        contributions.append(("confirmed_fraud_in_graph", 0.25))
    elif confirmed >= 2:
        contributions.append(("confirmed_fraud_in_graph", 0.18))
    elif confirmed >= 1:
        contributions.append(("confirmed_fraud_in_graph", 0.12))

    # Graph proximity to confirmed fraud -- graduated
    hops = signals.transaction_graph_min_hops_to_fraud
    if hops == 0:
        contributions.append(("graph_proximity_to_fraud", 0.15))
    elif hops == 1:
        contributions.append(("graph_proximity_to_fraud", 0.10))
    elif hops == 2:
        contributions.append(("graph_proximity_to_fraud", 0.05))

    # Device sharing -- graduated
    dev = signals.accounts_sharing_device
    if dev >= 10:
        contributions.append(("accounts_sharing_device", 0.10))
    elif dev >= 5:
        contributions.append(("accounts_sharing_device", 0.07))
    elif dev >= 3:
        contributions.append(("accounts_sharing_device", 0.04))

    # Linked accounts with block verdict -- graduated
    blocks = signals.linked_accounts_with_block_verdict
    if blocks >= 3:
        contributions.append(("linked_blocks", 0.08))
    elif blocks >= 1:
        contributions.append(("linked_blocks", 0.04))

    # Account creation velocity -- graduated
    vel = signals.velocity_account_creation_same_ip_7d
    if vel >= 10:
        contributions.append(("ip_creation_velocity", 0.07))
    elif vel >= 5:
        contributions.append(("ip_creation_velocity", 0.05))
    elif vel >= 3:
        contributions.append(("ip_creation_velocity", 0.03))

    # IP sharing -- graduated
    ip_share = signals.accounts_sharing_ip
    if ip_share >= 10:
        contributions.append(("accounts_sharing_ip", 0.05))
    elif ip_share >= 5:
        contributions.append(("accounts_sharing_ip", 0.03))

    # Shared payment method -- graduated
    pm_count = signals.payment_method_account_count
    if pm_count >= 3:
        contributions.append(("shared_payment_method", 0.04))
    elif pm_count >= 2:
        contributions.append(("shared_payment_method", 0.02))

    total_signals = 8
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
