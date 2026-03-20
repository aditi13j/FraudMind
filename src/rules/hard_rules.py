"""
Hard Rules -- P0 feedback layer.

Pure Python. No LLM. Runs before specialists in the graph.
Returns immediately on the first matching rule (order matters).

Rules are intentionally simple and binary. Each rule has a plain English
name that appears in ArbiterOutput.rule_name so analysts can aggregate
verdicts by rule without parsing free-text reasoning.

Rule order (most conclusive first):
    1. confirmed_ring   — ring signature match + confirmed fraud links
    2. known_bot        — TLS fingerprint + headless browser
    3. extreme_velocity — card testing burst (20+ txns/hr)
    4. trusted_account  — long-tenured, known device, home geo, normal spend
"""

from dataclasses import dataclass


@dataclass
class HardRuleResult:
    matched: bool
    rule_name: str   # empty string when matched=False
    verdict: str     # "block" | "allow" | "" when matched=False


def hard_rules_check(state: dict) -> HardRuleResult:
    """
    Evaluate hard rules against FraudState signals.

    Args:
        state: FraudState dict. Signal objects may be None if not provided.

    Returns:
        HardRuleResult with matched=True and the rule name/verdict on first
        match, or matched=False if no rule applies.
    """
    payload = state.get("payload_signals")
    ring    = state.get("ring_signals")
    payment = state.get("payment_signals")
    ato     = state.get("ato_signals")

    # confirmed_ring: entity is a known ring member with multiple fraud-confirmed
    # linked accounts. The combination of signature match + confirmed fraud links
    # is near-conclusive and requires no specialist scoring.
    if (ring is not None
            and ring.known_ring_signature_match
            and ring.linked_accounts_with_fraud_confirmed >= 2):
        return HardRuleResult(matched=True, rule_name="confirmed_ring", verdict="block")

    # known_bot: JA3 fingerprint matches a known automation tool AND the user
    # agent is headless. Two independent automation signals together remove
    # ambiguity around shared TLS libraries or spoofed user agents.
    if (payload is not None
            and payload.tls_fingerprint_known_bot
            and payload.user_agent_is_headless):
        return HardRuleResult(matched=True, rule_name="known_bot", verdict="block")

    # extreme_velocity: 20+ transactions in one hour is card testing regardless
    # of amount. No legitimate user produces this pattern.
    if payment is not None and payment.transactions_last_1h >= 20:
        return HardRuleResult(matched=True, rule_name="extreme_velocity", verdict="block")

    # trusted_account: account over 2 years old on a known device, in their
    # home geography, spending at or below their normal rate. All four
    # conditions must hold — any single anomaly exits this rule.
    if (ato is not None
            and payment is not None
            and ato.account_age_days > 730
            and not ato.is_new_device
            and not ato.geo_mismatch
            and payment.amount_vs_avg_ratio < 1.5):
        return HardRuleResult(matched=True, rule_name="trusted_account", verdict="allow")

    return HardRuleResult(matched=False, rule_name="", verdict="")
