"""
Hard Rules -- P0 feedback layer.

Pure Python. No LLM. Runs before specialists in the graph.
Returns immediately on the first matching rule (order matters).

Static rules are defined directly in this file (confirmed_ring, known_bot,
extreme_velocity, trusted_account). Dynamic rules are loaded from the
RulesStore at call time and evaluated in a sandboxed namespace — only the
six signal objects are in scope, no builtins, no imports.

Rule order: static rules first (most conclusive), then dynamic rules in
created_at order.
"""

from dataclasses import dataclass

from src.rules.rules_store import RulesStore

_rules_store = RulesStore()


@dataclass
class HardRuleResult:
    matched: bool
    rule_name: str   # empty string when matched=False
    verdict: str     # "block" | "allow" | "" when matched=False


def _eval_condition(condition: str, namespace: dict) -> bool:
    """
    Evaluate a condition string in a restricted namespace.

    builtins={} means no __import__, no open, no exec — only the
    signal variables supplied in namespace are accessible.
    Returns False on any exception so a bad rule never crashes the graph.
    """
    try:
        return bool(eval(condition, {"__builtins__": {}}, namespace))  # noqa: S307
    except Exception:
        return False


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

    # Dynamic rules from RulesStore — analyst-approved, zero .py file diff
    _namespace = {
        "ato":      ato,
        "payment":  payment,
        "ring":     ring,
        "payload":  payload,
        "identity": state.get("identity_signals"),
        "promo":    state.get("promo_signals"),
    }
    for rule in _rules_store.get_active_hard_rules():
        condition = rule.get("condition", "")
        verdict   = rule.get("verdict", "block")
        rule_name = rule.get("rule_name", "dynamic_rule")
        if condition and _eval_condition(condition, _namespace):
            return HardRuleResult(matched=True, rule_name=rule_name, verdict=verdict)

    return HardRuleResult(matched=False, rule_name="", verdict="")
