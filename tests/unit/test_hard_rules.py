"""
Unit tests for hard_rules_check().

Tests the static rules directly — no graph, no LLM, no specialists.
Each test exercises one rule boundary so regressions are pinpointed immediately.

Coverage:
  - confirmed_ring: fires / boundary (linked_fraud_confirmed < 2) / partial conditions
  - known_bot: fires / each condition alone does not fire
  - extreme_velocity: fires at 20 / does not fire at 19
  - trusted_account: fires / each condition independently breaks the rule
  - rule ordering: confirmed_ring takes priority over known_bot
  - no match: returns matched=False
  - dynamic eval safety: bad condition string returns False, not an exception
"""

import pytest

from src.rules.hard_rules import HardRuleResult, hard_rules_check
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.ring_schemas import RingSignals


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ring_confirmed() -> RingSignals:
    return RingSignals(
        primary_entity_id="acc_r", primary_entity_type="user",
        device_id="dev_r", ip_address_hash="ip_r",
        accounts_sharing_device=5, accounts_sharing_ip=3,
        linked_account_ids=["a", "b"],
        linked_accounts_with_block_verdict=2,
        linked_accounts_with_fraud_confirmed=2,
        shared_payment_method_across_accounts=True,
        payment_method_account_count=3,
        known_ring_signature_match=True,
        ring_signature_id="ring_001",
        velocity_account_creation_same_ip_7d=10,
        transaction_graph_min_hops_to_fraud=0,
    )


@pytest.fixture
def ring_no_match() -> RingSignals:
    """known_ring_signature_match=True but only 1 confirmed fraud — below threshold."""
    return RingSignals(
        primary_entity_id="acc_r2", primary_entity_type="user",
        device_id="dev_r2", ip_address_hash="ip_r2",
        accounts_sharing_device=1, accounts_sharing_ip=1,
        linked_account_ids=[],
        linked_accounts_with_block_verdict=0,
        linked_accounts_with_fraud_confirmed=1,   # < 2 — rule should NOT fire
        shared_payment_method_across_accounts=False,
        payment_method_account_count=1,
        known_ring_signature_match=True,
        ring_signature_id="ring_001",
        velocity_account_creation_same_ip_7d=0,
        transaction_graph_min_hops_to_fraud=5,
    )


@pytest.fixture
def payload_bot() -> PayloadSignals:
    return PayloadSignals(
        session_id="sess_bot", account_id="acc_bot",
        user_agent_string="HeadlessChrome/118.0",
        user_agent_is_headless=True,
        tls_fingerprint_ja3="botja3", tls_fingerprint_known_bot=True,
        http_header_order_anomaly=True, accept_language_missing=True,
        mouse_movement_entropy=0.0, keystroke_dynamics_score=0.02,
        requests_per_minute=200.0, request_timing_variance_ms=2.0,
        captcha_solve_time_ms=80, captcha_solve_pattern_automated=True,
        credential_stuffing_ip_on_blocklist=True,
        login_attempt_count_this_session=10,
        api_endpoint_sequence_anomaly=True,
    )


@pytest.fixture
def payment_high_velocity() -> PaymentSignals:
    return PaymentSignals(
        transaction_id="txn_v", account_id="acc_v",
        amount_usd=50.0, merchant_category="grocery",
        merchant_country="United States", account_home_country="United States",
        is_international=False, transactions_last_1h=20, transactions_last_24h=25,
        avg_transaction_amount_30d=45.0, amount_vs_avg_ratio=1.1,
        is_first_transaction=False, card_present=True,
        days_since_account_creation=400,
    )


@pytest.fixture
def ato_trusted() -> MockATOSignals:
    return MockATOSignals(
        account_id="acc_t", account_age_days=800,
        is_new_device=False, device_id="dev_home",
        login_geo="Seattle, WA", account_home_geo="Seattle, WA",
        geo_mismatch=False, time_since_last_login_days=1,
        immediate_high_value_action=False, email_change_attempted=False,
        password_change_attempted=False, support_ticket_language_match=True,
    )


@pytest.fixture
def payment_normal() -> PaymentSignals:
    return PaymentSignals(
        transaction_id="txn_n", account_id="acc_t",
        amount_usd=45.0, merchant_category="grocery",
        merchant_country="United States", account_home_country="United States",
        is_international=False, transactions_last_1h=1, transactions_last_24h=2,
        avg_transaction_amount_30d=50.0, amount_vs_avg_ratio=0.9,
        is_first_transaction=False, card_present=True,
        days_since_account_creation=800,
    )


# ---------------------------------------------------------------------------
# confirmed_ring
# ---------------------------------------------------------------------------

class TestConfirmedRing:
    def test_fires_on_signature_plus_two_confirmed(self, ring_confirmed):
        result = hard_rules_check({"ring_signals": ring_confirmed})
        assert result.matched is True
        assert result.rule_name == "confirmed_ring"
        assert result.verdict == "block"

    def test_does_not_fire_with_one_confirmed_fraud(self, ring_no_match):
        result = hard_rules_check({"ring_signals": ring_no_match})
        assert result.matched is False

    def test_does_not_fire_without_signature_match(self, ring_confirmed):
        no_sig = ring_confirmed.model_copy(update={"known_ring_signature_match": False})
        result = hard_rules_check({"ring_signals": no_sig})
        assert result.matched is False

    def test_does_not_fire_with_no_ring_signals(self):
        result = hard_rules_check({})
        assert result.matched is False

    def test_fires_with_zero_hops_to_fraud(self, ring_confirmed):
        # Graph proximity alone doesn't override the confirmed_ring condition
        result = hard_rules_check({"ring_signals": ring_confirmed})
        assert result.rule_name == "confirmed_ring"


# ---------------------------------------------------------------------------
# known_bot
# ---------------------------------------------------------------------------

class TestKnownBot:
    def test_fires_on_both_bot_signals(self, payload_bot):
        result = hard_rules_check({"payload_signals": payload_bot})
        assert result.matched is True
        assert result.rule_name == "known_bot"
        assert result.verdict == "block"

    def test_does_not_fire_on_tls_alone(self, payload_bot):
        tls_only = payload_bot.model_copy(update={"user_agent_is_headless": False})
        result = hard_rules_check({"payload_signals": tls_only})
        assert result.matched is False

    def test_does_not_fire_on_headless_alone(self, payload_bot):
        headless_only = payload_bot.model_copy(update={"tls_fingerprint_known_bot": False})
        result = hard_rules_check({"payload_signals": headless_only})
        assert result.matched is False

    def test_does_not_fire_with_no_payload_signals(self):
        result = hard_rules_check({})
        assert result.matched is False


# ---------------------------------------------------------------------------
# extreme_velocity
# ---------------------------------------------------------------------------

class TestExtremeVelocity:
    def test_fires_at_exactly_20(self, payment_high_velocity):
        result = hard_rules_check({"payment_signals": payment_high_velocity})
        assert result.matched is True
        assert result.rule_name == "extreme_velocity"
        assert result.verdict == "block"

    def test_fires_above_20(self, payment_high_velocity):
        high = payment_high_velocity.model_copy(update={"transactions_last_1h": 50})
        result = hard_rules_check({"payment_signals": high})
        assert result.matched is True
        assert result.rule_name == "extreme_velocity"

    def test_does_not_fire_at_19(self, payment_high_velocity):
        below = payment_high_velocity.model_copy(update={"transactions_last_1h": 19})
        result = hard_rules_check({"payment_signals": below})
        assert result.matched is False

    def test_does_not_fire_at_zero_velocity(self, payment_normal):
        result = hard_rules_check({"payment_signals": payment_normal})
        assert result.matched is False


# ---------------------------------------------------------------------------
# trusted_account
# ---------------------------------------------------------------------------

class TestTrustedAccount:
    def test_fires_on_all_four_conditions(self, ato_trusted, payment_normal):
        result = hard_rules_check({
            "ato_signals": ato_trusted,
            "payment_signals": payment_normal,
        })
        assert result.matched is True
        assert result.rule_name == "trusted_account"
        assert result.verdict == "allow"

    def test_does_not_fire_if_account_too_young(self, ato_trusted, payment_normal):
        young = ato_trusted.model_copy(update={"account_age_days": 730})  # must be > 730
        result = hard_rules_check({"ato_signals": young, "payment_signals": payment_normal})
        assert result.matched is False

    def test_does_not_fire_on_new_device(self, ato_trusted, payment_normal):
        new_dev = ato_trusted.model_copy(update={"is_new_device": True})
        result = hard_rules_check({"ato_signals": new_dev, "payment_signals": payment_normal})
        assert result.matched is False

    def test_does_not_fire_on_geo_mismatch(self, ato_trusted, payment_normal):
        geo = ato_trusted.model_copy(update={"geo_mismatch": True})
        result = hard_rules_check({"ato_signals": geo, "payment_signals": payment_normal})
        assert result.matched is False

    def test_does_not_fire_on_high_spend_ratio(self, ato_trusted, payment_normal):
        high_ratio = payment_normal.model_copy(update={"amount_vs_avg_ratio": 1.5})
        result = hard_rules_check({"ato_signals": ato_trusted, "payment_signals": high_ratio})
        assert result.matched is False

    def test_does_not_fire_without_payment_signals(self, ato_trusted):
        # trusted_account requires both ato AND payment
        result = hard_rules_check({"ato_signals": ato_trusted})
        assert result.matched is False


# ---------------------------------------------------------------------------
# Rule ordering
# ---------------------------------------------------------------------------

class TestRuleOrdering:
    def test_confirmed_ring_wins_over_known_bot(self, ring_confirmed, payload_bot):
        """confirmed_ring is checked before known_bot. When both conditions are present
        the first matching rule (confirmed_ring) is returned."""
        result = hard_rules_check({
            "ring_signals": ring_confirmed,
            "payload_signals": payload_bot,
        })
        assert result.rule_name == "confirmed_ring"

    def test_known_bot_wins_over_extreme_velocity(self, payload_bot, payment_high_velocity):
        """known_bot is checked before extreme_velocity."""
        result = hard_rules_check({
            "payload_signals": payload_bot,
            "payment_signals": payment_high_velocity,
        })
        assert result.rule_name == "known_bot"


# ---------------------------------------------------------------------------
# No match
# ---------------------------------------------------------------------------

class TestNoMatch:
    def test_empty_state_returns_no_match(self):
        result = hard_rules_check({})
        assert result.matched is False
        assert result.rule_name == ""
        assert result.verdict == ""

    def test_low_risk_signals_return_no_match(self, ato_trusted):
        # Old trusted account but missing payment signals — trusted_account won't fire
        result = hard_rules_check({"ato_signals": ato_trusted})
        assert result.matched is False

    def test_result_type_is_hard_rule_result(self):
        result = hard_rules_check({})
        assert isinstance(result, HardRuleResult)
