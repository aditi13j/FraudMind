"""
End-to-end integration tests for the FraudMind LangGraph pipeline.

Two execution paths are tested:

  Hard rules path  — a hard rule matches in hard_rules_node; graph short-circuits
                     to END without running specialists, aggregation, or the arbiter.

  Scoring path     — no hard rule matches; specialists run, risk aggregation
                     produces a RiskVector, and the arbiter issues a verdict.

All cases are designed to hit deterministic paths (no LLM calls).
"""

import pytest

from src.graph.fraud_graph import fraud_graph
from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.risk_vector import RiskVector
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.ring_schemas import RingSignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.promo_schemas import PromoSignals


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def confirmed_ring_state() -> dict:
    """
    Hard rule: confirmed_ring.
    known_ring_signature_match=True + linked_accounts_with_fraud_confirmed=3.
    Graph short-circuits before any specialist runs.
    """
    return {
        "primary_entity_id": "acc_ring_hr_001",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ring_signals": RingSignals(
            primary_entity_id="acc_ring_hr_001",
            primary_entity_type="user",
            device_id="dev_factory_01",
            ip_address_hash="hash_ring_001",
            accounts_sharing_device=22,
            accounts_sharing_ip=15,
            linked_account_ids=["acc_r2", "acc_r3", "acc_r4"],
            linked_accounts_with_block_verdict=3,
            linked_accounts_with_fraud_confirmed=3,
            shared_payment_method_across_accounts=True,
            payment_method_account_count=8,
            known_ring_signature_match=True,
            ring_signature_id="ring_WEST_AFRICA_001",
            velocity_account_creation_same_ip_7d=20,
            transaction_graph_min_hops_to_fraud=0,
        ),
    }


@pytest.fixture
def known_bot_state() -> dict:
    """
    Hard rule: known_bot.
    tls_fingerprint_known_bot=True AND user_agent_is_headless=True.
    """
    return {
        "primary_entity_id": "acc_bot_hr_001",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "payload_signals": PayloadSignals(
            session_id="sess_bot_hr_001",
            account_id="acc_bot_hr_001",
            user_agent_string="HeadlessChrome/118.0",
            user_agent_is_headless=True,
            tls_fingerprint_ja3="botja3hash",
            tls_fingerprint_known_bot=True,
            http_header_order_anomaly=True,
            accept_language_missing=True,
            mouse_movement_entropy=0.0,
            keystroke_dynamics_score=0.02,
            requests_per_minute=220.0,
            request_timing_variance_ms=2.0,
            captcha_solve_time_ms=80,
            captcha_solve_pattern_automated=True,
            credential_stuffing_ip_on_blocklist=True,
            login_attempt_count_this_session=10,
            api_endpoint_sequence_anomaly=True,
        ),
    }


@pytest.fixture
def trusted_account_state() -> dict:
    """
    Hard rule: trusted_account.
    730+ day account, known device, home geo, ratio < 1.5.
    """
    return {
        "primary_entity_id": "acc_trusted_hr_001",
        "primary_entity_type": "user",
        "event_type": "transaction",
        "ato_signals": MockATOSignals(
            account_id="acc_trusted_hr_001",
            account_age_days=1200,
            is_new_device=False,
            device_id="dev_trusted_home",
            login_geo="Seattle, WA",
            account_home_geo="Seattle, WA",
            geo_mismatch=False,
            time_since_last_login_days=1,
            immediate_high_value_action=False,
            email_change_attempted=False,
            password_change_attempted=False,
            support_ticket_language_match=True,
        ),
        "payment_signals": PaymentSignals(
            transaction_id="txn_trusted_001",
            account_id="acc_trusted_hr_001",
            amount_usd=55.00,
            merchant_category="grocery",
            merchant_country="United States",
            account_home_country="United States",
            is_international=False,
            transactions_last_1h=1,
            transactions_last_24h=2,
            avg_transaction_amount_30d=50.00,
            amount_vs_avg_ratio=1.1,
            is_first_transaction=False,
            card_present=True,
            days_since_account_creation=1200,
        ),
    }


@pytest.fixture
def scoring_path_block_state() -> dict:
    """
    Scoring path: no hard rule fires, but aggregate > 0.70 with 3 specialists.
    ATO + payment + identity all show high fraud signals.
    Designed to hit the deterministic block path through aggregation.

    Hard rule avoidance:
      - no ring_signals        (no confirmed_ring)
      - no payload_signals     (no known_bot)
      - transactions_last_1h=7 (no extreme_velocity, needs >= 20)
      - new device + geo mismatch (no trusted_account)
    """
    return {
        "primary_entity_id": "acc_scoring_block_001",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ato_signals": MockATOSignals(
            account_id="acc_scoring_block_001",
            account_age_days=14,
            is_new_device=True,
            device_id="dev_unknown_001",
            login_geo="Lagos, Nigeria",
            account_home_geo="San Jose, CA",
            geo_mismatch=True,
            time_since_last_login_days=1,
            immediate_high_value_action=True,
            email_change_attempted=True,
            password_change_attempted=False,
            support_ticket_language_match=False,
        ),
        "payment_signals": PaymentSignals(
            transaction_id="txn_scoring_block_001",
            account_id="acc_scoring_block_001",
            amount_usd=2000.00,
            merchant_category="electronics",
            merchant_country="Nigeria",
            account_home_country="United States",
            is_international=True,
            transactions_last_1h=7,
            transactions_last_24h=14,
            avg_transaction_amount_30d=60.00,
            amount_vs_avg_ratio=10.0,
            is_first_transaction=False,
            card_present=False,
            days_since_account_creation=14,
        ),
        "identity_signals": IdentitySignals(
            account_id="acc_scoring_block_001",
            account_age_days=14,
            email_domain="tempmail.io",
            is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True,
            address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=6,
            accounts_created_from_same_device=12,
            accounts_created_from_same_ip=10,
            signup_velocity_same_ip_24h=6,
            name_dob_mismatch=True,
        ),
    }


@pytest.fixture
def clean_login_state() -> dict:
    """Clean login: ATO only, all low-risk signals. Hits deterministic allow via scoring."""
    return {
        "primary_entity_id": "acc_clean_int_001",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ato_signals": MockATOSignals(
            account_id="acc_clean_int_001",
            account_age_days=900,
            is_new_device=False,
            device_id="dev_trusted_home",
            login_geo="Seattle, WA",
            account_home_geo="Seattle, WA",
            geo_mismatch=False,
            time_since_last_login_days=2,
            immediate_high_value_action=False,
            email_change_attempted=False,
            password_change_attempted=False,
            support_ticket_language_match=True,
        ),
    }


# ---------------------------------------------------------------------------
# Hard rules path
# ---------------------------------------------------------------------------

class TestHardRules:
    def test_confirmed_ring_verdict_is_block(self, confirmed_ring_state):
        result = fraud_graph.invoke(confirmed_ring_state)
        assert result["arbiter_output"].verdict == "block"

    def test_confirmed_ring_rule_name(self, confirmed_ring_state):
        result = fraud_graph.invoke(confirmed_ring_state)
        assert result["arbiter_output"].rule_name == "confirmed_ring"

    def test_confirmed_ring_no_risk_vector(self, confirmed_ring_state):
        # Hard rule short-circuits before specialists run; no RiskVector is produced.
        result = fraud_graph.invoke(confirmed_ring_state)
        assert result.get("risk_vector") is None

    def test_confirmed_ring_trigger_async_false(self, confirmed_ring_state):
        # Hard rule blocks are clear-cut; no investigation needed.
        result = fraud_graph.invoke(confirmed_ring_state)
        assert result["arbiter_output"].trigger_async is False

    def test_confirmed_ring_has_evidence(self, confirmed_ring_state):
        result = fraud_graph.invoke(confirmed_ring_state)
        assert "known_ring_signature_match" in result["arbiter_output"].evidence

    def test_known_bot_verdict_is_block(self, known_bot_state):
        result = fraud_graph.invoke(known_bot_state)
        assert result["arbiter_output"].verdict == "block"

    def test_known_bot_rule_name(self, known_bot_state):
        result = fraud_graph.invoke(known_bot_state)
        assert result["arbiter_output"].rule_name == "known_bot"

    def test_known_bot_no_risk_vector(self, known_bot_state):
        result = fraud_graph.invoke(known_bot_state)
        assert result.get("risk_vector") is None

    def test_trusted_account_verdict_is_allow(self, trusted_account_state):
        result = fraud_graph.invoke(trusted_account_state)
        assert result["arbiter_output"].verdict == "allow"

    def test_trusted_account_rule_name(self, trusted_account_state):
        result = fraud_graph.invoke(trusted_account_state)
        assert result["arbiter_output"].rule_name == "trusted_account"

    def test_trusted_account_no_risk_vector(self, trusted_account_state):
        result = fraud_graph.invoke(trusted_account_state)
        assert result.get("risk_vector") is None

    def test_trusted_account_trigger_async_false(self, trusted_account_state):
        result = fraud_graph.invoke(trusted_account_state)
        assert result["arbiter_output"].trigger_async is False


# ---------------------------------------------------------------------------
# Scoring path: deterministic block
# ---------------------------------------------------------------------------

class TestDeterministicBlock:
    def test_scoring_block_verdict_is_block(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert result["arbiter_output"].verdict == "block"

    def test_scoring_block_rule_name(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert result["arbiter_output"].rule_name == "high_aggregate_block"

    def test_scoring_block_has_risk_vector(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert isinstance(result["risk_vector"], RiskVector)

    def test_scoring_block_aggregate_exceeds_threshold(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert result["risk_vector"].aggregate > 0.70

    def test_scoring_block_three_specialists_ran(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert result["risk_vector"].specialists_run == 3

    def test_scoring_block_confidence_reflects_aggregate(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        arb = result["arbiter_output"]
        rv = result["risk_vector"]
        assert arb.confidence == pytest.approx(rv.aggregate, abs=1e-4)

    def test_scoring_block_has_evidence(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert len(result["arbiter_output"].evidence) > 0

    def test_scoring_block_no_failed_agents(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        assert result.get("failed_agents", []) == []


# ---------------------------------------------------------------------------
# Scoring path: deterministic allow
# ---------------------------------------------------------------------------

class TestDeterministicAllow:
    def test_clean_login_verdict_is_allow(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["arbiter_output"].verdict == "allow"

    def test_clean_login_rule_name(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["arbiter_output"].rule_name == "low_aggregate_allow"

    def test_clean_login_aggregate_below_threshold(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["risk_vector"].aggregate < 0.15

    def test_clean_login_trigger_async_is_false(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["arbiter_output"].trigger_async is False

    def test_clean_login_trigger_reason_is_none(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["arbiter_output"].trigger_reason is None

    def test_clean_login_one_specialist_ran(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["risk_vector"].specialists_run == 1

    def test_clean_login_stddev_is_none_with_single_specialist(self, clean_login_state):
        result = fraud_graph.invoke(clean_login_state)
        assert result["risk_vector"].score_stddev is None


# ---------------------------------------------------------------------------
# Risk vector correctness (scoring path only)
# ---------------------------------------------------------------------------

class TestRiskVector:
    def test_available_domains_sorted_descending(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        rv = result["risk_vector"]
        scores = [rv.scores[d] for d in rv.available_domains]
        assert scores == sorted(scores, reverse=True)

    def test_dominant_domain_has_highest_score(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        rv = result["risk_vector"]
        assert rv.dominant_score == rv.scores[rv.dominant_domain]
        assert rv.dominant_score == max(rv.scores.values())

    def test_aggregate_within_bounds(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        rv = result["risk_vector"]
        assert 0.0 <= rv.aggregate <= 1.0

    def test_stddev_present_with_multiple_specialists(self, scoring_path_block_state):
        result = fraud_graph.invoke(scoring_path_block_state)
        rv = result["risk_vector"]
        assert rv.specialists_run == 3
        assert rv.score_stddev is not None
        assert rv.score_stddev >= 0.0
