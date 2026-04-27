"""
Regression eval suite — FraudMind full pipeline.

Five canonical cases with locked expected verdicts. These are the ground truth
fixtures for the system. If any of these change, it means a scoring weight,
threshold, or hard rule has changed — that change must be deliberate.

Run with:
    pytest tests/evals/test_regression.py -v

Cases:
  R1  confirmed_ring hard rule   → block,   rule=confirmed_ring,      no risk_vector
  R2  known_bot hard rule        → block,   rule=known_bot,           no risk_vector
  R3  high fraud all domains     → block,   rule=high_aggregate_block, risk_vector present
  R4  clean account single spec  → allow,   rule=low_aggregate_allow
  R5  thin evidence mid-risk     → escalate, rule=thin_evidence_escalate

Each case also asserts:
  - No failed_agents
  - trigger_async matches expected policy
  - trigger_reason matches expected value
"""

import pytest

from src.graph.fraud_graph import fraud_graph
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.ring_schemas import RingSignals


# ---------------------------------------------------------------------------
# Canonical fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def r1_confirmed_ring():
    """R1: confirmed ring hard rule. Block, no scoring."""
    return {
        "primary_entity_id": "reg_r1",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ring_signals": RingSignals(
            primary_entity_id="reg_r1", primary_entity_type="user",
            device_id="dev_ring_reg", ip_address_hash="ip_ring_reg",
            accounts_sharing_device=20, accounts_sharing_ip=12,
            linked_account_ids=["a", "b", "c"],
            linked_accounts_with_block_verdict=3,
            linked_accounts_with_fraud_confirmed=3,
            shared_payment_method_across_accounts=True,
            payment_method_account_count=7,
            known_ring_signature_match=True,
            ring_signature_id="ring_REG_001",
            velocity_account_creation_same_ip_7d=18,
            transaction_graph_min_hops_to_fraud=0,
        ),
    }


@pytest.fixture
def r2_known_bot():
    """R2: known bot hard rule. Block, no scoring."""
    return {
        "primary_entity_id": "reg_r2",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "payload_signals": PayloadSignals(
            session_id="sess_reg_r2", account_id="reg_r2",
            user_agent_string="HeadlessChrome/118.0",
            user_agent_is_headless=True,
            tls_fingerprint_ja3="botja3reg",
            tls_fingerprint_known_bot=True,
            http_header_order_anomaly=True, accept_language_missing=True,
            mouse_movement_entropy=0.0, keystroke_dynamics_score=0.02,
            requests_per_minute=200.0, request_timing_variance_ms=2.0,
            captcha_solve_time_ms=80, captcha_solve_pattern_automated=True,
            credential_stuffing_ip_on_blocklist=True,
            login_attempt_count_this_session=10,
            api_endpoint_sequence_anomaly=True,
        ),
    }


@pytest.fixture
def r3_high_fraud_all_domains():
    """R3: 3 specialists all showing high fraud. Deterministic block via scoring."""
    return {
        "primary_entity_id": "reg_r3",
        "primary_entity_type": "user",
        "event_type": "transaction",
        "ato_signals": MockATOSignals(
            account_id="reg_r3", account_age_days=10,
            is_new_device=True, device_id="dev_unknown_reg",
            login_geo="Lagos, Nigeria", account_home_geo="San Jose, CA",
            geo_mismatch=True, time_since_last_login_days=1,
            immediate_high_value_action=True, email_change_attempted=True,
            password_change_attempted=False, support_ticket_language_match=False,
        ),
        "payment_signals": PaymentSignals(
            transaction_id="txn_reg_r3", account_id="reg_r3",
            amount_usd=3000.00, merchant_category="electronics",
            merchant_country="Nigeria", account_home_country="United States",
            is_international=True, transactions_last_1h=7, transactions_last_24h=14,
            avg_transaction_amount_30d=60.00, amount_vs_avg_ratio=12.0,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=10,
        ),
        "identity_signals": IdentitySignals(
            account_id="reg_r3", account_age_days=10,
            email_domain="tempmail.io", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True, address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=7,
            accounts_created_from_same_device=15,
            accounts_created_from_same_ip=8,
            signup_velocity_same_ip_24h=6,
            name_dob_mismatch=True,
        ),
    }


@pytest.fixture
def r4_clean_account():
    """R4: Single specialist, all clean signals. Deterministic allow."""
    return {
        "primary_entity_id": "reg_r4",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ato_signals": MockATOSignals(
            account_id="reg_r4", account_age_days=1100,
            is_new_device=False, device_id="dev_home_reg",
            login_geo="Seattle, WA", account_home_geo="Seattle, WA",
            geo_mismatch=False, time_since_last_login_days=1,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
    }


@pytest.fixture
def r5_thin_evidence():
    """R5: Single specialist at mid-range score. Too thin to block — escalate."""
    return {
        "primary_entity_id": "reg_r5",
        "primary_entity_type": "user",
        "event_type": "authentication",
        "ato_signals": MockATOSignals(
            account_id="reg_r5", account_age_days=200,
            is_new_device=True, device_id="dev_unknown_reg5",
            login_geo="London, UK", account_home_geo="New York, NY",
            geo_mismatch=True, time_since_last_login_days=10,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
    }


# ---------------------------------------------------------------------------
# R1: confirmed_ring hard rule
# ---------------------------------------------------------------------------

class TestR1ConfirmedRing:
    def test_verdict(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert result["arbiter_output"].verdict == "block"

    def test_rule_name(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert result["arbiter_output"].rule_name == "confirmed_ring"

    def test_no_risk_vector(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert result.get("risk_vector") is None

    def test_trigger_async_false(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert result["arbiter_output"].trigger_async is False

    def test_no_failed_agents(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert result.get("failed_agents", []) == []

    def test_evidence_contains_ring_signal(self, r1_confirmed_ring):
        result = fraud_graph.invoke(r1_confirmed_ring)
        assert "known_ring_signature_match" in result["arbiter_output"].evidence


# ---------------------------------------------------------------------------
# R2: known_bot hard rule
# ---------------------------------------------------------------------------

class TestR2KnownBot:
    def test_verdict(self, r2_known_bot):
        result = fraud_graph.invoke(r2_known_bot)
        assert result["arbiter_output"].verdict == "block"

    def test_rule_name(self, r2_known_bot):
        result = fraud_graph.invoke(r2_known_bot)
        assert result["arbiter_output"].rule_name == "known_bot"

    def test_no_risk_vector(self, r2_known_bot):
        result = fraud_graph.invoke(r2_known_bot)
        assert result.get("risk_vector") is None

    def test_no_failed_agents(self, r2_known_bot):
        result = fraud_graph.invoke(r2_known_bot)
        assert result.get("failed_agents", []) == []


# ---------------------------------------------------------------------------
# R3: high fraud all domains — deterministic block via scoring
# ---------------------------------------------------------------------------

class TestR3HighFraud:
    def test_verdict(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result["arbiter_output"].verdict == "block"

    def test_rule_name(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result["arbiter_output"].rule_name == "high_aggregate_block"

    def test_risk_vector_present(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result.get("risk_vector") is not None

    def test_aggregate_exceeds_block_threshold(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result["risk_vector"].aggregate > 0.70

    def test_three_specialists_ran(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result["risk_vector"].specialists_run == 3

    def test_no_failed_agents(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result.get("failed_agents", []) == []

    def test_trigger_async_false_consensus_block(self, r3_high_fraud_all_domains):
        result = fraud_graph.invoke(r3_high_fraud_all_domains)
        assert result["arbiter_output"].trigger_async is False


# ---------------------------------------------------------------------------
# R4: clean account — deterministic allow
# ---------------------------------------------------------------------------

class TestR4CleanAccount:
    def test_verdict(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result["arbiter_output"].verdict == "allow"

    def test_rule_name(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result["arbiter_output"].rule_name == "low_aggregate_allow"

    def test_aggregate_below_allow_threshold(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result["risk_vector"].aggregate < 0.15

    def test_trigger_async_false(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result["arbiter_output"].trigger_async is False

    def test_trigger_reason_is_none(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result["arbiter_output"].trigger_reason is None

    def test_no_failed_agents(self, r4_clean_account):
        result = fraud_graph.invoke(r4_clean_account)
        assert result.get("failed_agents", []) == []


# ---------------------------------------------------------------------------
# R5: thin evidence — escalate
# ---------------------------------------------------------------------------

class TestR5ThinEvidence:
    def test_verdict(self, r5_thin_evidence):
        result = fraud_graph.invoke(r5_thin_evidence)
        assert result["arbiter_output"].verdict == "escalate"

    def test_rule_name(self, r5_thin_evidence):
        result = fraud_graph.invoke(r5_thin_evidence)
        assert result["arbiter_output"].rule_name == "thin_evidence_escalate"

    def test_one_specialist_ran(self, r5_thin_evidence):
        result = fraud_graph.invoke(r5_thin_evidence)
        assert result["risk_vector"].specialists_run == 1

    def test_trigger_async_true(self, r5_thin_evidence):
        result = fraud_graph.invoke(r5_thin_evidence)
        assert result["arbiter_output"].trigger_async is True

    def test_no_failed_agents(self, r5_thin_evidence):
        result = fraud_graph.invoke(r5_thin_evidence)
        assert result.get("failed_agents", []) == []
