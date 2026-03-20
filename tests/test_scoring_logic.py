"""
Scoring logic tests for all six specialist agents.

Validates that the deterministic Python scorers produce the expected scores
and primary signals for high-fraud, clean, and ambiguous inputs. These tests
complement the schema validation tests in test_*_agent.py and catch weight
regressions that schema tests cannot detect.
"""

import pytest

from src.agents.ato_agent import score_ato
from src.agents.identity_agent import score_identity
from src.agents.payload_agent import score_payload
from src.agents.payment_agent import score_payment
from src.agents.promo_agent import score_promo
from src.agents.ring_detection_agent import score_ring
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.promo_schemas import PromoSignals
from src.schemas.ring_schemas import RingSignals


# ---------------------------------------------------------------------------
# ATO Scorer
# ---------------------------------------------------------------------------

class TestATOScorer:
    def _clean(self) -> MockATOSignals:
        return MockATOSignals(
            account_id="acc_clean",
            account_age_days=800,
            is_new_device=False,
            device_id="dev_trusted",
            login_geo="Seattle, WA",
            account_home_geo="Seattle, WA",
            geo_mismatch=False,
            time_since_last_login_days=1,
            immediate_high_value_action=False,
            email_change_attempted=False,
            password_change_attempted=False,
            support_ticket_language_match=True,
        )

    def test_clean_login_scores_zero(self):
        score = score_ato(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_high_fraud_scores_above_threshold(self):
        # new_device(0.25) + geo(0.20) + email_change(0.20) + immediate(0.15) = 0.80
        signals = self._clean()
        signals = signals.model_copy(update={
            "is_new_device": True,
            "geo_mismatch": True,
            "email_change_attempted": True,
            "immediate_high_value_action": True,
        })
        score = score_ato(signals)
        assert score.score >= 0.70
        assert "is_new_device" in score.primary_signals
        assert "email_change_attempted" in score.primary_signals

    def test_new_device_and_geo_mismatch_contribute(self):
        # new_device(0.25) + geo(0.20) = 0.45
        signals = self._clean()
        signals = signals.model_copy(update={"is_new_device": True, "geo_mismatch": True})
        score = score_ato(signals)
        assert score.score == pytest.approx(0.45)
        assert "is_new_device" in score.primary_signals
        assert "geo_mismatch" in score.primary_signals

    def test_dormant_account_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"time_since_last_login_days": 45})
        score = score_ato(signals)
        assert score.score == pytest.approx(0.05)
        assert "dormant_account_reactivated" in score.primary_signals

    def test_support_language_mismatch_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"support_ticket_language_match": False})
        score = score_ato(signals)
        assert score.score == pytest.approx(0.05)

    def test_score_capped_at_one(self):
        # All signals fire: 0.25+0.20+0.20+0.15+0.10+0.05+0.05 = 1.00
        signals = MockATOSignals(
            account_id="acc_all",
            account_age_days=800,
            is_new_device=True,
            device_id="dev_x",
            login_geo="Lagos, Nigeria",
            account_home_geo="Seattle, WA",
            geo_mismatch=True,
            time_since_last_login_days=60,
            immediate_high_value_action=True,
            email_change_attempted=True,
            password_change_attempted=True,
            support_ticket_language_match=False,
        )
        score = score_ato(signals)
        assert score.score <= 1.0

    def test_signals_evaluated_count(self):
        score = score_ato(self._clean())
        assert score.signals_evaluated == 7

    def test_primary_signals_max_three(self):
        signals = MockATOSignals(
            account_id="acc_all",
            account_age_days=800,
            is_new_device=True,
            device_id="dev_x",
            login_geo="Lagos",
            account_home_geo="Seattle",
            geo_mismatch=True,
            time_since_last_login_days=60,
            immediate_high_value_action=True,
            email_change_attempted=True,
            password_change_attempted=True,
            support_ticket_language_match=False,
        )
        score = score_ato(signals)
        assert len(score.primary_signals) <= 3


# ---------------------------------------------------------------------------
# Payment Scorer
# ---------------------------------------------------------------------------

class TestPaymentScorer:
    def _clean(self) -> PaymentSignals:
        return PaymentSignals(
            transaction_id="txn_clean",
            account_id="acc_clean",
            amount_usd=45.00,
            merchant_category="grocery",
            merchant_country="United States",
            account_home_country="United States",
            is_international=False,
            transactions_last_1h=0,
            transactions_last_24h=1,
            avg_transaction_amount_30d=50.00,
            amount_vs_avg_ratio=0.9,
            is_first_transaction=False,
            card_present=True,
            days_since_account_creation=365,
        )

    def test_clean_transaction_scores_zero(self):
        score = score_payment(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_high_fraud_scores_above_threshold(self):
        # ratio>=10(0.25) + v1h=7(0.14) + international(0.15) + CNP(0.10) + new_account(0.10) = 0.74
        signals = self._clean()
        signals = signals.model_copy(update={
            "amount_vs_avg_ratio": 15.0,
            "transactions_last_1h": 7,
            "is_international": True,
            "card_present": False,
            "days_since_account_creation": 10,
        })
        score = score_payment(signals)
        assert score.score >= 0.70
        assert "amount_vs_avg_ratio" in score.primary_signals

    def test_ratio_graduation_10x(self):
        signals = self._clean()
        signals = signals.model_copy(update={"amount_vs_avg_ratio": 10.0})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.25)

    def test_ratio_graduation_5x(self):
        signals = self._clean()
        signals = signals.model_copy(update={"amount_vs_avg_ratio": 5.0})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.18)

    def test_ratio_graduation_3x(self):
        signals = self._clean()
        signals = signals.model_copy(update={"amount_vs_avg_ratio": 3.0})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.12)

    def test_ratio_graduation_2x(self):
        signals = self._clean()
        signals = signals.model_copy(update={"amount_vs_avg_ratio": 2.0})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.06)

    def test_velocity_graduation_high(self):
        signals = self._clean()
        signals = signals.model_copy(update={"transactions_last_1h": 10})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.20)

    def test_velocity_graduation_medium(self):
        signals = self._clean()
        signals = signals.model_copy(update={"transactions_last_1h": 5})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.08)

    def test_high_risk_merchant_category(self):
        signals = self._clean()
        signals = signals.model_copy(update={"merchant_category": "gift_cards"})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.10)
        assert "high_risk_merchant_category" in score.primary_signals

    def test_medium_risk_merchant_category(self):
        signals = self._clean()
        signals = signals.model_copy(update={"merchant_category": "electronics"})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.05)

    def test_first_transaction_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"is_first_transaction": True})
        score = score_payment(signals)
        assert score.score == pytest.approx(0.10)

    def test_score_capped_at_one(self):
        signals = PaymentSignals(
            transaction_id="txn_max",
            account_id="acc_max",
            amount_usd=9999.00,
            merchant_category="gift_cards",
            merchant_country="Nigeria",
            account_home_country="United States",
            is_international=True,
            transactions_last_1h=15,
            transactions_last_24h=30,
            avg_transaction_amount_30d=50.00,
            amount_vs_avg_ratio=20.0,
            is_first_transaction=True,
            card_present=False,
            days_since_account_creation=5,
        )
        score = score_payment(signals)
        assert score.score <= 1.0


# ---------------------------------------------------------------------------
# Ring Scorer
# ---------------------------------------------------------------------------

class TestRingScorer:
    def _clean(self) -> RingSignals:
        return RingSignals(
            primary_entity_id="acc_clean",
            primary_entity_type="user",
            device_id="dev_clean",
            ip_address_hash="hash_clean",
            accounts_sharing_device=1,
            accounts_sharing_ip=2,
            linked_account_ids=[],
            linked_accounts_with_block_verdict=0,
            linked_accounts_with_fraud_confirmed=0,
            shared_payment_method_across_accounts=False,
            payment_method_account_count=1,
            known_ring_signature_match=False,
            ring_signature_id=None,
            velocity_account_creation_same_ip_7d=0,
            transaction_graph_min_hops_to_fraud=10,
        )

    def test_clean_entity_scores_zero(self):
        score = score_ring(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_known_ring_signature_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={
            "known_ring_signature_match": True,
            "ring_signature_id": "ring_001",
        })
        score = score_ring(signals)
        assert score.score == pytest.approx(0.40)
        assert "known_ring_signature_match" in score.primary_signals

    def test_high_fraud_scores_above_threshold(self):
        # known_sig(0.40) + confirmed=2(0.18) + hops=1(0.10) + device>=10(0.10) = 0.78
        signals = self._clean()
        signals = signals.model_copy(update={
            "known_ring_signature_match": True,
            "ring_signature_id": "ring_001",
            "linked_accounts_with_fraud_confirmed": 2,
            "transaction_graph_min_hops_to_fraud": 1,
            "accounts_sharing_device": 10,
        })
        score = score_ring(signals)
        assert score.score >= 0.70

    def test_confirmed_fraud_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"linked_accounts_with_fraud_confirmed": 1})
        assert score_ring(signals).score == pytest.approx(0.12)

        signals = signals.model_copy(update={"linked_accounts_with_fraud_confirmed": 2})
        assert score_ring(signals).score == pytest.approx(0.18)

        signals = signals.model_copy(update={"linked_accounts_with_fraud_confirmed": 3})
        assert score_ring(signals).score == pytest.approx(0.25)

    def test_graph_proximity_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"transaction_graph_min_hops_to_fraud": 0})
        assert score_ring(signals).score == pytest.approx(0.15)

        signals = signals.model_copy(update={"transaction_graph_min_hops_to_fraud": 1})
        assert score_ring(signals).score == pytest.approx(0.10)

        signals = signals.model_copy(update={"transaction_graph_min_hops_to_fraud": 2})
        assert score_ring(signals).score == pytest.approx(0.05)

    def test_device_sharing_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"accounts_sharing_device": 3})
        assert score_ring(signals).score == pytest.approx(0.04)

        signals = signals.model_copy(update={"accounts_sharing_device": 5})
        assert score_ring(signals).score == pytest.approx(0.07)

        signals = signals.model_copy(update={"accounts_sharing_device": 10})
        assert score_ring(signals).score == pytest.approx(0.10)

    def test_score_capped_at_one(self):
        signals = RingSignals(
            primary_entity_id="acc_ring",
            primary_entity_type="user",
            device_id="dev_factory",
            ip_address_hash="hash_ring",
            accounts_sharing_device=22,
            accounts_sharing_ip=15,
            linked_account_ids=["a", "b", "c"],
            linked_accounts_with_block_verdict=5,
            linked_accounts_with_fraud_confirmed=5,
            shared_payment_method_across_accounts=True,
            payment_method_account_count=7,
            known_ring_signature_match=True,
            ring_signature_id="ring_001",
            velocity_account_creation_same_ip_7d=20,
            transaction_graph_min_hops_to_fraud=0,
        )
        score = score_ring(signals)
        assert score.score <= 1.0


# ---------------------------------------------------------------------------
# Identity Scorer
# ---------------------------------------------------------------------------

class TestIdentityScorer:
    def _clean(self) -> IdentitySignals:
        return IdentitySignals(
            account_id="acc_clean",
            account_age_days=500,
            email_domain="gmail.com",
            is_disposable_email=False,
            phone_country_matches_ip_country=True,
            address_provided=True,
            address_is_commercial=False,
            document_verification_passed=True,
            pii_seen_on_other_accounts=0,
            accounts_created_from_same_device=1,
            accounts_created_from_same_ip=2,
            signup_velocity_same_ip_24h=1,
            name_dob_mismatch=False,
        )

    def test_clean_account_scores_zero(self):
        score = score_identity(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_high_fraud_scores_above_threshold(self):
        # pii>=5(0.25) + doc_fail(0.20) + disposable(0.15) + name_dob(0.15) = 0.75
        signals = self._clean()
        signals = signals.model_copy(update={
            "pii_seen_on_other_accounts": 6,
            "document_verification_passed": False,
            "is_disposable_email": True,
            "name_dob_mismatch": True,
        })
        score = score_identity(signals)
        assert score.score >= 0.70
        assert "pii_seen_on_other_accounts" in score.primary_signals

    def test_pii_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"pii_seen_on_other_accounts": 1})
        assert score_identity(signals).score == pytest.approx(0.10)

        signals = signals.model_copy(update={"pii_seen_on_other_accounts": 3})
        assert score_identity(signals).score == pytest.approx(0.18)

        signals = signals.model_copy(update={"pii_seen_on_other_accounts": 5})
        assert score_identity(signals).score == pytest.approx(0.25)

    def test_document_failure_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"document_verification_passed": False})
        score = score_identity(signals)
        assert score.score == pytest.approx(0.20)
        assert "document_verification_failed" in score.primary_signals

    def test_device_factory_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"accounts_created_from_same_device": 3})
        assert score_identity(signals).score == pytest.approx(0.04)

        signals = signals.model_copy(update={"accounts_created_from_same_device": 10})
        assert score_identity(signals).score == pytest.approx(0.10)

    def test_signup_velocity_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"signup_velocity_same_ip_24h": 3})
        assert score_identity(signals).score == pytest.approx(0.05)

        signals = signals.model_copy(update={"signup_velocity_same_ip_24h": 5})
        assert score_identity(signals).score == pytest.approx(0.08)

    def test_score_capped_at_one(self):
        signals = IdentitySignals(
            account_id="acc_synth",
            account_age_days=3,
            email_domain="tempmail.io",
            is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True,
            address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=10,
            accounts_created_from_same_device=20,
            accounts_created_from_same_ip=10,
            signup_velocity_same_ip_24h=8,
            name_dob_mismatch=True,
        )
        score = score_identity(signals)
        assert score.score <= 1.0


# ---------------------------------------------------------------------------
# Promo Scorer
# ---------------------------------------------------------------------------

class TestPromoScorer:
    def _clean(self) -> PromoSignals:
        return PromoSignals(
            account_id="acc_clean",
            promo_code="SAVE10",
            promo_type="coupon",
            account_age_days=200,
            is_first_order=False,
            promo_uses_this_account=1,
            promo_uses_same_code=1,
            accounts_linked_same_device=0,
            accounts_linked_same_ip=1,
            referrer_account_id=None,
            referrer_account_age_days=None,
            device_shared_with_referrer=False,
            email_domain_pattern_suspicious=False,
            order_cancelled_after_promo=False,
            payout_requested_immediately=False,
        )

    def test_clean_redemption_scores_zero(self):
        score = score_promo(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_high_fraud_scores_above_threshold(self):
        # device_shared(0.30) + payout(0.25) + cancelled(0.20) = 0.75
        signals = self._clean()
        signals = signals.model_copy(update={
            "device_shared_with_referrer": True,
            "payout_requested_immediately": True,
            "order_cancelled_after_promo": True,
        })
        score = score_promo(signals)
        assert score.score >= 0.70
        assert "device_shared_with_referrer" in score.primary_signals
        assert "payout_requested_immediately" in score.primary_signals

    def test_device_shared_with_referrer_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"device_shared_with_referrer": True})
        score = score_promo(signals)
        assert score.score == pytest.approx(0.30)

    def test_payout_immediately_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"payout_requested_immediately": True})
        score = score_promo(signals)
        assert score.score == pytest.approx(0.25)

    def test_device_clustering_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"accounts_linked_same_device": 2})
        assert score_promo(signals).score == pytest.approx(0.04)

        signals = signals.model_copy(update={"accounts_linked_same_device": 3})
        assert score_promo(signals).score == pytest.approx(0.08)

        signals = signals.model_copy(update={"accounts_linked_same_device": 5})
        assert score_promo(signals).score == pytest.approx(0.12)

    def test_new_account_high_promo_use(self):
        signals = self._clean()
        signals = signals.model_copy(update={
            "account_age_days": 5,
            "promo_uses_this_account": 4,
        })
        score = score_promo(signals)
        assert score.score == pytest.approx(0.08)
        assert "new_account_high_promo_use" in score.primary_signals

    def test_young_referrer_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={
            "referrer_account_id": "ref_001",
            "referrer_account_age_days": 7,
        })
        score = score_promo(signals)
        assert score.score == pytest.approx(0.05)

    def test_score_capped_at_one(self):
        signals = PromoSignals(
            account_id="acc_fraud",
            promo_code="REF-SELF",
            promo_type="referral",
            account_age_days=3,
            is_first_order=True,
            promo_uses_this_account=5,
            promo_uses_same_code=3,
            accounts_linked_same_device=10,
            accounts_linked_same_ip=8,
            referrer_account_id="ref_self",
            referrer_account_age_days=2,
            device_shared_with_referrer=True,
            email_domain_pattern_suspicious=True,
            order_cancelled_after_promo=True,
            payout_requested_immediately=True,
        )
        score = score_promo(signals)
        assert score.score <= 1.0


# ---------------------------------------------------------------------------
# Payload Scorer
# ---------------------------------------------------------------------------

class TestPayloadScorer:
    def _clean(self) -> PayloadSignals:
        return PayloadSignals(
            session_id="sess_clean",
            account_id="acc_clean",
            user_agent_string="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            user_agent_is_headless=False,
            tls_fingerprint_ja3="legitimate_ja3_hash",
            tls_fingerprint_known_bot=False,
            http_header_order_anomaly=False,
            accept_language_missing=False,
            mouse_movement_entropy=0.85,
            keystroke_dynamics_score=0.80,
            requests_per_minute=12.0,
            request_timing_variance_ms=250.0,
            captcha_solve_time_ms=8500,
            captcha_solve_pattern_automated=False,
            credential_stuffing_ip_on_blocklist=False,
            login_attempt_count_this_session=1,
            api_endpoint_sequence_anomaly=False,
        )

    def test_clean_session_scores_zero(self):
        score = score_payload(self._clean())
        assert score.score == 0.0
        assert score.primary_signals == ["no_risk_signals_detected"]

    def test_high_fraud_scores_above_threshold(self):
        # tls_bot(0.25) + ip_blocklist(0.20) + headless(0.15) + captcha_auto(0.15) = 0.75
        signals = self._clean()
        signals = signals.model_copy(update={
            "tls_fingerprint_known_bot": True,
            "credential_stuffing_ip_on_blocklist": True,
            "user_agent_is_headless": True,
            "captcha_solve_pattern_automated": True,
        })
        score = score_payload(signals)
        assert score.score >= 0.70
        assert "tls_fingerprint_known_bot" in score.primary_signals

    def test_tls_bot_fingerprint_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"tls_fingerprint_known_bot": True})
        score = score_payload(signals)
        assert score.score == pytest.approx(0.25)
        assert "tls_fingerprint_known_bot" in score.primary_signals

    def test_ip_blocklist_contributes(self):
        signals = self._clean()
        signals = signals.model_copy(update={"credential_stuffing_ip_on_blocklist": True})
        score = score_payload(signals)
        assert score.score == pytest.approx(0.20)

    def test_timing_variance_graduation(self):
        signals = self._clean()
        # < 5ms = 0.10
        signals = signals.model_copy(update={"request_timing_variance_ms": 3.0})
        assert score_payload(signals).score == pytest.approx(0.10)
        # < 10ms = 0.06
        signals = signals.model_copy(update={"request_timing_variance_ms": 7.0})
        assert score_payload(signals).score == pytest.approx(0.06)
        # >= 10ms: no contribution
        signals = signals.model_copy(update={"request_timing_variance_ms": 15.0})
        assert score_payload(signals).score == pytest.approx(0.0)

    def test_login_attempt_graduation(self):
        signals = self._clean()
        signals = signals.model_copy(update={"login_attempt_count_this_session": 3})
        assert score_payload(signals).score == pytest.approx(0.03)

        signals = signals.model_copy(update={"login_attempt_count_this_session": 5})
        assert score_payload(signals).score == pytest.approx(0.05)

        signals = signals.model_copy(update={"login_attempt_count_this_session": 10})
        assert score_payload(signals).score == pytest.approx(0.08)

    def test_mouse_entropy_graduation(self):
        signals = self._clean()
        # < 0.10 = 0.07
        signals = signals.model_copy(update={"mouse_movement_entropy": 0.0})
        assert score_payload(signals).score == pytest.approx(0.07)
        # < 0.20 = 0.04
        signals = signals.model_copy(update={"mouse_movement_entropy": 0.15})
        assert score_payload(signals).score == pytest.approx(0.04)
        # >= 0.20: no contribution
        signals = signals.model_copy(update={"mouse_movement_entropy": 0.85})
        assert score_payload(signals).score == pytest.approx(0.0)

    def test_score_capped_at_one(self):
        signals = PayloadSignals(
            session_id="sess_bot",
            account_id="acc_bot",
            user_agent_string="HeadlessChrome/118.0",
            user_agent_is_headless=True,
            tls_fingerprint_ja3="a1b2c3",
            tls_fingerprint_known_bot=True,
            http_header_order_anomaly=True,
            accept_language_missing=True,
            mouse_movement_entropy=0.0,
            keystroke_dynamics_score=0.02,
            requests_per_minute=300.0,
            request_timing_variance_ms=1.5,
            captcha_solve_time_ms=50,
            captcha_solve_pattern_automated=True,
            credential_stuffing_ip_on_blocklist=True,
            login_attempt_count_this_session=15,
            api_endpoint_sequence_anomaly=True,
        )
        score = score_payload(signals)
        assert score.score <= 1.0
