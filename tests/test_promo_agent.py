"""
Schema validation tests for the Promo Agent -- Version 2.

Tests cover:
- Valid construction of PromoSignals and PromoVerdict
- Field constraint enforcement (confidence bounds, verdict literals, ge=0 fields)
- Three canonical promo test cases parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.promo_schemas import PromoSignals, PromoVerdict


# ---------------------------------------------------------------------------
# Shared fixtures -- three canonical promo test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_self_referral_ring() -> dict:
    """Case 1 -- Self-referral ring abuse. Expected verdict: block."""
    return {
        "account_id": "acc_promo_001",
        "promo_code": "REF-ABUSE-001",
        "promo_type": "referral",
        "account_age_days": 2,
        "is_first_order": True,
        "promo_uses_this_account": 1,
        "promo_uses_same_code": 1,
        "accounts_linked_same_device": 6,
        "accounts_linked_same_ip": 8,
        "referrer_account_id": "acc_promo_ref_001",
        "referrer_account_age_days": 5,
        "device_shared_with_referrer": True,
        "email_domain_pattern_suspicious": True,
        "order_cancelled_after_promo": True,
        "payout_requested_immediately": True,
    }


@pytest.fixture
def case_legitimate_promo() -> dict:
    """Case 2 -- Legitimate first-time promo use. Expected verdict: allow."""
    return {
        "account_id": "acc_promo_002",
        "promo_code": "WELCOME10",
        "promo_type": "coupon",
        "account_age_days": 365,
        "is_first_order": True,
        "promo_uses_this_account": 1,
        "promo_uses_same_code": 1,
        "accounts_linked_same_device": 1,
        "accounts_linked_same_ip": 1,
        "referrer_account_id": None,
        "referrer_account_age_days": None,
        "device_shared_with_referrer": False,
        "email_domain_pattern_suspicious": False,
        "order_cancelled_after_promo": False,
        "payout_requested_immediately": False,
    }


@pytest.fixture
def case_suspicious_promo() -> dict:
    """Case 3 -- Suspicious promo velocity on a new account. Expected verdict: step_up."""
    return {
        "account_id": "acc_promo_003",
        "promo_code": "TRIAL2024",
        "promo_type": "trial",
        "account_age_days": 10,
        "is_first_order": False,
        "promo_uses_this_account": 4,
        "promo_uses_same_code": 2,
        "accounts_linked_same_device": 2,
        "accounts_linked_same_ip": 3,
        "referrer_account_id": "acc_promo_ref_002",
        "referrer_account_age_days": 15,
        "device_shared_with_referrer": False,
        "email_domain_pattern_suspicious": False,
        "order_cancelled_after_promo": False,
        "payout_requested_immediately": False,
    }


# ---------------------------------------------------------------------------
# PromoSignals -- valid construction
# ---------------------------------------------------------------------------

class TestPromoSignalsValid:
    def test_self_referral_ring_parses(self, case_self_referral_ring: dict) -> None:
        signals = PromoSignals(**case_self_referral_ring)
        assert signals.account_id == "acc_promo_001"
        assert signals.device_shared_with_referrer is True
        assert signals.payout_requested_immediately is True
        assert signals.accounts_linked_same_device == 6

    def test_legitimate_promo_parses(self, case_legitimate_promo: dict) -> None:
        signals = PromoSignals(**case_legitimate_promo)
        assert signals.account_id == "acc_promo_002"
        assert signals.referrer_account_id is None
        assert signals.device_shared_with_referrer is False

    def test_suspicious_promo_parses(self, case_suspicious_promo: dict) -> None:
        signals = PromoSignals(**case_suspicious_promo)
        assert signals.account_id == "acc_promo_003"
        assert signals.promo_uses_this_account == 4


# ---------------------------------------------------------------------------
# PromoSignals -- invalid inputs
# ---------------------------------------------------------------------------

class TestPromoSignalsInvalid:
    def test_missing_required_field(self, case_legitimate_promo: dict) -> None:
        del case_legitimate_promo["promo_code"]
        with pytest.raises(ValidationError):
            PromoSignals(**case_legitimate_promo)

    def test_negative_promo_uses_rejected(self, case_legitimate_promo: dict) -> None:
        case_legitimate_promo["promo_uses_this_account"] = -1
        with pytest.raises(ValidationError):
            PromoSignals(**case_legitimate_promo)

    def test_negative_linked_device_count_rejected(self, case_legitimate_promo: dict) -> None:
        case_legitimate_promo["accounts_linked_same_device"] = -1
        with pytest.raises(ValidationError):
            PromoSignals(**case_legitimate_promo)

    def test_negative_referrer_age_rejected(self, case_suspicious_promo: dict) -> None:
        case_suspicious_promo["referrer_account_age_days"] = -5
        with pytest.raises(ValidationError):
            PromoSignals(**case_suspicious_promo)


# ---------------------------------------------------------------------------
# PromoVerdict -- valid construction
# ---------------------------------------------------------------------------

class TestPromoVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = PromoVerdict(
            verdict="block",
            confidence=0.96,
            primary_signals=["device_shared_with_referrer", "payout_requested_immediately", "accounts_linked_same_device"],
            reasoning="Self-referral ring: device shared with referrer, 6 accounts on same device, immediate payout.",
            recommended_action="Block promo redemption, freeze referral credit, and flag both accounts.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.96

    def test_allow_verdict(self) -> None:
        verdict = PromoVerdict(
            verdict="allow",
            confidence=0.90,
            primary_signals=["account_age_days", "accounts_linked_same_device"],
            reasoning="Mature account, first promo use, no device or IP clustering.",
            recommended_action="Allow promo redemption.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = PromoVerdict(
            verdict="step_up",
            confidence=0.60,
            primary_signals=["promo_uses_this_account", "account_age_days"],
            reasoning="New account with 4 promo uses in 10 days. Unusual but not conclusive.",
            recommended_action="Require phone OTP before applying promo benefit.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = PromoVerdict(
            verdict="escalate",
            confidence=0.55,
            primary_signals=["accounts_linked_same_ip"],
            reasoning="Three accounts from same IP using same trial code. Possible shared household.",
            recommended_action="Route to promotions fraud team for review.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = PromoVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["account_age_days"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# PromoVerdict -- constraint violations
# ---------------------------------------------------------------------------

class TestPromoVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            PromoVerdict(
                verdict="decline",
                confidence=0.9,
                primary_signals=["device_shared_with_referrer"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            PromoVerdict(
                verdict="block",
                confidence=1.1,
                primary_signals=["device_shared_with_referrer"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            PromoVerdict(
                verdict="allow",
                confidence=-0.1,
                primary_signals=["account_age_days"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            PromoVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            PromoVerdict(
                verdict="allow",
                confidence=0.9,
                primary_signals=[],
                reasoning="Test.",
                recommended_action="Test.",
            )
