"""
Schema validation tests for the Identity Agent -- Version 2.

Tests cover:
- Valid construction of IdentitySignals and IdentityVerdict
- Field constraint enforcement (confidence bounds, verdict literals, signal list length, ge=0 fields)
- Three canonical identity test cases parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.identity_schemas import IdentitySignals, IdentityVerdict


# ---------------------------------------------------------------------------
# Shared fixtures -- three canonical identity test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_synthetic_identity() -> dict:
    """Case 1 -- Clear synthetic identity. Expected verdict: block."""
    return {
        "account_id": "acc_synth_001",
        "account_age_days": 1,
        "email_domain": "tempmail.io",
        "is_disposable_email": True,
        "phone_country_matches_ip_country": False,
        "address_provided": True,
        "address_is_commercial": True,
        "document_verification_passed": False,
        "pii_seen_on_other_accounts": 5,
        "accounts_created_from_same_device": 8,
        "accounts_created_from_same_ip": 12,
        "signup_velocity_same_ip_24h": 7,
        "name_dob_mismatch": True,
    }


@pytest.fixture
def case_legitimate_identity() -> dict:
    """Case 2 -- Clean legitimate account. Expected verdict: allow."""
    return {
        "account_id": "acc_real_002",
        "account_age_days": 730,
        "email_domain": "gmail.com",
        "is_disposable_email": False,
        "phone_country_matches_ip_country": True,
        "address_provided": True,
        "address_is_commercial": False,
        "document_verification_passed": True,
        "pii_seen_on_other_accounts": 0,
        "accounts_created_from_same_device": 1,
        "accounts_created_from_same_ip": 1,
        "signup_velocity_same_ip_24h": 1,
        "name_dob_mismatch": False,
    }


@pytest.fixture
def case_ambiguous_identity() -> dict:
    """Case 3 -- Ambiguous, some risk signals. Expected verdict: step_up."""
    return {
        "account_id": "acc_ambig_003",
        "account_age_days": 14,
        "email_domain": "protonmail.com",
        "is_disposable_email": False,
        "phone_country_matches_ip_country": False,
        "address_provided": False,
        "address_is_commercial": False,
        "document_verification_passed": True,
        "pii_seen_on_other_accounts": 1,
        "accounts_created_from_same_device": 2,
        "accounts_created_from_same_ip": 3,
        "signup_velocity_same_ip_24h": 2,
        "name_dob_mismatch": False,
    }


# ---------------------------------------------------------------------------
# IdentitySignals -- valid construction
# ---------------------------------------------------------------------------

class TestIdentitySignalsValid:
    def test_synthetic_identity_parses(self, case_synthetic_identity: dict) -> None:
        signals = IdentitySignals(**case_synthetic_identity)
        assert signals.account_id == "acc_synth_001"
        assert signals.is_disposable_email is True
        assert signals.pii_seen_on_other_accounts == 5
        assert signals.name_dob_mismatch is True

    def test_legitimate_identity_parses(self, case_legitimate_identity: dict) -> None:
        signals = IdentitySignals(**case_legitimate_identity)
        assert signals.account_id == "acc_real_002"
        assert signals.document_verification_passed is True
        assert signals.accounts_created_from_same_device == 1

    def test_ambiguous_identity_parses(self, case_ambiguous_identity: dict) -> None:
        signals = IdentitySignals(**case_ambiguous_identity)
        assert signals.account_id == "acc_ambig_003"
        assert signals.is_disposable_email is False
        assert signals.pii_seen_on_other_accounts == 1


# ---------------------------------------------------------------------------
# IdentitySignals -- invalid inputs
# ---------------------------------------------------------------------------

class TestIdentitySignalsInvalid:
    def test_missing_required_field(self, case_legitimate_identity: dict) -> None:
        del case_legitimate_identity["account_id"]
        with pytest.raises(ValidationError):
            IdentitySignals(**case_legitimate_identity)

    def test_negative_pii_count_rejected(self, case_legitimate_identity: dict) -> None:
        case_legitimate_identity["pii_seen_on_other_accounts"] = -1
        with pytest.raises(ValidationError):
            IdentitySignals(**case_legitimate_identity)

    def test_negative_device_count_rejected(self, case_legitimate_identity: dict) -> None:
        case_legitimate_identity["accounts_created_from_same_device"] = -1
        with pytest.raises(ValidationError):
            IdentitySignals(**case_legitimate_identity)

    def test_negative_velocity_rejected(self, case_legitimate_identity: dict) -> None:
        case_legitimate_identity["signup_velocity_same_ip_24h"] = -1
        with pytest.raises(ValidationError):
            IdentitySignals(**case_legitimate_identity)


# ---------------------------------------------------------------------------
# IdentityVerdict -- valid construction
# ---------------------------------------------------------------------------

class TestIdentityVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = IdentityVerdict(
            verdict="block",
            confidence=0.94,
            primary_signals=["pii_seen_on_other_accounts", "is_disposable_email", "document_verification_passed"],
            reasoning="Five other accounts share PII with this account, using a disposable email, and document verification failed.",
            recommended_action="Block account creation and flag for fraud team review.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.94

    def test_allow_verdict(self) -> None:
        verdict = IdentityVerdict(
            verdict="allow",
            confidence=0.91,
            primary_signals=["document_verification_passed", "pii_seen_on_other_accounts"],
            reasoning="Verified identity document, no PII overlap, legitimate email domain.",
            recommended_action="Allow account creation to proceed.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = IdentityVerdict(
            verdict="step_up",
            confidence=0.62,
            primary_signals=["phone_country_matches_ip_country", "accounts_created_from_same_ip"],
            reasoning="Phone country does not match signup IP. Three accounts from same IP.",
            recommended_action="Request additional phone OTP verification before granting access.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = IdentityVerdict(
            verdict="escalate",
            confidence=0.55,
            primary_signals=["name_dob_mismatch"],
            reasoning="Name and date of birth are inconsistent but document passed. Unusual pattern.",
            recommended_action="Route to identity review queue for manual investigation.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = IdentityVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["document_verification_passed"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# IdentityVerdict -- constraint violations
# ---------------------------------------------------------------------------

class TestIdentityVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerdict(
                verdict="approve",
                confidence=0.9,
                primary_signals=["document_verification_passed"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerdict(
                verdict="block",
                confidence=1.1,
                primary_signals=["pii_seen_on_other_accounts"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerdict(
                verdict="allow",
                confidence=-0.1,
                primary_signals=["document_verification_passed"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            IdentityVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=[],
                reasoning="Test.",
                recommended_action="Test.",
            )
