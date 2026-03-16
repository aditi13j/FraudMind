"""
Basic schema validation tests for the ATO Agent — Version 0.

Tests cover:
- Valid construction of MockATOSignals and ATOVerdict
- Field constraint enforcement (confidence bounds, verdict literals, signal list length)
- The three canonical test cases from CLAUDE.md parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.ato_schemas import ATOVerdict, MockATOSignals

# ---------------------------------------------------------------------------
# Shared fixtures — the three canonical Version 0 test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_clear_ato() -> dict:
    """Case 1 — Clear ATO. Expected verdict: block."""
    return {
        "account_id": "acc_001",
        "account_age_days": 210,
        "is_new_device": True,
        "device_id": "dev_unknown_001",
        "login_geo": "Lagos, Nigeria",
        "account_home_geo": "San Jose, CA",
        "geo_mismatch": True,
        "time_since_last_login_days": 2,
        "immediate_high_value_action": True,
        "email_change_attempted": True,
        "password_change_attempted": False,
        "support_ticket_language_match": False,
    }


@pytest.fixture
def case_clean_login() -> dict:
    """Case 2 — Clean legitimate login. Expected verdict: allow."""
    return {
        "account_id": "acc_002",
        "account_age_days": 847,
        "is_new_device": False,
        "device_id": "dev_trusted_047",
        "login_geo": "San Jose, CA",
        "account_home_geo": "San Jose, CA",
        "geo_mismatch": False,
        "time_since_last_login_days": 1,
        "immediate_high_value_action": False,
        "email_change_attempted": False,
        "password_change_attempted": False,
        "support_ticket_language_match": True,
    }


@pytest.fixture
def case_ambiguous() -> dict:
    """Case 3 — Ambiguous session. Expected verdict: step_up."""
    return {
        "account_id": "acc_003",
        "account_age_days": 430,
        "is_new_device": True,
        "device_id": "dev_unknown_002",
        "login_geo": "London, UK",
        "account_home_geo": "New York, NY",
        "geo_mismatch": True,
        "time_since_last_login_days": 12,
        "immediate_high_value_action": False,
        "email_change_attempted": False,
        "password_change_attempted": False,
        "support_ticket_language_match": True,
    }


# ---------------------------------------------------------------------------
# MockATOSignals — valid construction
# ---------------------------------------------------------------------------

class TestMockATOSignalsValid:
    def test_case_clear_ato_parses(self, case_clear_ato: dict) -> None:
        signals = MockATOSignals(**case_clear_ato)
        assert signals.account_id == "acc_001"
        assert signals.is_new_device is True
        assert signals.geo_mismatch is True
        assert signals.email_change_attempted is True

    def test_case_clean_login_parses(self, case_clean_login: dict) -> None:
        signals = MockATOSignals(**case_clean_login)
        assert signals.account_id == "acc_002"
        assert signals.is_new_device is False
        assert signals.geo_mismatch is False
        assert signals.account_age_days == 847

    def test_case_ambiguous_parses(self, case_ambiguous: dict) -> None:
        signals = MockATOSignals(**case_ambiguous)
        assert signals.account_id == "acc_003"
        assert signals.is_new_device is True
        assert signals.immediate_high_value_action is False


# ---------------------------------------------------------------------------
# MockATOSignals — invalid inputs
# ---------------------------------------------------------------------------

class TestMockATOSignalsInvalid:
    def test_missing_required_field(self, case_clear_ato: dict) -> None:
        del case_clear_ato["account_id"]
        with pytest.raises(ValidationError):
            MockATOSignals(**case_clear_ato)

    def test_wrong_type_for_bool_field(self, case_clean_login: dict) -> None:
        case_clean_login["is_new_device"] = "yes"  # string instead of bool
        # Pydantic v2 coerces "yes" → True for bool fields, so no error expected.
        # Confirm it at least parses without crashing.
        signals = MockATOSignals(**case_clean_login)
        assert isinstance(signals.is_new_device, bool)

    def test_wrong_type_for_int_field(self, case_clean_login: dict) -> None:
        case_clean_login["account_age_days"] = "not-a-number"
        with pytest.raises(ValidationError):
            MockATOSignals(**case_clean_login)


# ---------------------------------------------------------------------------
# ATOVerdict — valid construction
# ---------------------------------------------------------------------------

class TestATOVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = ATOVerdict(
            verdict="block",
            confidence=0.95,
            primary_signals=["geo_mismatch", "email_change_attempted", "immediate_high_value_action"],
            reasoning="New device logging in from a foreign country with an immediate email change and payout request.",
            recommended_action="Block the session and lock the account pending owner verification.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.95
        assert len(verdict.primary_signals) == 3

    def test_allow_verdict(self) -> None:
        verdict = ATOVerdict(
            verdict="allow",
            confidence=0.92,
            primary_signals=["known_device", "matching_geo"],
            reasoning="Trusted device from the account's home location with no sensitive actions.",
            recommended_action="Allow the session to proceed normally.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = ATOVerdict(
            verdict="step_up",
            confidence=0.60,
            primary_signals=["is_new_device", "geo_mismatch"],
            reasoning="New device from a location the account has visited before.",
            recommended_action="Prompt for MFA before allowing further actions.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = ATOVerdict(
            verdict="escalate",
            confidence=0.55,
            primary_signals=["support_ticket_language_match"],
            reasoning="Unusual pattern that does not fit a standard ATO profile.",
            recommended_action="Route to fraud review queue.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = ATOVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["known_device"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# ATOVerdict — constraint violations
# ---------------------------------------------------------------------------

class TestATOVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="challenge",  # not a valid literal (renamed to step_up)
                confidence=0.9,
                primary_signals=["geo_mismatch"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="block",
                confidence=1.1,
                primary_signals=["geo_mismatch"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="allow",
                confidence=-0.1,
                primary_signals=["known_device"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],  # max is 3
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=[],  # min is 1
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_missing_required_field(self) -> None:
        with pytest.raises(ValidationError):
            ATOVerdict(
                verdict="block",
                confidence=0.9,
                # primary_signals missing
                reasoning="Test.",
                recommended_action="Test.",
            )
