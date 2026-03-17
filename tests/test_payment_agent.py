"""
Schema validation tests for the Payment Agent -- Version 1.

Tests cover:
- Valid construction of PaymentSignals and PaymentVerdict
- Field constraint enforcement (confidence bounds, verdict literals, signal list length, amount > 0)
- Three canonical payment test cases parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.payment_schemas import PaymentSignals, PaymentVerdict


# ---------------------------------------------------------------------------
# Shared fixtures -- three canonical Version 1 payment test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_fraudulent_payment() -> dict:
    """Case 1 -- Clear payment fraud. Expected verdict: decline."""
    return {
        "transaction_id": "txn_001",
        "account_id": "acc_001",
        "amount_usd": 2400.00,
        "merchant_category": "electronics",
        "merchant_country": "Nigeria",
        "account_home_country": "United States",
        "is_international": True,
        "transactions_last_1h": 8,
        "transactions_last_24h": 14,
        "avg_transaction_amount_30d": 85.00,
        "amount_vs_avg_ratio": 28.2,
        "is_first_transaction": False,
        "card_present": False,
        "days_since_account_creation": 3,
    }


@pytest.fixture
def case_legitimate_payment() -> dict:
    """Case 2 -- Clean legitimate transaction. Expected verdict: approve."""
    return {
        "transaction_id": "txn_002",
        "account_id": "acc_002",
        "amount_usd": 94.50,
        "merchant_category": "grocery",
        "merchant_country": "United States",
        "account_home_country": "United States",
        "is_international": False,
        "transactions_last_1h": 1,
        "transactions_last_24h": 3,
        "avg_transaction_amount_30d": 88.00,
        "amount_vs_avg_ratio": 1.07,
        "is_first_transaction": False,
        "card_present": True,
        "days_since_account_creation": 847,
    }


@pytest.fixture
def case_suspicious_payment() -> dict:
    """Case 3 -- Suspicious velocity. Expected verdict: review or step_up."""
    return {
        "transaction_id": "txn_003",
        "account_id": "acc_003",
        "amount_usd": 310.00,
        "merchant_category": "gaming",
        "merchant_country": "United Kingdom",
        "account_home_country": "United States",
        "is_international": True,
        "transactions_last_1h": 6,
        "transactions_last_24h": 9,
        "avg_transaction_amount_30d": 120.00,
        "amount_vs_avg_ratio": 2.58,
        "is_first_transaction": False,
        "card_present": False,
        "days_since_account_creation": 430,
    }


# ---------------------------------------------------------------------------
# PaymentSignals -- valid construction
# ---------------------------------------------------------------------------

class TestPaymentSignalsValid:
    def test_fraudulent_payment_parses(self, case_fraudulent_payment: dict) -> None:
        signals = PaymentSignals(**case_fraudulent_payment)
        assert signals.transaction_id == "txn_001"
        assert signals.is_international is True
        assert signals.transactions_last_1h == 8
        assert signals.amount_vs_avg_ratio == pytest.approx(28.2)

    def test_legitimate_payment_parses(self, case_legitimate_payment: dict) -> None:
        signals = PaymentSignals(**case_legitimate_payment)
        assert signals.account_id == "acc_002"
        assert signals.card_present is True
        assert signals.is_international is False

    def test_suspicious_payment_parses(self, case_suspicious_payment: dict) -> None:
        signals = PaymentSignals(**case_suspicious_payment)
        assert signals.transaction_id == "txn_003"
        assert signals.merchant_category == "gaming"
        assert signals.days_since_account_creation == 430


# ---------------------------------------------------------------------------
# PaymentSignals -- invalid inputs
# ---------------------------------------------------------------------------

class TestPaymentSignalsInvalid:
    def test_missing_required_field(self, case_legitimate_payment: dict) -> None:
        del case_legitimate_payment["transaction_id"]
        with pytest.raises(ValidationError):
            PaymentSignals(**case_legitimate_payment)

    def test_amount_zero_rejected(self, case_legitimate_payment: dict) -> None:
        case_legitimate_payment["amount_usd"] = 0
        with pytest.raises(ValidationError):
            PaymentSignals(**case_legitimate_payment)

    def test_amount_negative_rejected(self, case_legitimate_payment: dict) -> None:
        case_legitimate_payment["amount_usd"] = -50.0
        with pytest.raises(ValidationError):
            PaymentSignals(**case_legitimate_payment)

    def test_negative_velocity_rejected(self, case_legitimate_payment: dict) -> None:
        case_legitimate_payment["transactions_last_1h"] = -1
        with pytest.raises(ValidationError):
            PaymentSignals(**case_legitimate_payment)

    def test_wrong_type_for_bool_field(self, case_suspicious_payment: dict) -> None:
        case_suspicious_payment["card_present"] = "yes"
        signals = PaymentSignals(**case_suspicious_payment)
        assert isinstance(signals.card_present, bool)


# ---------------------------------------------------------------------------
# PaymentVerdict -- valid construction
# ---------------------------------------------------------------------------

class TestPaymentVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = PaymentVerdict(
            verdict="block",
            confidence=0.95,
            primary_signals=["amount_vs_avg_ratio", "transactions_last_1h", "is_international"],
            reasoning="Transaction is 28x the account average from a new account with 8 transactions in the last hour.",
            recommended_action="Block the transaction and flag the account for fraud review.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.95
        assert len(verdict.primary_signals) == 3

    def test_allow_verdict(self) -> None:
        verdict = PaymentVerdict(
            verdict="allow",
            confidence=0.91,
            primary_signals=["card_present", "amount_vs_avg_ratio"],
            reasoning="In-store purchase close to the account average with normal velocity.",
            recommended_action="Allow the transaction.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = PaymentVerdict(
            verdict="step_up",
            confidence=0.63,
            primary_signals=["is_international", "card_present"],
            reasoning="International card-not-present transaction with mildly elevated amount.",
            recommended_action="Trigger a 3DS challenge before authorizing.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = PaymentVerdict(
            verdict="escalate",
            confidence=0.55,
            primary_signals=["transactions_last_1h", "merchant_category"],
            reasoning="Unusual velocity in a gaming merchant category.",
            recommended_action="Route to fraud analyst queue.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = PaymentVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["card_present"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# PaymentVerdict -- constraint violations
# ---------------------------------------------------------------------------

class TestPaymentVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="approve",  # not a valid literal for PaymentVerdict
                confidence=0.9,
                primary_signals=["card_present"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="allow",
                confidence=1.1,
                primary_signals=["card_present"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="block",
                confidence=-0.1,
                primary_signals=["amount_vs_avg_ratio"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],  # max is 3
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="allow",
                confidence=0.9,
                primary_signals=[],  # min is 1
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_missing_required_field(self) -> None:
        with pytest.raises(ValidationError):
            PaymentVerdict(
                verdict="decline",
                confidence=0.9,
                # primary_signals missing
                reasoning="Test.",
                recommended_action="Test.",
            )
