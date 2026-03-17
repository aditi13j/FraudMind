"""
Schema validation tests for the Ring Detection Agent -- Version 2.

Tests cover:
- Valid construction of RingSignals and RingVerdict
- Field constraint enforcement (confidence bounds, verdict literals, ge=0 fields)
- Three canonical ring detection test cases parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.ring_schemas import RingSignals, RingVerdict


# ---------------------------------------------------------------------------
# Shared fixtures -- three canonical ring detection test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_confirmed_ring_member() -> dict:
    """Case 1 -- Known ring member with signature match. Expected verdict: block."""
    return {
        "primary_entity_id": "acc_ring_001",
        "primary_entity_type": "user",
        "device_id": "dev_shared_factory_01",
        "ip_address_hash": "hash_known_ring_ip",
        "accounts_sharing_device": 22,
        "accounts_sharing_ip": 15,
        "linked_account_ids": ["acc_ring_002", "acc_ring_003", "acc_ring_004"],
        "linked_accounts_with_block_verdict": 3,
        "linked_accounts_with_fraud_confirmed": 2,
        "shared_payment_method_across_accounts": True,
        "payment_method_account_count": 7,
        "known_ring_signature_match": True,
        "ring_signature_id": "ring_WEST_AFRICA_001",
        "velocity_account_creation_same_ip_7d": 18,
        "transaction_graph_min_hops_to_fraud": 1,
    }


@pytest.fixture
def case_isolated_entity() -> dict:
    """Case 2 -- Clean isolated entity. Expected verdict: allow."""
    return {
        "primary_entity_id": "acc_clean_002",
        "primary_entity_type": "user",
        "device_id": "dev_personal_laptop",
        "ip_address_hash": "hash_home_ip",
        "accounts_sharing_device": 1,
        "accounts_sharing_ip": 1,
        "linked_account_ids": [],
        "linked_accounts_with_block_verdict": 0,
        "linked_accounts_with_fraud_confirmed": 0,
        "shared_payment_method_across_accounts": False,
        "payment_method_account_count": 1,
        "known_ring_signature_match": False,
        "ring_signature_id": None,
        "velocity_account_creation_same_ip_7d": 1,
        "transaction_graph_min_hops_to_fraud": 99,
    }


@pytest.fixture
def case_suspicious_cluster() -> dict:
    """Case 3 -- Suspicious cluster without confirmed ring match. Expected verdict: escalate."""
    return {
        "primary_entity_id": "acc_cluster_003",
        "primary_entity_type": "user",
        "device_id": "dev_shared_003",
        "ip_address_hash": "hash_shared_ip_003",
        "accounts_sharing_device": 5,
        "accounts_sharing_ip": 8,
        "linked_account_ids": ["acc_cluster_004", "acc_cluster_005"],
        "linked_accounts_with_block_verdict": 1,
        "linked_accounts_with_fraud_confirmed": 0,
        "shared_payment_method_across_accounts": True,
        "payment_method_account_count": 3,
        "known_ring_signature_match": False,
        "ring_signature_id": None,
        "velocity_account_creation_same_ip_7d": 6,
        "transaction_graph_min_hops_to_fraud": 2,
    }


# ---------------------------------------------------------------------------
# RingSignals -- valid construction
# ---------------------------------------------------------------------------

class TestRingSignalsValid:
    def test_confirmed_ring_member_parses(self, case_confirmed_ring_member: dict) -> None:
        signals = RingSignals(**case_confirmed_ring_member)
        assert signals.primary_entity_id == "acc_ring_001"
        assert signals.known_ring_signature_match is True
        assert signals.ring_signature_id == "ring_WEST_AFRICA_001"
        assert len(signals.linked_account_ids) == 3

    def test_isolated_entity_parses(self, case_isolated_entity: dict) -> None:
        signals = RingSignals(**case_isolated_entity)
        assert signals.primary_entity_id == "acc_clean_002"
        assert signals.known_ring_signature_match is False
        assert signals.ring_signature_id is None
        assert signals.linked_account_ids == []

    def test_suspicious_cluster_parses(self, case_suspicious_cluster: dict) -> None:
        signals = RingSignals(**case_suspicious_cluster)
        assert signals.primary_entity_id == "acc_cluster_003"
        assert signals.accounts_sharing_device == 5
        assert signals.transaction_graph_min_hops_to_fraud == 2


# ---------------------------------------------------------------------------
# RingSignals -- invalid inputs
# ---------------------------------------------------------------------------

class TestRingSignalsInvalid:
    def test_missing_required_field(self, case_isolated_entity: dict) -> None:
        del case_isolated_entity["primary_entity_id"]
        with pytest.raises(ValidationError):
            RingSignals(**case_isolated_entity)

    def test_negative_device_sharing_rejected(self, case_isolated_entity: dict) -> None:
        case_isolated_entity["accounts_sharing_device"] = -1
        with pytest.raises(ValidationError):
            RingSignals(**case_isolated_entity)

    def test_negative_linked_block_count_rejected(self, case_isolated_entity: dict) -> None:
        case_isolated_entity["linked_accounts_with_block_verdict"] = -1
        with pytest.raises(ValidationError):
            RingSignals(**case_isolated_entity)

    def test_negative_velocity_rejected(self, case_isolated_entity: dict) -> None:
        case_isolated_entity["velocity_account_creation_same_ip_7d"] = -1
        with pytest.raises(ValidationError):
            RingSignals(**case_isolated_entity)


# ---------------------------------------------------------------------------
# RingVerdict -- valid construction
# ---------------------------------------------------------------------------

class TestRingVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = RingVerdict(
            verdict="block",
            confidence=0.97,
            primary_signals=["known_ring_signature_match", "transaction_graph_min_hops_to_fraud", "linked_accounts_with_fraud_confirmed"],
            reasoning="Matched known ring signature, 1 hop from confirmed fraud node, 2 linked confirmed fraud accounts.",
            recommended_action="Block entity immediately and freeze all linked accounts.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.97

    def test_allow_verdict(self) -> None:
        verdict = RingVerdict(
            verdict="allow",
            confidence=0.92,
            primary_signals=["known_ring_signature_match", "linked_account_ids"],
            reasoning="No ring signature match, no linked accounts, isolated device and IP.",
            recommended_action="Allow. No ring indicators detected.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = RingVerdict(
            verdict="step_up",
            confidence=0.60,
            primary_signals=["accounts_sharing_device", "linked_accounts_with_block_verdict"],
            reasoning="Device shared with 5 accounts, one linked account has a block verdict.",
            recommended_action="Require additional verification before proceeding.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = RingVerdict(
            verdict="escalate",
            confidence=0.65,
            primary_signals=["accounts_sharing_ip", "transaction_graph_min_hops_to_fraud"],
            reasoning="Suspicious cluster at 2 graph hops from confirmed fraud but no signature match.",
            recommended_action="Escalate to fraud ring investigation team.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = RingVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["known_ring_signature_match"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# RingVerdict -- constraint violations
# ---------------------------------------------------------------------------

class TestRingVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            RingVerdict(
                verdict="flag",
                confidence=0.9,
                primary_signals=["known_ring_signature_match"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            RingVerdict(
                verdict="block",
                confidence=1.1,
                primary_signals=["known_ring_signature_match"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            RingVerdict(
                verdict="allow",
                confidence=-0.1,
                primary_signals=["linked_account_ids"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            RingVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            RingVerdict(
                verdict="allow",
                confidence=0.9,
                primary_signals=[],
                reasoning="Test.",
                recommended_action="Test.",
            )
