"""
Pydantic schemas for the Ring Detection Agent.

Defines the structured input signals and output verdict used by the Ring Detection
Agent to identify coordinated fraud rings, shared-entity clusters, and known
ring signatures across accounts.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class RingSignals(BaseModel):
    """
    Input signals provided to the Ring Detection Agent.

    Ring Detection always runs regardless of routing tier. Its signals are
    cross-entity by nature, reasoning about network position rather than
    individual account behavior.
    """

    primary_entity_id: str = Field(..., description="The account or entity that is the primary subject of investigation")
    primary_entity_type: str = Field(
        ..., description="Entity type: 'account', 'buyer', 'seller', 'merchant', or 'user'"
    )
    device_id: str = Field(..., description="Device fingerprint for this session")
    ip_address_hash: str = Field(..., description="Hashed IP address used for cross-entity linking (not the raw IP)")
    accounts_sharing_device: int = Field(
        ..., ge=0, description="Number of distinct accounts observed on this device fingerprint"
    )
    accounts_sharing_ip: int = Field(
        ..., ge=0, description="Number of distinct accounts observed on this IP address in the last 30 days"
    )
    linked_account_ids: list[str] = Field(
        ..., description="Known accounts directly linked via shared PII, device fingerprint, or payment method"
    )
    linked_accounts_with_block_verdict: int = Field(
        ..., ge=0, description="How many of the linked accounts currently have an active block verdict"
    )
    linked_accounts_with_fraud_confirmed: int = Field(
        ..., ge=0, description="How many linked accounts have confirmed fraud from chargebacks or manual review"
    )
    shared_payment_method_across_accounts: bool = Field(
        ..., description="Whether this payment method appears on any other account in the system"
    )
    payment_method_account_count: int = Field(
        ..., ge=0, description="Total number of accounts sharing this payment method"
    )
    known_ring_signature_match: bool = Field(
        ...,
        description="Whether this entity matches a known ring signature in the intelligence store. "
                    "This is the highest-weight signal. True warrants block or escalate regardless of other signals.",
    )
    ring_signature_id: Optional[str] = Field(
        None, description="The identifier of the matched ring signature if known_ring_signature_match is True"
    )
    velocity_account_creation_same_ip_7d: int = Field(
        ..., ge=0, description="Number of new accounts created from the same IP in the last 7 days"
    )
    transaction_graph_min_hops_to_fraud: int = Field(
        ..., ge=0, description="Shortest path in hops from this entity to any confirmed fraud node in the transaction graph"
    )


class RingVerdict(BaseModel):
    """Structured verdict returned by the Ring Detection Agent after evaluating network connections."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision based on ring membership and network position"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    primary_signals: list[str] = Field(
        ...,
        min_length=1,
        max_length=3,
        description="The 2-3 signals that most influenced the verdict",
    )
    reasoning: str = Field(..., description="Plain English explanation of why this verdict was issued")
    recommended_action: str = Field(..., description="What the platform should do next based on this verdict")
