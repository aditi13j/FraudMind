"""
Pydantic schemas for the Promo Agent.

Defines the structured input signals and output verdict used by the Promo Agent
to evaluate a promo code redemption for incentive abuse.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class PromoSignals(BaseModel):
    """Input signals provided to the Promo Agent for promo redemption evaluation."""

    account_id: str = Field(..., description="Account attempting to redeem the promo")
    promo_code: str = Field(..., description="The promo or coupon code being applied")
    promo_type: str = Field(
        ..., description="Type of incentive: 'referral', 'trial', 'coupon', or 'loyalty_credit'"
    )
    account_age_days: int = Field(..., ge=0, description="Age of the account in days")
    is_first_order: bool = Field(..., description="Whether this is the account's first order on the platform")
    promo_uses_this_account: int = Field(
        ..., ge=0, description="Total number of promo codes this account has ever redeemed"
    )
    promo_uses_same_code: int = Field(
        ..., ge=0, description="Number of times this account has redeemed this specific promo code"
    )
    accounts_linked_same_device: int = Field(
        ..., ge=0, description="Number of accounts that have used this promo code from the same device fingerprint"
    )
    accounts_linked_same_ip: int = Field(
        ..., ge=0, description="Number of accounts that have used this promo code from the same IP address"
    )
    referrer_account_id: Optional[str] = Field(
        None, description="Account ID that generated this referral code, if applicable"
    )
    referrer_account_age_days: Optional[int] = Field(
        None, ge=0, description="Age in days of the referring account, if applicable"
    )
    device_shared_with_referrer: bool = Field(
        ..., description="Whether this account and the referrer account share a device fingerprint (self-referral signal)"
    )
    email_domain_pattern_suspicious: bool = Field(
        ...,
        description="Whether the account email follows a synthetic variation pattern (e.g. user+1@domain.com, user+2@domain.com)",
    )
    order_cancelled_after_promo: bool = Field(
        ..., description="Whether prior orders on this account were cancelled after a promo benefit was redeemed"
    )
    payout_requested_immediately: bool = Field(
        ...,
        description="Whether a payout or credit export was requested within 10 minutes of promo redemption",
    )


class PromoVerdict(BaseModel):
    """Structured verdict returned by the Promo Agent after evaluating a promo redemption."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision on how to handle this promo redemption"
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
