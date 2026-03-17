"""
Pydantic schemas for the Payment Agent.

Defines the structured input signals and output verdict used by the Payment Agent
to evaluate a transaction for payment fraud.
"""

from typing import Literal

from pydantic import BaseModel, Field


class PaymentSignals(BaseModel):
    """Input signals provided to the Payment Agent for transaction evaluation."""

    transaction_id: str = Field(..., description="Unique identifier for the transaction")
    account_id: str = Field(..., description="Account initiating the transaction")
    amount_usd: float = Field(..., gt=0, description="Transaction amount in USD")
    merchant_category: str = Field(
        ..., description="Category of the merchant (e.g. electronics, travel, gaming, grocery)"
    )
    merchant_country: str = Field(..., description="Country where the merchant is located")
    account_home_country: str = Field(..., description="Country where the account normally transacts")
    is_international: bool = Field(..., description="Whether the merchant country differs from the account home country")
    transactions_last_1h: int = Field(..., ge=0, description="Number of transactions in the last 1 hour")
    transactions_last_24h: int = Field(..., ge=0, description="Number of transactions in the last 24 hours")
    avg_transaction_amount_30d: float = Field(
        ..., gt=0, description="Average transaction amount over the past 30 days"
    )
    amount_vs_avg_ratio: float = Field(
        ..., gt=0, description="Ratio of current amount to 30-day average (e.g. 3.5 means 3.5x the average)"
    )
    is_first_transaction: bool = Field(..., description="Whether this is the account's first ever transaction")
    card_present: bool = Field(
        ..., description="Whether the physical card was present (True) or card-not-present / online (False)"
    )
    days_since_account_creation: int = Field(..., ge=0, description="Age of the account in days")


class PaymentVerdict(BaseModel):
    """Structured verdict returned by the Payment Agent after evaluating a transaction."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision on how to handle the transaction"
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
