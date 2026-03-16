"""
Pydantic schemas for the ATO (Account Takeover) Agent.

Defines the structured input signals and output verdict used by the ATO Agent.
"""

from typing import Literal

from pydantic import BaseModel, Field


class MockATOSignals(BaseModel):
    """Input signals provided to the ATO Agent for session evaluation."""

    account_id: str = Field(..., description="Unique identifier for the account")
    account_age_days: int = Field(..., description="How old the account is in days")
    is_new_device: bool = Field(..., description="Whether the login device has never been seen before")
    device_id: str = Field(..., description="Identifier for the login device")
    login_geo: str = Field(..., description="City and country of the current login")
    account_home_geo: str = Field(..., description="City and country where the account normally logs in")
    geo_mismatch: bool = Field(..., description="Whether login_geo differs from account_home_geo")
    time_since_last_login_days: int = Field(..., description="Days elapsed since the previous login")
    immediate_high_value_action: bool = Field(
        ...,
        description="Whether the user attempted a payout, booking, or purchase within 5 minutes of login",
    )
    email_change_attempted: bool = Field(..., description="Whether an email change was attempted this session")
    password_change_attempted: bool = Field(..., description="Whether a password change was attempted this session")
    support_ticket_language_match: bool = Field(
        ...,
        description="Whether the writing style in support tickets matches the account's historical style",
    )


class ATOVerdict(BaseModel):
    """Structured verdict returned by the ATO Agent after evaluating session signals."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision on how to handle the session"
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
