"""
Pydantic schemas for the Identity Agent.

Defines the structured input signals and output verdict used by the Identity Agent
to evaluate an account for synthetic identity fraud and fake account creation.
"""

from typing import Literal

from pydantic import BaseModel, Field


class IdentitySignals(BaseModel):
    """Input signals provided to the Identity Agent for account identity evaluation."""

    account_id: str = Field(..., description="Account under evaluation")
    account_age_days: int = Field(..., ge=0, description="Days since the account was created")
    email_domain: str = Field(..., description="Domain portion of the account email (e.g. gmail.com, tempmail.io)")
    is_disposable_email: bool = Field(..., description="Whether the email domain is on a known disposable or temp-mail list")
    phone_country_matches_ip_country: bool = Field(
        ..., description="Whether the phone number country code matches the country of the signup IP"
    )
    address_provided: bool = Field(..., description="Whether a physical address was submitted at signup")
    address_is_commercial: bool = Field(
        ..., description="Whether the address resolves to a commercial address such as a UPS store or virtual mailbox"
    )
    document_verification_passed: bool = Field(
        ..., description="Whether the KYC document verification check returned a passing result"
    )
    pii_seen_on_other_accounts: int = Field(
        ..., ge=0, description="Count of other accounts sharing one or more PII fields (name, phone, address) with this account"
    )
    accounts_created_from_same_device: int = Field(
        ..., ge=0, description="Number of accounts created using the same device fingerprint"
    )
    accounts_created_from_same_ip: int = Field(
        ..., ge=0, description="Number of accounts created from this IP address in the last 30 days"
    )
    signup_velocity_same_ip_24h: int = Field(
        ..., ge=0, description="Number of new account signups from this IP in the last 24 hours"
    )
    name_dob_mismatch: bool = Field(
        ..., description="Whether the submitted name and date of birth are inconsistent with each other or unverifiable"
    )


class IdentityVerdict(BaseModel):
    """Structured verdict returned by the Identity Agent after evaluating an account's identity."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision on how to handle this account"
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
