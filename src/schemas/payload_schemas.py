"""
Pydantic schemas for the Payload Specialist Agent.

Defines the structured input signals and output verdict used by the Payload Agent
to detect bot attacks, automation frameworks, TLS anomalies, and scripted sessions.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class PayloadSignals(BaseModel):
    """Input signals provided to the Payload Agent for session automation detection."""

    session_id: str = Field(..., description="Unique identifier for this session")
    account_id: str = Field(..., description="Account under evaluation")
    user_agent_string: str = Field(..., description="Raw User-Agent header value as sent by the client")
    user_agent_is_headless: bool = Field(
        ..., description="Whether the User-Agent indicates a headless browser (e.g. HeadlessChrome, PhantomJS)"
    )
    tls_fingerprint_ja3: str = Field(..., description="JA3 TLS fingerprint hash for this connection")
    tls_fingerprint_known_bot: bool = Field(
        ..., description="Whether the JA3 hash matches a known bot or automation tool fingerprint"
    )
    http_header_order_anomaly: bool = Field(
        ..., description="Whether the order of HTTP request headers differs from standard browser ordering"
    )
    accept_language_missing: bool = Field(
        ..., description="Whether the Accept-Language header was absent (common in scripted requests)"
    )
    mouse_movement_entropy: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Entropy score of mouse and pointer movements during the session (0.0 = no movement, 1.0 = fully human-like). None if not measurable."
    )
    keystroke_dynamics_score: Optional[float] = Field(
        None, ge=0.0, le=1.0,
        description="Behavioral biometric similarity to this account's known typing pattern. None if no baseline exists."
    )
    requests_per_minute: float = Field(
        ..., ge=0.0, description="Rate of HTTP requests per minute for this session"
    )
    request_timing_variance_ms: float = Field(
        ..., ge=0.0,
        description="Standard deviation of inter-request timing in milliseconds. "
                    "Values below 10ms indicate machine-like precision.",
    )
    captcha_solve_time_ms: Optional[int] = Field(
        None, ge=0,
        description="Time in milliseconds to solve a CAPTCHA challenge. None if no CAPTCHA was presented."
    )
    captcha_solve_pattern_automated: Optional[bool] = Field(
        None,
        description="Whether the CAPTCHA solve timing or pattern matches known automated solver signatures. None if no CAPTCHA was presented."
    )
    credential_stuffing_ip_on_blocklist: bool = Field(
        ..., description="Whether the source IP appears on a credential-stuffing or bot IP blocklist"
    )
    login_attempt_count_this_session: int = Field(
        ..., ge=1, description="Number of login attempts in this session (1 = first try, higher values indicate retry or stuffing patterns)"
    )
    api_endpoint_sequence_anomaly: bool = Field(
        ..., description="Whether the sequence of API endpoint calls differs from typical human navigation patterns"
    )


class PayloadVerdict(BaseModel):
    """Structured verdict returned by the Payload Agent after evaluating session automation signals."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The agent's decision on how to handle this session"
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
