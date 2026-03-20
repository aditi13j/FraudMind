"""
InvestigationRecord schema -- output of the Sentinel Investigation Agent.

Produced asynchronously after the Execution System on cases where
arbiter_output.trigger_async is True. Stored in the memory store and
used for pattern clustering, verdict auditing, and future model improvement.
"""

from typing import Literal

from pydantic import BaseModel, Field


class InvestigationRecord(BaseModel):
    """Full investigation output produced by Sentinel for a single case."""

    case_id: str = Field(
        ..., description="UUID uniquely identifying this investigation record."
    )
    entity_id: str = Field(
        ..., description="The primary entity (account, buyer, etc.) that was investigated."
    )
    timestamp: str = Field(
        ..., description="ISO 8601 timestamp of when the investigation was run."
    )

    # Arbiter context
    arbiter_verdict: str = Field(
        ..., description="The verdict issued by the Arbiter: block, allow, step_up, or escalate."
    )
    arbiter_confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Arbiter confidence in its verdict."
    )
    arbiter_reasoning: str = Field(
        ..., description="Plain English reasoning from the Arbiter."
    )

    # Risk vector summary
    risk_vector_aggregate: float = Field(
        ..., ge=0.0, le=1.0, description="Weighted aggregate risk score from the RiskVector."
    )
    risk_vector_dominant_domain: str = Field(
        ..., description="The specialist domain with the highest individual score."
    )

    # Memory
    memory_matches: list[str] = Field(
        default_factory=list,
        description="case_ids of past InvestigationRecords with overlapping pattern_tags.",
    )

    # Enrichment
    enriched_signals: dict = Field(
        default_factory=dict,
        description="Structured output from mock enrichment tool calls (IP, device, entity history).",
    )

    # LLM synthesis
    investigation_narrative: str = Field(
        ..., description="Sentinel's plain English narrative synthesizing all available evidence."
    )
    pattern_tags: list[str] = Field(
        ...,
        description=(
            "Structured labels assigned by Sentinel for case clustering. "
            "Examples: ring_fraud, ato, new_account, cross_border, bot_session."
        ),
    )

    # Verdict audit
    verdict_assessment: Literal["correct", "possible_false_positive", "uncertain"] = Field(
        ...,
        description=(
            "Sentinel's assessment of whether the Arbiter verdict was correct. "
            "correct: evidence supports the verdict. "
            "possible_false_positive: evidence suggests a legitimate user was incorrectly flagged. "
            "uncertain: insufficient evidence to audit the verdict."
        ),
    )
    confidence_in_assessment: float = Field(
        ..., ge=0.0, le=1.0, description="Sentinel's confidence in its own verdict assessment."
    )

    # Trigger context
    trigger_reason: str = Field(
        ..., description="The trigger_reason from ArbiterOutput that caused this investigation."
    )
