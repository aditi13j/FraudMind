"""
InvestigationRecord schema -- output of the Sentinel Investigation Agent.

Produced asynchronously after the Execution System on cases where
arbiter_output.trigger_async is True. Stored in the memory store and
used for pattern clustering, verdict auditing, and future model improvement.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field

from src.schemas.risk_vector import RiskVector


class InvestigationRecord(BaseModel):
    """Full investigation output produced by Sentinel for a single case."""

    case_id: str = Field(..., description="UUID uniquely identifying this investigation record.")
    entity_id: Optional[str] = Field(None, description="The primary entity (account/user) under investigation.")
    arbiter_verdict: str = Field(..., description="Verdict issued by the Arbiter: block, allow, step_up, or escalate.")
    arbiter_confidence: float = Field(..., ge=0.0, le=1.0, description="Arbiter confidence in its verdict.")
    amount_usd: Optional[float] = Field(
        default=None,
        description="Transaction amount in USD associated with this case. Used for financial impact metrics.",
    )
    trigger_reason: Optional[str] = Field(None, description="The trigger_reason from ArbiterOutput that caused this investigation.")
    analyst_verdict: Optional[Literal["confirm_fraud", "false_positive", "uncertain"]] = Field(
        default=None,
        description="Label applied by a human analyst after reviewing this case.",
    )
    risk_vector: RiskVector = Field(..., description="Full RiskVector from the risk aggregation node.")
    enriched_signals: dict = Field(default_factory=dict, description="Structured output from enrichment tool calls.")
    memory_matches: list[dict] = Field(default_factory=list, description="Full records of similar past investigations.")
    investigation_narrative: str = Field(..., description="Sentinel's plain English narrative synthesizing all available evidence.")
    pattern_tags: list[str] = Field(..., description="Structured labels for case clustering. E.g. ring_fraud, bot_session, new_account.")
    assessment: str = Field(..., description="Sentinel's verdict assessment: correct, possible_false_positive, or uncertain.")
    created_at: str = Field(..., description="ISO 8601 timestamp of when the investigation was run.")
    hypothesis: Optional[str] = Field(
        default=None,
        description="One-sentence fraud hypothesis generated before investigation begins.",
    )
    hypothesis_outcome: Optional[Literal["confirmed", "refuted", "ambiguous"]] = Field(
        default=None,
        description=(
            "Whether the investigation evidence confirmed or refuted the pre-generated hypothesis. "
            "confirmed: evidence supports the hypothesis. "
            "refuted: evidence contradicts it. "
            "ambiguous: mixed or inconclusive evidence."
        ),
    )
    investigation_plan: Optional[list[str]] = Field(
        default=None,
        description="Three-step plan generated before the ReAct tool loop.",
    )
    tool_trace: list[dict] = Field(
        default_factory=list,
        description=(
            "Ordered log of tool calls made by the ReAct agent. "
            "Each entry: tool_name, arguments, result_summary, call_order."
        ),
    )
