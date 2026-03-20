"""
InvestigationRecord schema -- output of the Sentinel Investigation Agent.

Produced asynchronously after the Execution System on cases where
arbiter_output.trigger_async is True. Stored in the memory store and
used for pattern clustering, verdict auditing, and future model improvement.
"""

from typing import Optional

from pydantic import BaseModel, Field

from src.schemas.risk_vector import RiskVector


class InvestigationRecord(BaseModel):
    """Full investigation output produced by Sentinel for a single case."""

    case_id: str = Field(..., description="UUID uniquely identifying this investigation record.")
    arbiter_verdict: str = Field(..., description="Verdict issued by the Arbiter: block, allow, step_up, or escalate.")
    arbiter_confidence: float = Field(..., ge=0.0, le=1.0, description="Arbiter confidence in its verdict.")
    trigger_reason: Optional[str] = Field(None, description="The trigger_reason from ArbiterOutput that caused this investigation.")
    risk_vector: RiskVector = Field(..., description="Full RiskVector from the risk aggregation node.")
    enriched_signals: dict = Field(default_factory=dict, description="Structured output from enrichment tool calls.")
    memory_matches: list[dict] = Field(default_factory=list, description="Full records of similar past investigations.")
    investigation_narrative: str = Field(..., description="Sentinel's plain English narrative synthesizing all available evidence.")
    pattern_tags: list[str] = Field(..., description="Structured labels for case clustering. E.g. ring_fraud, bot_session, new_account.")
    assessment: str = Field(..., description="Sentinel's verdict assessment: correct, possible_false_positive, or uncertain.")
    created_at: str = Field(..., description="ISO 8601 timestamp of when the investigation was run.")
    tool_trace: list[dict] = Field(
        default_factory=list,
        description=(
            "Ordered log of tool calls made by the ReAct agent. "
            "Each entry: tool_name, arguments, result_summary, call_order."
        ),
    )
