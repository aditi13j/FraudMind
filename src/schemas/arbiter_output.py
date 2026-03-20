"""
ArbiterOutput schema -- output of the Arbiter node.

The Arbiter is the only verdict producer in FraudMind v2. It reads the
RiskVector from the risk aggregation node and issues one of four verdicts.
This schema is consumed by the Execution System.
"""

from typing import Literal, Optional

from pydantic import BaseModel, Field


class ArbiterOutput(BaseModel):
    """Verdict produced by the Arbiter after synthesizing the RiskVector."""

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ...,
        description="Final disposition. block/allow are high-confidence. step_up adds friction. escalate routes to human review.",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Arbiter confidence in the verdict. Deterministic paths yield higher values than LLM synthesis.",
    )
    reasoning: str = Field(
        ...,
        description="Plain English explanation of why this verdict was issued, referencing the signals that drove it.",
    )
    evidence: list[str] = Field(
        ...,
        description="Specific signal names that most influenced the verdict, drawn from specialist primary_signals.",
    )
    trigger_async: bool = Field(
        ...,
        description=(
            "Whether the Learning System should run an async investigation on this case. "
            "True when LLM synthesis was used, verdict is escalate, stddev exceeds the "
            "Red Team threshold, or a dominant high score exists with too few specialists."
        ),
    )
    trigger_reason: Optional[str] = Field(
        None,
        description="Why trigger_async was set to True. None when trigger_async is False.",
    )
    rule_name: Optional[str] = Field(
        None,
        description=(
            "The rule or path that produced this verdict. Hard rules use their rule name "
            "(confirmed_ring, known_bot, extreme_velocity, trusted_account). "
            "Scoring paths use: high_aggregate_block, low_aggregate_allow, "
            "llm_synthesis, llm_timeout_escalate."
        ),
    )
