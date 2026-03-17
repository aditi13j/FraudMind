"""
Pydantic schema for the Final Verdict.

FinalVerdict is the output of the Arbiter Agent (Version 4). It is defined here
as a stub so FraudState can hold a typed field for it from Version 2 onward,
keeping the state schema forward-compatible.

Do not populate this field until the Arbiter Agent is implemented.
"""

from typing import Literal

from pydantic import BaseModel, Field


class FinalVerdict(BaseModel):
    """
    Synthesized verdict produced by the Arbiter Agent after reviewing all
    specialist verdicts and the Red Team challenge.

    Not populated until Version 4.
    """

    verdict: Literal["block", "allow", "step_up", "escalate"] = Field(
        ..., description="The Arbiter's final disposition across all specialist inputs"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    reasoning: str = Field(..., description="Full narrative explanation synthesizing all specialist verdicts")
    recommended_action: str = Field(..., description="The definitive action the platform should take")
    contributing_verdicts: list[str] = Field(
        default_factory=list,
        description="List of specialist agent names whose verdicts contributed to this final decision",
    )
