"""
Output schema for all specialist scoring functions -- v2 architecture.

Every specialist returns a SpecialistScore. No verdicts are produced here.
The Risk Aggregation layer combines specialist scores into a RiskVector,
and the Arbiter produces the final verdict.
"""

from pydantic import BaseModel, Field


class SpecialistScore(BaseModel):
    """
    Output of a deterministic specialist scoring function.

    score            -- raw fraud risk for this domain, 0.0 (clean) to 1.0 (certain fraud)
    primary_signals  -- 2-3 signal names that contributed the most to the score
    signals_evaluated -- total number of signals the scorer checked
    """

    score: float = Field(..., ge=0.0, le=1.0, description="Fraud risk score for this domain, 0.0 to 1.0")
    primary_signals: list[str] = Field(
        ...,
        min_length=1,
        max_length=3,
        description="The 2-3 signals with the highest individual contribution to the score",
    )
    signals_evaluated: int = Field(..., ge=1, description="Total number of signals checked by this scorer")
