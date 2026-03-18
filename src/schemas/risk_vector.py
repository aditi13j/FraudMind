"""
RiskVector schema -- output of the Risk Aggregation node.

Produced after all specialist scores are collected and synthesized.
Consumed by the Arbiter Agent (Milestone 3).
"""

from pydantic import BaseModel, Field


class RiskVector(BaseModel):
    """Aggregated risk representation computed from all available specialist scores."""

    scores: dict[str, float] = Field(
        ...,
        description="Raw score from each specialist domain that ran. Keys are domain names.",
    )
    available_domains: list[str] = Field(
        ...,
        description="Domain names that ran and contributed a score, in descending score order.",
    )
    aggregate: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Weighted average of specialist scores, re-normalized to the domains that ran. "
            "This is the primary input to the Arbiter verdict decision."
        ),
    )
    score_stddev: float = Field(
        ...,
        ge=0.0,
        description=(
            "Standard deviation of specialist scores across available domains. "
            "High values indicate specialist disagreement and may trigger Red Team review."
        ),
    )
    dominant_domain: str = Field(
        ...,
        description="The specialist domain with the highest individual score.",
    )
    dominant_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="The score of the dominant domain.",
    )
    specialists_run: int = Field(
        ...,
        ge=0,
        description="Number of specialist domains that ran and produced a score.",
    )
