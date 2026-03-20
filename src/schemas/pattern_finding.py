"""
PatternFinding schema -- output of the Pattern Detection Agent.

Produced by run_pattern_detection after analyzing tag co-occurrences
across recent InvestigationRecords. Used for surfacing emerging fraud
patterns, false positive clusters, and novel behaviors to analysts.
"""

from typing import Literal

from pydantic import BaseModel, Field


class PatternFinding(BaseModel):
    """A detected tag co-occurrence pattern from recent investigations."""

    pattern_tags: list[str] = Field(
        ...,
        description="The tag or pair of tags that define this pattern.",
    )
    count: int = Field(
        ...,
        description="Number of investigation records matching this pattern within the time window.",
    )
    time_window_hours: int = Field(
        ...,
        description="The lookback window in hours used to produce this finding.",
    )
    assessment_distribution: dict[str, int] = Field(
        ...,
        description="Count of each Sentinel assessment value among matching records.",
    )
    dominant_verdict: str = Field(
        ...,
        description="The most common arbiter_verdict among matching records.",
    )
    suggestion: str = Field(
        ...,
        description="Actionable recommendation from the LLM analyst (one sentence).",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Fraction of matching records that share the dominant assessment.",
    )
    finding_type: Literal["emerging_fraud", "false_positive_cluster", "novel_pattern"] = Field(
        ...,
        description=(
            "emerging_fraud: high count, block verdict, likely_correct dominant. "
            "false_positive_cluster: > 40% possible_false_positive assessments. "
            "novel_pattern: everything else."
        ),
    )
    detected_at: str = Field(
        ...,
        description="ISO 8601 timestamp of when this finding was generated.",
    )
