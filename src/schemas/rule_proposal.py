"""
RuleProposal schema -- output of the Rule Proposer.

Produced by propose_rule() after analyzing a PatternFinding.
Stored in data/rule_proposals.json for analyst review and approval.
"""

from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class RuleProposal(BaseModel):
    """A proposed rule change derived from a detected fraud pattern."""

    proposal_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this proposal.",
    )
    pattern_tags: list[str] = Field(
        ...,
        description="The pattern tags from the PatternFinding that triggered this proposal.",
    )
    pattern_count: int = Field(
        ...,
        description="Number of investigation records that matched the pattern.",
    )
    pattern_finding_type: str = Field(
        ...,
        description="The finding_type from the source PatternFinding.",
    )
    rule_type: Literal["hard_rule", "weight_adjustment", "sentinel_filter"] = Field(
        ...,
        description=(
            "hard_rule: new instant block/allow condition in hard_rules.py. "
            "weight_adjustment: change a domain weight in scoring_config.py. "
            "sentinel_filter: change when Sentinel investigation triggers."
        ),
    )
    rule_name: str = Field(
        ...,
        description="Short snake_case identifier for the proposed rule.",
    )
    description: str = Field(
        ...,
        description="Plain English one-sentence description of the proposed change.",
    )
    proposed_change: dict = Field(
        ...,
        description="Structured representation of the exact change to make.",
    )
    expected_impact: str = Field(
        ...,
        description="One sentence describing the expected effect if approved.",
    )
    risk: str = Field(
        ...,
        description="One sentence describing the main risk of applying this change.",
    )
    status: Literal["pending", "approved", "rejected"] = Field(
        default="pending",
        description="Analyst review status.",
    )
    created_at: str = Field(
        ...,
        description="ISO 8601 timestamp of when this proposal was created.",
    )
