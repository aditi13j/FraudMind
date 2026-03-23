"""
RedTeamReport schema — output of the Red Team Agent.

Produced by red_team_rule() after stress-testing an approved RuleProposal
with adversarial signal combinations.
"""

from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


class BypassScenario(BaseModel):
    """One adversarial attempt against the rule."""

    description: str = Field(..., description="Plain English description of the evasion strategy.")
    signal_overrides: dict = Field(
        ..., description="Signal field values crafted to evade the rule."
    )
    rule_fired: bool = Field(
        ..., description="Whether the targeted rule matched this scenario."
    )
    system_verdict: str = Field(
        ..., description="Full pipeline verdict: block, allow, step_up, escalate."
    )
    caught_by: Optional[str] = Field(
        None, description="Rule or mechanism that caught this scenario (if rule_fired=False)."
    )


class RedTeamReport(BaseModel):
    """Full red-team report for one RuleProposal."""

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str = Field(..., description="The RuleProposal that was tested.")
    rule_name: str = Field(..., description="The rule under test.")
    rule_type: str = Field(..., description="hard_rule | weight_adjustment | sentinel_filter.")
    condition_tested: str = Field(
        ..., description="The condition or change that was stress-tested."
    )
    attempts_total: int = Field(..., description="Number of adversarial scenarios generated.")
    attempts_bypassed_rule: int = Field(
        ..., description="Scenarios where the specific rule did NOT fire."
    )
    attempts_bypassed_system: int = Field(
        ..., description="Scenarios where the full system gave allow or step_up."
    )
    bypass_rate: float = Field(
        ..., ge=0.0, le=1.0,
        description="attempts_bypassed_rule / attempts_total.",
    )
    scenarios: list[BypassScenario] = Field(
        default_factory=list, description="Detailed results for each adversarial attempt."
    )
    recommendation: Literal["approve", "revise", "reject"] = Field(
        ..., description="Red team recommendation based on bypass rate."
    )
    recommendation_reasoning: str = Field(
        ..., description="One sentence explaining the recommendation."
    )
    created_at: str = Field(..., description="ISO 8601 timestamp.")
