"""
Rule Proposer -- Milestone 6

Reads a PatternFinding and produces a RuleProposal via one GPT-4o call.
The LLM acts as a fraud rule engineer: it chooses the rule type, names the
rule, writes the description, proposes the specific change, and assesses
expected impact and risk.

ProposalStore handles persistence at data/rule_proposals.json using the
same append-then-rewrite pattern as MemoryStore.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.pattern_finding import PatternFinding
from src.schemas.rule_proposal import RuleProposal

load_dotenv()

_PROPOSALS_PATH = Path("data/rule_proposals.json")

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a fraud rule engineer.
You receive a pattern finding from recent fraud investigations.
Propose one specific rule change to address this pattern.

Rule types:
  weight_adjustment — change a weight in scoring_config.py
  hard_rule         — add a new instant block/allow condition to hard_rules.py
  sentinel_filter   — change when Sentinel investigation triggers

Choose weight_adjustment for emerging_fraud findings with high count.
Choose hard_rule for false_positive_cluster findings.
Choose sentinel_filter for high volume low-value patterns.

proposed_change must follow the exact format for the chosen rule type:

weight_adjustment:
{
    "file": "scoring_config.py",
    "field": "<DICT_NAME>.<key>",
    "current_value": <float>,
    "proposed_value": <float between 0.0 and 1.0>,
    "rationale": "<one sentence>"
}

hard_rule:
{
    "condition": "<Python-readable condition string>",
    "verdict": "block" | "allow" | "step_up" | "escalate",
    "rationale": "<one sentence>"
}

sentinel_filter:
{
    "action": "remove_trigger" | "add_filter",
    "target": "<trigger_reason or filter description>",
    "rationale": "<one sentence>"
}

Output JSON only:
{
  "rule_type": "weight_adjustment" | "hard_rule" | "sentinel_filter",
  "rule_name": "short_snake_case_name",
  "description": "plain English one sentence",
  "proposed_change": {...exact format per rule type above...},
  "expected_impact": "one sentence",
  "risk": "one sentence"
}\
"""


# ---------------------------------------------------------------------------
# Public interface: propose_rule
# ---------------------------------------------------------------------------

def propose_rule(finding: PatternFinding) -> RuleProposal:
    """
    Produce a RuleProposal from a PatternFinding using one GPT-4o call.

    Args:
        finding: A PatternFinding from run_pattern_detection.

    Returns:
        A RuleProposal with status="pending".
    """
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    user_content = json.dumps({
        "pattern_tags": finding.pattern_tags,
        "count": finding.count,
        "time_window_hours": finding.time_window_hours,
        "assessment_distribution": finding.assessment_distribution,
        "dominant_verdict": finding.dominant_verdict,
        "confidence": finding.confidence,
        "finding_type": finding.finding_type,
        "suggestion": finding.suggestion,
    }, indent=2)

    response = client.chat.completions.create(
        model="gpt-4o",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    )

    data = json.loads(response.choices[0].message.content.strip())

    return RuleProposal(
        pattern_tags=finding.pattern_tags,
        pattern_count=finding.count,
        pattern_finding_type=finding.finding_type,
        rule_type=data["rule_type"],
        rule_name=data["rule_name"],
        description=data["description"],
        proposed_change=data["proposed_change"],
        expected_impact=data["expected_impact"],
        risk=data["risk"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# ProposalStore
# ---------------------------------------------------------------------------

class ProposalStore:
    """Append-only JSON store for RuleProposals at data/rule_proposals.json."""

    def __init__(self, path: Path = _PROPOSALS_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("[]")

    def _load_all(self) -> list[dict]:
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def save(self, proposal: RuleProposal) -> None:
        """Append a proposal to the store."""
        records = self._load_all()
        records.append(proposal.model_dump())
        self._path.write_text(json.dumps(records, indent=2))

    def load_pending(self) -> list[RuleProposal]:
        """Return all proposals with status='pending'."""
        return [
            RuleProposal(**r)
            for r in self._load_all()
            if r.get("status") == "pending"
        ]

    def update_status(self, proposal_id: str, status: str) -> None:
        """Update the status of a proposal by ID."""
        records = self._load_all()
        for record in records:
            if record.get("proposal_id") == proposal_id:
                record["status"] = status
                break
        self._path.write_text(json.dumps(records, indent=2))
