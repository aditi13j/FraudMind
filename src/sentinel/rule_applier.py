"""
Rule Applier

Applies approved RuleProposals by writing to the RulesStore (SQLite).
Zero diff in any .py file — approving a rule change never modifies source code.

weight_adjustment  → upsert into rules table; scoring_config reads it at next startup
hard_rule          → insert into rules table; hard_rules.py evaluates it at call time
sentinel_filter    → insert into rules table; consumed by investigation_agent (future)
"""

from src.rules.rules_store import RulesStore
from src.schemas.rule_proposal import RuleProposal

_rules_store = RulesStore()


def apply_proposal(proposal: RuleProposal, approved_by: str = "analyst") -> str:
    """
    Write an approved RuleProposal to the rules table.

    Args:
        proposal:    The approved RuleProposal.
        approved_by: Free-text identifier for the approving analyst.

    Returns:
        Human-readable string describing what was written.
    """
    rt = proposal.rule_type

    if rt == "weight_adjustment":
        field = proposal.proposed_change.get("field", "?")
        proposed = proposal.proposed_change.get("proposed_value", "?")
        _rules_store.insert_rule(
            rule_type="weight_adjustment",
            rule_name=proposal.rule_name,
            condition_json=proposal.proposed_change,
            approved_by=approved_by,
        )
        return (
            f"✅ Weight adjustment written to rules table: "
            f"{field} → {proposed}. Takes effect on next process start."
        )

    if rt == "hard_rule":
        condition = proposal.proposed_change.get("condition", "")
        verdict = proposal.proposed_change.get("verdict", "block")
        _rules_store.insert_rule(
            rule_type="hard_rule",
            rule_name=proposal.rule_name,
            condition_json=proposal.proposed_change,
            approved_by=approved_by,
        )
        return (
            f"✅ Hard rule '{proposal.rule_name}' active immediately: "
            f"if [{condition}] → {verdict}"
        )

    if rt == "sentinel_filter":
        action = proposal.proposed_change.get("action", "")
        target = proposal.proposed_change.get("target", "")
        _rules_store.insert_rule(
            rule_type="sentinel_filter",
            rule_name=proposal.rule_name,
            condition_json=proposal.proposed_change,
            approved_by=approved_by,
        )
        return f"✅ Sentinel filter recorded: {action} on '{target}'"

    raise ValueError(f"Unknown rule_type '{rt}'")
