"""
Rule Applier -- wires approved RuleProposals to actual code changes.

Three rule types are handled:

  weight_adjustment — rewrites a single value in DOMAIN_WEIGHTS inside
                      src/config/scoring_config.py

  hard_rule         — appends a new if-block to hard_rules_check() inside
                      src/rules/hard_rules.py, before the final return

  sentinel_filter   — writes a machine-readable entry to
                      data/sentinel_filters.json (consumed at runtime by
                      investigation_agent to skip/add trigger conditions)

apply_proposal(proposal) is idempotent: calling it twice with the same
proposal does not duplicate changes (weight_adjustment and hard_rule check
for the rule_name marker before writing; sentinel_filter deduplicates by
target string).
"""

import json
import re
from pathlib import Path

from src.schemas.rule_proposal import RuleProposal

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_SCORING_CONFIG  = Path("src/config/scoring_config.py")
_HARD_RULES      = Path("src/rules/hard_rules.py")
_SENTINEL_FILTER = Path("data/sentinel_filters.json")

# ---------------------------------------------------------------------------
# weight_adjustment
# ---------------------------------------------------------------------------

_WEIGHT_RE = re.compile(
    r'(DOMAIN_WEIGHTS\s*:\s*dict\[.*?\]\s*=\s*\{[^}]*"({key})"\s*:\s*)[0-9.]+',
    re.DOTALL,
)


def _apply_weight_adjustment(proposal: RuleProposal) -> str:
    """
    Rewrite the matching key in DOMAIN_WEIGHTS.
    Returns a human-readable status message.
    """
    pc = proposal.proposed_change
    field: str = pc.get("field", "")           # e.g. "DOMAIN_WEIGHTS.ring"
    proposed: float = pc.get("proposed_value")

    if not field.startswith("DOMAIN_WEIGHTS."):
        return f"weight_adjustment: unexpected field format '{field}' — skipped"

    key = field.split(".", 1)[1]               # e.g. "ring"
    source = _SCORING_CONFIG.read_text(encoding="utf-8")

    # Guard: already at proposed value?
    marker = f'"{key}":     {proposed}'  # exact spacing from file (rough match)
    # Use regex for a precise match regardless of whitespace
    pattern = re.compile(
        r'("' + re.escape(key) + r'"\s*:\s*)([0-9.]+)'
    )
    m = pattern.search(source)
    if not m:
        return f"weight_adjustment: key '{key}' not found in DOMAIN_WEIGHTS — skipped"

    current_str = m.group(2)
    if float(current_str) == proposed:
        return f"weight_adjustment: '{key}' already at {proposed} — no change"

    new_source = pattern.sub(lambda _m: _m.group(1) + str(proposed), source, count=1)
    _SCORING_CONFIG.write_text(new_source, encoding="utf-8")
    return (
        f"weight_adjustment: DOMAIN_WEIGHTS['{key}'] "
        f"{current_str} → {proposed} in {_SCORING_CONFIG}"
    )


# ---------------------------------------------------------------------------
# hard_rule
# ---------------------------------------------------------------------------

_FINAL_RETURN = "    return HardRuleResult(matched=False, rule_name=\"\", verdict=\"\")"


def _apply_hard_rule(proposal: RuleProposal) -> str:
    """
    Append a new if-block to hard_rules_check() before the terminal return.
    Inserts a comment marker so the block can be detected on re-runs.
    """
    pc = proposal.proposed_change
    condition: str = pc.get("condition", "")
    verdict: str   = pc.get("verdict", "block")
    rule_name: str = proposal.rule_name

    source = _HARD_RULES.read_text(encoding="utf-8")

    # Idempotency check
    marker = f"# RULE:{rule_name}"
    if marker in source:
        return f"hard_rule: '{rule_name}' already present in {_HARD_RULES} — skipped"

    if _FINAL_RETURN not in source:
        return f"hard_rule: could not locate terminal return in {_HARD_RULES} — skipped"

    block = (
        f"\n    {marker}\n"
        f"    if {condition}:\n"
        f"        return HardRuleResult(matched=True, rule_name=\"{rule_name}\", verdict=\"{verdict}\")\n"
    )
    new_source = source.replace(_FINAL_RETURN, block + _FINAL_RETURN)
    _HARD_RULES.write_text(new_source, encoding="utf-8")
    return f"hard_rule: appended '{rule_name}' to {_HARD_RULES}"


# ---------------------------------------------------------------------------
# sentinel_filter
# ---------------------------------------------------------------------------

def _apply_sentinel_filter(proposal: RuleProposal) -> str:
    """
    Append an entry to data/sentinel_filters.json.
    """
    pc = proposal.proposed_change
    action: str = pc.get("action", "")
    target: str = pc.get("target", "")

    _SENTINEL_FILTER.parent.mkdir(parents=True, exist_ok=True)
    if _SENTINEL_FILTER.exists():
        try:
            filters: list[dict] = json.loads(_SENTINEL_FILTER.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError):
            filters = []
    else:
        filters = []

    # Idempotency: deduplicate by (action, target)
    for f in filters:
        if f.get("action") == action and f.get("target") == target:
            return f"sentinel_filter: '{action}/{target}' already recorded — skipped"

    filters.append({
        "rule_name":   proposal.rule_name,
        "action":      action,
        "target":      target,
        "rationale":   pc.get("rationale", ""),
        "proposal_id": proposal.proposal_id,
    })
    _SENTINEL_FILTER.write_text(json.dumps(filters, indent=2), encoding="utf-8")
    return f"sentinel_filter: appended '{action}/{target}' to {_SENTINEL_FILTER}"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def apply_proposal(proposal: RuleProposal) -> str:
    """
    Apply an approved RuleProposal to the codebase / config files.

    Args:
        proposal: A RuleProposal (typically with status='approved').

    Returns:
        A human-readable string describing what was done (or skipped).

    Raises:
        ValueError: If the rule_type is not recognised.
    """
    rt = proposal.rule_type
    if rt == "weight_adjustment":
        return _apply_weight_adjustment(proposal)
    if rt == "hard_rule":
        return _apply_hard_rule(proposal)
    if rt == "sentinel_filter":
        return _apply_sentinel_filter(proposal)
    raise ValueError(f"Unknown rule_type '{rt}'")
