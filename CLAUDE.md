Build Milestone 6 — Rule Proposer.

New files:
  src/sentinel/rule_proposer.py
  src/schemas/rule_proposal.py
  data/rule_proposals.json  (created automatically)

RuleProposal schema (src/schemas/rule_proposal.py):
  proposal_id: str (uuid)
  pattern_tags: list[str]
  pattern_count: int
  pattern_finding_type: str
  rule_type: Literal["hard_rule", "weight_adjustment", "sentinel_filter"]
  rule_name: str
  description: str  (plain English, one sentence)
  proposed_change: dict
  expected_impact: str  (one sentence)
  risk: str  (one sentence)
  status: Literal["pending", "approved", "rejected"] = "pending"
  created_at: str

Rule Proposer function (src/sentinel/rule_proposer.py):
  propose_rule(finding: PatternFinding) -> RuleProposal

One LLM call (GPT-4o, temperature=0).

System prompt:
  You are a fraud rule engineer.
  You receive a pattern finding from recent fraud investigations.
  Propose one specific rule change to address this pattern.
  
  Rule types:
  hard_rule — add a new instant block/allow condition to hard_rules.py
  weight_adjustment — change a weight in scoring_config.py  
  sentinel_filter — change when Sentinel investigation triggers
  
  Choose hard_rule for false_positive_cluster findings
  Choose weight_adjustment for emerging_fraud with high count
  Choose sentinel_filter for high volume low-value patterns
  
  Output JSON only:
  {
    "rule_type": "...",
    "rule_name": "short_snake_case_name",
    "description": "plain English one sentence",
    "proposed_change": {...specific change dict...},
    "expected_impact": "one sentence",
    "risk": "one sentence"
  }

Also create a ProposalStore class (in rule_proposer.py):
  save(proposal: RuleProposal) -> None
  load_pending() -> list[RuleProposal]
  update_status(proposal_id: str, status: str) -> None
  (same JSON file pattern as MemoryStore)

Create notebooks/milestone6_rule_proposer_demo.ipynb:
  Run pattern detection on stored records
  For each PatternFinding run propose_rule()
  Print all proposals in readable format
  Show: rule_type, rule_name, description, proposed_change