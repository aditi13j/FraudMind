Implement P0 feedback before building Rule Proposer:

1. Add a hard_rules_check() function in src/rules/hard_rules.py
   Pure Python. No LLM. Runs before specialists.
   Returns: HardRuleResult(matched: bool, rule_name: str, verdict: str)
   
   Initial rules:
   - known_bot: tls_fingerprint_known_bot AND user_agent_is_headless → block
   - confirmed_ring: known_ring_signature_match AND 
     linked_accounts_with_fraud_confirmed >= 2 → block
   - extreme_velocity: transactions_last_1h >= 20 → block
   - trusted_account: account_age_days > 730 AND not is_new_device 
     AND not geo_mismatch AND amount_vs_avg_ratio < 1.5 → allow

2. Add rule_name: Optional[str] to ArbiterOutput schema

3. In arbiter.py populate rule_name:
   - Deterministic block: rule_name = "high_aggregate_block"
   - Deterministic allow: rule_name = "low_aggregate_allow"  
   - LLM synthesis: rule_name = "llm_synthesis"
   - Timeout fallback: rule_name = "llm_timeout_escalate"

4. Add hard_rules_node to fraud_graph.py
   Runs BEFORE specialists
   If matched: write verdict to state, skip specialists
   If not matched: continue to specialists as normal

Do not change specialist scoring logic.
Do not change RiskVector schema.