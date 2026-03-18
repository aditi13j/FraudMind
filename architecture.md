FraudMind v2 architecture. Key changes:
- Specialists are deterministic Python scoring functions, not LLM agents
- Specialists output score (float) + primary_signals (list), not verdicts
- Risk Aggregation layer produces RiskVector
- Arbiter is the only verdict producer
- LLM lives in Arbiter (conditional) and Learning System only
- Two paths: Execution System (sync) and Learning System (async)