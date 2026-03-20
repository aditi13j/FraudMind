Build Milestone 5A — Sentinel v2: bounded ReAct investigator.

Refactor src/sentinel/investigation_agent.py to use 
LangGraph's create_react_agent with bounded tool-calling.

## Three tools only

1. get_enrichment(entity_id: str) -> dict
   Extract from existing enrich_entity() in mock_enrichment.py
   Returns: account_age_days, prior_chargebacks, 
            prior_step_up_results, device_reuse_count,
            linked_entities_count

2. find_similar_cases(pattern_tags: list[str], limit: int = 5) -> list[dict]
   Extract from existing memory_store.query_similar()
   Returns: list of similar past investigation records

3. get_specialist_evidence(domain: str) -> dict
   New tool — returns the specialist score and primary signals
   for a given domain from the current case context
   Domains: ato, payment, identity, promo, ring, payload

## Tool-calling loop constraints
- Max 3 tool calls per investigation
- temperature=0
- Use create_react_agent from langgraph.prebuilt
- Stop when LLM decides it has enough evidence

## Tool trace logging
Log to investigation record:
    tool_trace: list[dict] with fields:
        tool_name: str
        arguments: dict
        result_summary: str  (one line summary of what was returned)
        call_order: int

## Final output schema — unchanged
InvestigationRecord stays exactly the same.
Add tool_trace: list[dict] as a new optional field.

## System prompt for Sentinel v2
You are Sentinel, a bounded fraud investigator.
You have 3 tool calls maximum. Use them wisely.
Start with the tool most relevant to the dominant domain.
Stop early if evidence is clear.
Always end with a structured JSON output:
  investigation_narrative, pattern_tags, assessment

## Do not change
- memory_store.py
- investigation_record.py (except add tool_trace field)
- mock_enrichment.py
- Any Execution System files

## Update notebooks/milestone4_sentinel_demo.ipynb
Rename to milestone5a_sentinel_v2_demo.ipynb
Show tool trace for Case 1 — ring attack
Show which tools were called and in what order