Build Milestone 4 — Sentinel Investigation Agent.

Sentinel is the async learning system. It runs after 
the Execution System on cases where trigger_async is True.

## Files to create

src/sentinel/investigation_agent.py  — main agent
src/sentinel/memory_store.py         — simple JSON file store
src/sentinel/mock_enrichment.py      — mock tool calls
src/schemas/investigation_record.py  — output schema

## InvestigationRecord schema (src/schemas/investigation_record.py)

Fields:
- case_id: str (uuid)
- entity_id: str
- timestamp: str (ISO format)
- arbiter_verdict: str
- arbiter_confidence: float
- arbiter_reasoning: str
- risk_vector_aggregate: float
- risk_vector_dominant_domain: str
- memory_matches: list[str] (case_ids of similar past cases)
- enriched_signals: dict (output of mock enrichment)
- investigation_narrative: str (LLM synthesis)
- pattern_tags: list[str] (structured labels for clustering)
- verdict_assessment: Literal["correct", "possible_false_positive", "uncertain"]
- confidence_in_assessment: float
- trigger_reason: str

## Memory store (src/sentinel/memory_store.py)

Simple JSON file store at data/investigation_records.json
Two methods only:
- save(record: InvestigationRecord) → appends to JSON file
- query_similar(pattern_tags: list[str],