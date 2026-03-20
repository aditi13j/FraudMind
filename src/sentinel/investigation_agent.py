"""
Sentinel Investigation Agent -- Milestone 5A

Bounded ReAct investigator using LangGraph's create_react_agent.
Runs asynchronously after the Execution System on cases where
arbiter_output.trigger_async is True.

Tool-calling loop:
    - Max 3 tool calls per investigation
    - Agent decides which tools to call based on case context
    - Stops early when evidence is clear
    - Final output: investigation_narrative, pattern_tags, assessment
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.investigation_record import InvestigationRecord
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore
from src.sentinel.memory_store import MemoryStore
from src.sentinel.mock_enrichment import enrich_entity

load_dotenv()

_memory_store = MemoryStore()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Sentinel, a bounded fraud investigator.
You have 3 tool calls maximum. Use them wisely.
Start with the tool most relevant to the dominant domain.
Stop early if evidence is clear.

Available tools:
  get_enrichment         — entity history: account age, chargebacks, step-up results,
                           device reuse count, linked entities count
  find_similar_cases     — search memory for past cases with similar pattern tags
  get_specialist_evidence — score and primary signals for a specific domain
                           (ato, payment, identity, promo, ring, payload)

Always end with a structured JSON object (no markdown, no preamble):
{
  "investigation_narrative": "<3-6 sentences synthesizing all evidence>",
  "pattern_tags": ["<tag1>", "<tag2>", ...],
  "assessment": "likely_correct" | "possible_false_positive" | "uncertain"
}

Pattern tag vocabulary (pick 2-6 that apply):
  Domain   : ring_fraud, payment_fraud, ato, identity_fraud, bot_session, promo_abuse
  Account  : new_account, dormant_account, high_value_account, synthetic_identity
  Behavior : cross_border, geo_mismatch, credential_stuffing, scripted_session,
             account_factory, self_referral, velocity_abuse
  Verdict  : high_confidence_block, borderline_case, insufficient_evidence,
             single_domain_signal, multi_domain_convergence

Assessment values:
  likely_correct          Evidence supports the verdict.
  possible_false_positive Enrichment contradicts the verdict (clean history, yet blocked).
  uncertain               Mixed or ambiguous evidence.\
"""


# ---------------------------------------------------------------------------
# Tool factory
# ---------------------------------------------------------------------------

def _build_tools(
    specialist_scores: dict[str, Optional[SpecialistScore]],
    risk_vector: RiskVector,
    store: MemoryStore,
) -> list:
    @tool
    def get_enrichment(entity_id: str) -> dict:
        """
        Fetch enrichment signals for an entity: account_age_days, prior_chargebacks,
        prior_step_up_results, device_reuse_count, linked_entities_count.
        """
        return enrich_entity(entity_id)

    @tool
    def find_similar_cases(pattern_tags: list[str], limit: int = 5) -> list[dict]:
        """
        Search memory for past investigation records sharing pattern tags with this case.
        Returns up to `limit` similar records, most similar first.
        """
        return store.query_similar(pattern_tags, limit)

    @tool
    def get_specialist_evidence(domain: str) -> dict:
        """
        Return the fraud score and primary signals for a specialist domain in the current case.
        Valid domains: ato, payment, identity, promo, ring, payload.
        """
        if domain not in risk_vector.scores:
            return {"error": f"domain '{domain}' did not run or has no score"}
        spec = specialist_scores.get(domain)
        return {
            "domain": domain,
            "score": risk_vector.scores[domain],
            "primary_signals": spec.primary_signals if spec else [],
            "signals_evaluated": spec.signals_evaluated if spec else 0,
        }

    return [get_enrichment, find_similar_cases, get_specialist_evidence]


# ---------------------------------------------------------------------------
# Message parsing
# ---------------------------------------------------------------------------

def _extract_tool_trace(messages: list) -> list[dict]:
    """Walk message history and build an ordered log of tool calls with results."""
    pending: dict[str, tuple[str, dict]] = {}
    trace: list[dict] = []

    for msg in messages:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                pending[tc["id"]] = (tc["name"], tc["args"])
        elif isinstance(msg, ToolMessage):
            tool_name, arguments = pending.pop(msg.tool_call_id, ("unknown", {}))
            try:
                result = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
            except (json.JSONDecodeError, TypeError):
                result = msg.content
            summary = (
                ", ".join(f"{k}={v}" for k, v in list(result.items())[:3]) if isinstance(result, dict)
                else f"{len(result)} record(s) returned" if isinstance(result, list)
                else str(result)[:120]
            )
            trace.append({
                "tool_name": tool_name,
                "arguments": arguments,
                "result_summary": summary,
                "call_order": len(trace) + 1,
                "_result": result,
            })

    return trace


def _parse_final_output(messages: list) -> dict:
    """Extract and parse the final JSON from the last AI message."""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            try:
                return json.loads(msg.content.strip())
            except json.JSONDecodeError:
                continue
    raise ValueError("Sentinel did not produce a parseable JSON output")


# ---------------------------------------------------------------------------
# Initial user message
# ---------------------------------------------------------------------------

def _build_initial_message(
    entity_id: str,
    arbiter_output: ArbiterOutput,
    risk_vector: RiskVector,
) -> str:
    lines = [
        f"Entity: {entity_id}",
        f"Trigger reason: {arbiter_output.trigger_reason}",
        "",
        "Arbiter verdict:",
        f"  verdict    : {arbiter_output.verdict}",
        f"  confidence : {arbiter_output.confidence:.4f}",
        f"  reasoning  : {arbiter_output.reasoning}",
        "",
        "Risk Vector:",
        f"  aggregate       : {risk_vector.aggregate:.4f}",
        f"  score_stddev    : {risk_vector.score_stddev:.4f}",
        f"  specialists_run : {risk_vector.specialists_run}",
        f"  dominant_domain : {risk_vector.dominant_domain} ({risk_vector.dominant_score:.4f})",
        "",
        "Domain scores:",
    ]
    for domain in risk_vector.available_domains:
        lines.append(f"  {domain:<10} {risk_vector.scores[domain]:.4f}")
    lines += ["", "Begin your investigation."]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_investigation(
    entity_id: str,
    arbiter_output: ArbiterOutput,
    risk_vector: RiskVector,
    specialist_scores: dict[str, Optional[SpecialistScore]],
    store: Optional[MemoryStore] = None,
) -> InvestigationRecord:
    """
    Run a bounded Sentinel investigation and persist the record.

    Args:
        entity_id:         The primary entity under investigation.
        arbiter_output:    The verdict and metadata from the Arbiter.
        risk_vector:       Aggregated specialist scores from risk aggregation.
        specialist_scores: Per-domain SpecialistScore objects (may be None).
        store:             MemoryStore instance (uses module default if None).

    Returns:
        A fully populated InvestigationRecord, already persisted to the store.
    """
    active_store = store or _memory_store

    tools = _build_tools(specialist_scores, risk_vector, active_store)

    model = ChatOpenAI(
        model="gpt-4o",
        temperature=0,
        api_key=os.environ["OPENAI_API_KEY"],
    )

    agent = create_react_agent(
        model=model,
        tools=tools,
        prompt=_SYSTEM_PROMPT,
    )

    initial_message = _build_initial_message(entity_id, arbiter_output, risk_vector)
    result = agent.invoke(
        {"messages": [{"role": "user", "content": initial_message}]},
        config={"recursion_limit": 10},  # headroom for 3 tool calls
    )

    messages = result["messages"]
    raw_trace = _extract_tool_trace(messages)
    data = _parse_final_output(messages)

    enriched_signals = next(
        (e["_result"] for e in raw_trace if e["tool_name"] == "get_enrichment" and isinstance(e["_result"], dict)),
        {},
    )
    memory_matches = next(
        (e["_result"] for e in raw_trace if e["tool_name"] == "find_similar_cases" and isinstance(e["_result"], list)),
        [],
    )
    tool_trace = [{k: v for k, v in e.items() if k != "_result"} for e in raw_trace]

    record = InvestigationRecord(
        case_id=str(uuid.uuid4()),
        entity_id=entity_id,
        arbiter_verdict=arbiter_output.verdict,
        arbiter_confidence=arbiter_output.confidence,
        trigger_reason=arbiter_output.trigger_reason,
        risk_vector=risk_vector,
        enriched_signals=enriched_signals,
        memory_matches=memory_matches,
        investigation_narrative=data["investigation_narrative"],
        pattern_tags=data["pattern_tags"],
        assessment=data["assessment"],
        created_at=datetime.now(timezone.utc).isoformat(),
        tool_trace=tool_trace,
    )

    active_store.save(record)
    return record
