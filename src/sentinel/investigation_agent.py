"""
Sentinel Investigation Agent -- Milestone 5A (Plan-then-Execute)

Two-phase investigation:
  Phase 1 — Planning (one LLM call, no tools):
      Given the case context, generate a one-sentence fraud hypothesis
      and a 3-step investigation plan before any tools are called.

  Phase 2 — Execution (bounded ReAct, max 3 tool calls):
      Execute the plan. The hypothesis and plan are injected into the
      initial message so the ReAct loop has a clear target to confirm
      or refute.

Final output: investigation_narrative, pattern_tags, assessment,
              hypothesis, investigation_plan.
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
# Phase 1: Planning prompt
# ---------------------------------------------------------------------------

_PLAN_PROMPT = """\
You are a fraud investigation planner.
You receive a brief case summary and must produce a structured plan BEFORE
any evidence is gathered. Do not speculate beyond what the signals imply.

Output JSON only:
{
  "hypothesis": "<one sentence — what fraud type this most likely is and why>",
  "plan": [
    "<step 1: which tool to call first and what to look for>",
    "<step 2: what to investigate next based on what step 1 might reveal>",
    "<step 3: what to check last to confirm or refute the hypothesis>"
  ]
}

Available tools: get_enrichment, find_similar_cases, get_specialist_evidence(domain).
Be specific about domain names (ato, payment, ring, identity, payload, promo).\
"""


def _generate_plan(
    entity_id: str,
    arbiter_output: ArbiterOutput,
    risk_vector: RiskVector,
    model: ChatOpenAI,
) -> dict:
    """
    Phase 1: one LLM call to produce hypothesis + 3-step plan.
    Returns {"hypothesis": str, "plan": [str, str, str]}.
    Falls back to a generic plan on any failure.
    """
    brief = (
        f"Entity: {entity_id}\n"
        f"Verdict: {arbiter_output.verdict} (confidence {arbiter_output.confidence:.2f})\n"
        f"Trigger: {arbiter_output.trigger_reason}\n"
        f"Dominant domain: {risk_vector.dominant_domain} ({risk_vector.dominant_score:.4f})\n"
        f"Domains run: {', '.join(risk_vector.available_domains)}\n"
        f"Aggregate risk: {risk_vector.aggregate:.4f}"
    )
    try:
        response = model.invoke([
            {"role": "system", "content": _PLAN_PROMPT},
            {"role": "user",   "content": brief},
        ])
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        return json.loads(content)
    except Exception:
        return {
            "hypothesis": f"Possible {risk_vector.dominant_domain} fraud based on dominant domain signal.",
            "plan": [
                f"get_specialist_evidence({risk_vector.dominant_domain}) — confirm dominant signal strength",
                "get_enrichment — check entity history for prior chargebacks or step-up failures",
                "find_similar_cases — compare against past cases with matching pattern",
            ],
        }


# ---------------------------------------------------------------------------
# Phase 2: Execution system prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Sentinel, a bounded fraud investigator.
You have 4 tool calls maximum. Use them wisely.
Start with the tool most relevant to the dominant domain.
Stop early if evidence is clear.

Available tools:
  get_enrichment         — entity history: account age, chargebacks, step-up results,
                           device reuse count, linked entities count
  find_similar_cases     — semantic search of past cases; pass a free-text description
                           of this case (behavior, signals, domains, tags so far)
  get_specialist_evidence — score and primary signals for a specific domain
                           (ato, payment, identity, promo, ring, payload)
  get_case_archetype     — learned pattern statistics from all past investigations
                           matching these tags: fp_rate, dominant assessment,
                           hypothesis_confirmed_rate. Use when you have candidate
                           tags and want to know how reliable this pattern has been.

Always end with a structured JSON object (no markdown, no preamble):
{
  "investigation_narrative": "<3-6 sentences synthesizing all evidence>",
  "pattern_tags": ["<tag1>", "<tag2>", ...],
  "assessment": "likely_correct" | "possible_false_positive" | "uncertain",
  "hypothesis_outcome": "confirmed" | "refuted" | "ambiguous"
}

hypothesis_outcome rules:
  confirmed  — evidence gathered supports the pre-generated hypothesis.
  refuted    — evidence contradicts the hypothesis (e.g. clean enrichment history
               despite a high-risk signal, or a different fraud type emerged).
  ambiguous  — evidence is mixed or the hypothesis was too vague to evaluate.

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
  uncertain               Mixed or ambiguous evidence.

When find_similar_cases returns results with analyst_verdict = "false_positive",
treat that as strong evidence the current case may also be a false positive.
Adjust your assessment accordingly and call this out explicitly in your narrative.\
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
    def find_similar_cases(query_text: str, limit: int = 5) -> list[dict]:
        """
        Search memory for past investigations semantically similar to this case.
        Pass a free-text description: entity behavior, fraud signals, domain scores,
        and any pattern tags you have identified so far.
        Returns up to `limit` records, most similar first.
        Each result includes analyst_verdict when an analyst has labeled the case —
        use this to calibrate your assessment (e.g. if similar cases were labeled
        false_positive, lower your confidence in a block assessment).
        """
        _KEEP = {"investigation_narrative", "pattern_tags", "assessment", "analyst_verdict"}
        return [{k: v for k, v in r.items() if k in _KEEP}
                for r in store.query_similar(query_text, limit)]

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

    @tool
    def get_case_archetype(pattern_tags: list[str]) -> dict:
        """
        Retrieve a learned archetype for a recurring fraud pattern.

        Returns aggregate statistics from all past investigations that share
        these pattern tags: false positive rate, dominant assessment, dominant
        verdict, hypothesis confirmation rate, and a representative narrative.

        Use this when you have identified likely pattern tags and want to know
        how reliable this pattern has historically been before finalising your
        assessment. An fp_rate above 0.3 is a strong signal to consider
        possible_false_positive.
        """
        archetypes = store.get_archetypes(min_cases=2)
        if not archetypes:
            return {"message": "No archetypes available yet — insufficient historical data."}

        query_set = set(pattern_tags)
        best_match = None
        best_overlap = 0
        for arch in archetypes:
            overlap = len(query_set & set(arch["tags"]))
            if overlap > best_overlap:
                best_overlap = overlap
                best_match = arch

        if best_match is None or best_overlap == 0:
            return {"message": "No matching archetype found for these tags."}

        return best_match

    return [get_enrichment, find_similar_cases, get_specialist_evidence, get_case_archetype]


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
    plan: Optional[dict] = None,
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

    if plan:
        lines += [
            "",
            "── Investigation plan (pre-generated) ──",
            f"Hypothesis: {plan.get('hypothesis', '')}",
        ]
        for i, step in enumerate(plan.get("plan", []), 1):
            lines.append(f"  Step {i}: {step}")
        lines += [
            "",
            "Execute this plan. Confirm or refute the hypothesis. "
            "Adjust if evidence points elsewhere.",
        ]
    else:
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
    amount_usd: Optional[float] = None,
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

    model = ChatOpenAI(
        model="gpt-4o",
        temperature=0,
        api_key=os.environ["OPENAI_API_KEY"],
    )

    # Phase 1 — Planning
    plan = _generate_plan(entity_id, arbiter_output, risk_vector, model)

    # Phase 2 — Execution
    tools = _build_tools(specialist_scores, risk_vector, active_store)

    agent = create_react_agent(
        model=model,
        tools=tools,
        prompt=_SYSTEM_PROMPT,
    )

    initial_message = _build_initial_message(entity_id, arbiter_output, risk_vector, plan)
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
        amount_usd=amount_usd,
        trigger_reason=arbiter_output.trigger_reason,
        hypothesis=plan.get("hypothesis"),
        hypothesis_outcome=data.get("hypothesis_outcome"),
        investigation_plan=plan.get("plan"),
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
