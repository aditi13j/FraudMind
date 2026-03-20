"""
Sentinel Investigation Agent -- Milestone 4

Runs asynchronously after the Execution System on cases where
arbiter_output.trigger_async is True.

Workflow:
    1. Extract context from FraudState (arbiter verdict, risk vector, entity ids)
    2. Run mock enrichment tools (IP reputation, device history, entity history)
    3. Query memory store for similar past cases by pattern_tags
    4. Call GPT-4o to synthesize investigation narrative, pattern_tags,
       and verdict_assessment
    5. Save the InvestigationRecord to the memory store
    6. Return the record for downstream use

Sentinel is the learning system. Its output feeds future model calibration
and pattern analysis. It never blocks or allows -- it only investigates.
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.investigation_record import InvestigationRecord
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore
from src.sentinel.memory_store import MemoryStore
from src.sentinel.mock_enrichment import run_all_enrichment

load_dotenv()

_memory_store = MemoryStore()

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are Sentinel, the async investigation agent for FraudMind. You run after
the Execution System has issued a verdict. Your job is not to re-decide the
verdict but to investigate it: understand what happened, tag the case for
clustering, and assess whether the verdict was correct.

You receive:
  - The Arbiter's verdict, confidence, and reasoning
  - The RiskVector (aggregate, stddev, per-domain scores and signals)
  - Enrichment data from three tools: IP reputation, device history, entity history
  - A list of similar past case IDs from memory (may be empty)
  - The trigger reason that caused this investigation

## Output

Respond with a JSON object matching this schema exactly:
{
  "investigation_narrative": "<3-6 sentences synthesizing all evidence into a coherent account of what likely happened>",
  "pattern_tags": ["<tag1>", "<tag2>", ...],
  "verdict_assessment": "correct" | "possible_false_positive" | "uncertain",
  "confidence_in_assessment": <float 0.0 to 1.0>
}

## Pattern tags

Choose from this vocabulary (use only tags that apply; pick 2 to 6):
  Domain tags    : ring_fraud, payment_fraud, ato, identity_fraud, bot_session, promo_abuse
  Account tags   : new_account, dormant_account, high_value_account, synthetic_identity
  Behavior tags  : cross_border, geo_mismatch, credential_stuffing, scripted_session,
                   account_factory, self_referral, velocity_abuse
  Verdict tags   : high_confidence_block, borderline_case, insufficient_evidence,
                   single_domain_signal, multi_domain_convergence

## Verdict assessment

correct                 The evidence strongly supports the Arbiter's verdict. The
                        enrichment and risk signals are coherent and point the same direction.

possible_false_positive The enrichment suggests a legitimate user. For example: clean IP
                        reputation, trusted device with long history, no prior fraud, yet
                        the Arbiter blocked or stepped up. Use this when the enrichment
                        materially contradicts the risk signals.

uncertain               The evidence is mixed or ambiguous. Use when you cannot confidently
                        support or contradict the verdict.

## Confidence in assessment

Reserve > 0.80 for cases where the evidence is unambiguous.
Use 0.50 to 0.70 for cases where enrichment provides some clarity but gaps remain.
Use < 0.50 for cases where enrichment is neutral and the assessment is speculative.

Respond with JSON only. No preamble, no markdown, no explanation outside the JSON.\
"""


def _build_user_message(
    entity_id: str,
    arbiter_output: ArbiterOutput,
    risk_vector: RiskVector,
    specialist_scores: dict[str, Optional[SpecialistScore]],
    enriched_signals: dict,
    memory_matches: list[str],
) -> str:
    lines: list[str] = [
        f"Entity: {entity_id}",
        f"Trigger reason: {arbiter_output.trigger_reason}",
        "",
        "Arbiter verdict:",
        f"  verdict    : {arbiter_output.verdict}",
        f"  confidence : {arbiter_output.confidence:.4f}",
        f"  reasoning  : {arbiter_output.reasoning}",
        f"  evidence   : {', '.join(arbiter_output.evidence)}",
        "",
        "Risk Vector:",
        f"  aggregate       : {risk_vector.aggregate:.4f}",
        f"  score_stddev    : {risk_vector.score_stddev:.4f}",
        f"  specialists_run : {risk_vector.specialists_run}",
        f"  dominant_domain : {risk_vector.dominant_domain} ({risk_vector.dominant_score:.4f})",
        "",
        "Domain scores and primary signals:",
    ]

    for domain in risk_vector.available_domains:
        score = risk_vector.scores[domain]
        spec = specialist_scores.get(domain)
        signals = ", ".join(spec.primary_signals) if spec else "unavailable"
        lines.append(f"  {domain:<10} {score:.4f}  →  {signals}")

    lines += ["", "Enrichment data:"]
    lines.append(json.dumps(enriched_signals, indent=2))

    if memory_matches:
        lines += ["", f"Similar past cases in memory: {', '.join(memory_matches)}"]
    else:
        lines += ["", "No similar past cases found in memory."]

    lines += ["", "Produce your investigation output."]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_investigation(
    entity_id: str,
    arbiter_output: ArbiterOutput,
    risk_vector: RiskVector,
    specialist_scores: dict[str, Optional[SpecialistScore]],
    ip_hash: Optional[str] = None,
    device_id: Optional[str] = None,
    store: Optional[MemoryStore] = None,
) -> InvestigationRecord:
    """
    Run a full Sentinel investigation and persist the record.

    Args:
        entity_id:         The primary entity under investigation.
        arbiter_output:    The verdict and metadata from the Arbiter.
        risk_vector:       Aggregated specialist scores from risk aggregation.
        specialist_scores: Per-domain SpecialistScore objects (may be None).
        ip_hash:           Hashed IP address for IP enrichment (optional).
        device_id:         Device fingerprint for device enrichment (optional).
        store:             MemoryStore instance (uses module default if None).

    Returns:
        A fully populated InvestigationRecord, already persisted to the store.
    """
    active_store = store or _memory_store

    # Step 1: Mock enrichment
    enriched_signals = run_all_enrichment(
        entity_id=entity_id,
        ip_hash=ip_hash,
        device_id=device_id,
    )

    # Step 2: Derive initial pattern_tags for memory query from RiskVector context.
    # The LLM will refine these; we use a lightweight heuristic to seed memory lookup.
    seed_tags: list[str] = []
    if risk_vector.dominant_score > 0.60:
        domain_tag_map = {
            "ring": "ring_fraud", "payment": "payment_fraud", "ato": "ato",
            "identity": "identity_fraud", "payload": "bot_session", "promo": "promo_abuse",
        }
        seed_tags.append(domain_tag_map.get(risk_vector.dominant_domain, risk_vector.dominant_domain))
    if arbiter_output.verdict in ("block", "escalate"):
        seed_tags.append("high_confidence_block" if arbiter_output.confidence > 0.80 else "borderline_case")

    # Step 3: Query memory
    memory_matches = active_store.query_similar(seed_tags, limit=5)

    # Step 4: LLM synthesis
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    user_message = _build_user_message(
        entity_id=entity_id,
        arbiter_output=arbiter_output,
        risk_vector=risk_vector,
        specialist_scores=specialist_scores,
        enriched_signals=enriched_signals,
        memory_matches=memory_matches,
    )

    response = client.chat.completions.create(
        model="gpt-4o",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
    )

    raw = response.choices[0].message.content.strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Sentinel returned invalid JSON:\n{raw}") from exc

    # Step 5: Build and persist the record
    record = InvestigationRecord(
        case_id=str(uuid.uuid4()),
        entity_id=entity_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        arbiter_verdict=arbiter_output.verdict,
        arbiter_confidence=arbiter_output.confidence,
        arbiter_reasoning=arbiter_output.reasoning,
        risk_vector_aggregate=risk_vector.aggregate,
        risk_vector_dominant_domain=risk_vector.dominant_domain,
        memory_matches=memory_matches,
        enriched_signals=enriched_signals,
        investigation_narrative=data["investigation_narrative"],
        pattern_tags=data["pattern_tags"],
        verdict_assessment=data["verdict_assessment"],
        confidence_in_assessment=data["confidence_in_assessment"],
        trigger_reason=arbiter_output.trigger_reason or "unspecified",
    )

    active_store.save(record)
    return record
