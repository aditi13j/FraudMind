"""
Arbiter -- Milestone 3

The only verdict producer in FraudMind v2. Reads the RiskVector produced
by risk aggregation and issues a final verdict via four-tier logic:

    DETERMINISTIC (no LLM):
        aggregate > 0.70 AND specialists_run >= 3  →  block
        aggregate < 0.15                           →  allow
        score_stddev > 0.25                        →  escalate  (specialists disagree)
        specialists_run < 3                        →  escalate  (thin evidence)

    LLM synthesis (genuinely ambiguous cases only):
        0.15 ≤ aggregate ≤ 0.70, stddev ≤ 0.25, specialists_run ≥ 3
        GPT-4o, temperature=0, 500ms timeout, fallback to escalate on timeout

Only the Arbiter makes LLM calls. Specialist scorers remain pure Python.
"""

import json
import os
from typing import Optional

from dotenv import load_dotenv
from openai import APITimeoutError, OpenAI

from src.config.scoring_config import (
    ALLOW_THRESHOLD,
    BLOCK_THRESHOLD,
    RED_TEAM_VARIANCE_THRESHOLD,
    TRIGGER_REASONS,
)
from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore

load_dotenv()

# ---------------------------------------------------------------------------
# Deterministic thresholds
# ---------------------------------------------------------------------------

_MIN_SPECIALISTS_FOR_BLOCK = 3   # need at least 3 domains to hard-block


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are the Arbiter, the final decision-making component of FraudMind, a \
multi-domain fraud intelligence system.

You receive a RiskVector produced by up to six specialist scoring domains:
  ring     (weight 0.30)  fraud ring membership and transaction graph signals
  payment  (weight 0.25)  transaction anomalies, velocity, amount ratio
  ato      (weight 0.20)  account takeover: new device, geo mismatch, session signals
  identity (weight 0.15)  synthetic identity: PII reuse, document failure
  payload  (weight 0.07)  bot and automation: TLS fingerprint, headless browser
  promo    (weight 0.03)  incentive abuse: self-referral, cancel after promo

The aggregate score is a domain-weight-normalized mean across whichever \
specialists ran. score_stddev measures specialist disagreement. High \
disagreement means the case is ambiguous.

## Verdicts

block     High confidence this is fraud. Multiple domains converge at high \
scores, or a single domain is extremely high with clear corroboration.

allow     High confidence this is legitimate. Aggregate is low and no domain \
has a meaningful signal.

step_up   Moderate risk. Serve additional friction (MFA, CAPTCHA, ID check) \
before allowing. Use when risk is elevated but not conclusive.

escalate  Insufficient or conflicting evidence. Route to human review. Use \
when specialists_run < 3, score_stddev is high, or the pattern is ambiguous.

## Reasoning rules

1. Aggregate above 0.70 with specialists_run >= 3 is strong block evidence.
2. High score_stddev (> 0.25) means specialists disagree. Prefer escalate \
over block in ambiguous cases.
3. If specialists_run < 3, you have partial evidence. A single-domain high \
score should escalate, not block.
4. Ring signals carry the highest domain weight. A high ring score is the \
strongest indicator in the system.
5. Check whether primary signals across domains tell a coherent fraud story \
or are isolated anomalies.
6. Use step_up to challenge the user rather than blocking outright when risk \
is moderate.

## Output format

Respond with a JSON object exactly matching this schema:
{
  "verdict": "block" | "allow" | "step_up" | "escalate",
  "confidence": <float 0.0 to 1.0>,
  "reasoning": "<2 to 4 sentences explaining the verdict>",
  "evidence": ["<signal 1>", "<signal 2>", ...]
}

Respond with JSON only. No preamble, no markdown, no explanation outside the JSON.\
"""


def _build_user_message(
    risk_vector: RiskVector,
    specialist_scores: dict[str, Optional[SpecialistScore]],
) -> str:
    """Construct the user-turn prompt from the RiskVector and specialist scores."""
    stddev_str = (
        f"{risk_vector.score_stddev:.4f}"
        if risk_vector.score_stddev is not None
        else "N/A (single specialist)"
    )
    lines: list[str] = [
        "Risk Vector:",
        f"  aggregate       : {risk_vector.aggregate:.4f}",
        f"  score_stddev    : {stddev_str}",
        f"  specialists_run : {risk_vector.specialists_run}",
        f"  dominant_domain : {risk_vector.dominant_domain} ({risk_vector.dominant_score:.4f})",
        f"  available_domains: {', '.join(risk_vector.available_domains)}",
        "",
        "Domain scores and primary signals:",
    ]

    for domain in risk_vector.available_domains:
        score = risk_vector.scores[domain]
        spec = specialist_scores.get(domain)
        signals = ", ".join(spec.primary_signals) if spec else "unavailable"
        lines.append(f"  {domain:<10} {score:.4f}  →  {signals}")

    not_run = [d for d in ("ring", "payment", "ato", "identity", "payload", "promo")
               if d not in risk_vector.available_domains]
    if not_run:
        lines.append("")
        lines.append(f"Domains not run: {', '.join(not_run)}")

    lines.append("")
    lines.append("Produce your verdict.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Deterministic helpers
# ---------------------------------------------------------------------------

def _collect_evidence(specialist_scores: dict[str, Optional[SpecialistScore]]) -> list[str]:
    """Flatten primary signals from all available specialists, preserving order."""
    seen: set[str] = set()
    evidence: list[str] = []
    for spec in specialist_scores.values():
        if spec is None:
            continue
        for signal in spec.primary_signals:
            if signal not in seen and signal != "no_risk_signals_detected":
                seen.add(signal)
                evidence.append(signal)
    return evidence


def _decide_async_trigger(
    verdict: str,
    risk_vector: RiskVector,
) -> tuple[bool, Optional[str]]:
    """
    Apply the v1 trigger_async policy and return (trigger_async, trigger_reason).

    trigger_reason values are drawn exclusively from TRIGGER_REASONS in
    scoring_config.py so downstream systems can query against a fixed set.

    Policy:
        allow   + aggregate < 0.15              → False, None
        allow   + aggregate >= 0.15             → True,  "novel_allow_pattern"
        step_up + specialists_run < 3           → False, None
        step_up + stddev > threshold            → True,  "conflicting_signals"
        block   + specialists_run >= 3
                + aggregate > 0.85              → True,  "high_risk_multi_domain"
        block   + specialists_run < 3           → True,  "novel_pattern_candidate"
        escalate                                → True,  "conflicting_signals"
    """
    _CONFLICTING_SIGNALS = TRIGGER_REASONS[0]   # "conflicting_signals"
    _NOVEL_PATTERN       = TRIGGER_REASONS[1]   # "novel_pattern_candidate"
    _NOVEL_ALLOW         = TRIGGER_REASONS[2]   # "novel_allow_pattern"

    if verdict == "allow":
        if risk_vector.aggregate < ALLOW_THRESHOLD:
            return False, None
        return True, _NOVEL_ALLOW

    if verdict == "step_up":
        if risk_vector.specialists_run < _MIN_SPECIALISTS_FOR_BLOCK:
            return False, None
        if risk_vector.score_stddev is not None and risk_vector.score_stddev > RED_TEAM_VARIANCE_THRESHOLD:
            return True, _CONFLICTING_SIGNALS
        return False, None

    if verdict == "block":
        if risk_vector.specialists_run >= _MIN_SPECIALISTS_FOR_BLOCK and risk_vector.aggregate > BLOCK_THRESHOLD:
            return False, None  # consensus block — no investigation needed
        return True, _NOVEL_PATTERN

    # escalate (and any future verdict not matched above)
    return True, _CONFLICTING_SIGNALS


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------

def _timeout_fallback(risk_vector: RiskVector) -> ArbiterOutput:
    """Issued when the LLM call times out. Always escalates."""
    trigger_async, trigger_reason = _decide_async_trigger("escalate", risk_vector)
    return ArbiterOutput(
        verdict="escalate",
        confidence=0.0,
        reasoning=(
            "Arbiter LLM call timed out. Escalating to human review to avoid "
            "an uninformed automated decision."
        ),
        evidence=[],
        trigger_async=trigger_async,
        trigger_reason=trigger_reason,
        rule_name="llm_timeout_escalate",
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_arbiter(
    risk_vector: RiskVector,
    specialist_scores: dict[str, Optional[SpecialistScore]],
) -> ArbiterOutput:
    """
    Produce a final verdict from the RiskVector.

    Uses deterministic rules for clear-cut cases (aggregate > 0.85 with
    sufficient specialists, or aggregate < 0.15). Falls through to GPT-4o
    for everything in between. Times out at 500ms and falls back to escalate.

    Args:
        risk_vector:       Aggregated risk summary from risk_aggregation_node.
        specialist_scores: Dict mapping domain name to SpecialistScore or None.

    Returns:
        ArbiterOutput with verdict, confidence, reasoning, evidence, and
        async-trigger metadata.
    """

    # --- Deterministic: hard block ---
    # v1 policy: aggregate > 0.85 AND specialists_run >= 3
    # This is a starting threshold, not a validated rule.
    # Future iterations should consider corroboration shape:
    # 1. dominant domain strength (ring > 0.70 alone may warrant block)
    # 2. at least one supporting domain above 0.50
    # 3. ring dominance overrides aggregate in coordinated attack patterns
    if risk_vector.aggregate > BLOCK_THRESHOLD and risk_vector.specialists_run >= _MIN_SPECIALISTS_FOR_BLOCK:
        evidence = _collect_evidence(specialist_scores)
        trigger_async, trigger_reason = _decide_async_trigger("block", risk_vector)
        return ArbiterOutput(
            verdict="block",
            confidence=round(risk_vector.aggregate, 4),
            reasoning=(
                f"Aggregate risk score {risk_vector.aggregate:.4f} exceeds the block threshold "
                f"with {risk_vector.specialists_run} specialist domains in agreement. "
                f"Dominant domain is {risk_vector.dominant_domain} "
                f"({risk_vector.dominant_score:.4f}). No LLM synthesis required."
            ),
            evidence=evidence,
            trigger_async=trigger_async,
            trigger_reason=trigger_reason,
            rule_name="high_aggregate_block",
        )

    # --- Deterministic: hard allow ---
    if risk_vector.aggregate < ALLOW_THRESHOLD:
        trigger_async, trigger_reason = _decide_async_trigger("allow", risk_vector)
        return ArbiterOutput(
            verdict="allow",
            confidence=round(1.0 - risk_vector.aggregate, 4),
            reasoning=(
                f"Aggregate risk score {risk_vector.aggregate:.4f} is below the allow threshold. "
                f"No specialist domain raised a meaningful signal."
            ),
            evidence=["no_risk_signals_detected"],
            trigger_async=trigger_async,
            trigger_reason=trigger_reason,
            rule_name="low_aggregate_allow",
        )

    # --- Deterministic: escalate on specialist disagreement ---
    if risk_vector.score_stddev > RED_TEAM_VARIANCE_THRESHOLD:
        evidence = _collect_evidence(specialist_scores)
        trigger_async, trigger_reason = _decide_async_trigger("escalate", risk_vector)
        return ArbiterOutput(
            verdict="escalate",
            confidence=round(1.0 - risk_vector.score_stddev, 4),
            reasoning=(
                f"Specialist disagreement too high to issue an automated verdict "
                f"(stddev={risk_vector.score_stddev:.4f}, threshold={RED_TEAM_VARIANCE_THRESHOLD}). "
                f"Routing to human review."
            ),
            evidence=evidence,
            trigger_async=trigger_async,
            trigger_reason=trigger_reason,
            rule_name="high_variance_escalate",
        )

    # --- Deterministic: escalate on thin evidence ---
    if risk_vector.specialists_run < _MIN_SPECIALISTS_FOR_BLOCK:
        evidence = _collect_evidence(specialist_scores)
        trigger_async, trigger_reason = _decide_async_trigger("escalate", risk_vector)
        return ArbiterOutput(
            verdict="escalate",
            confidence=round(1.0 - risk_vector.aggregate, 4),
            reasoning=(
                f"Only {risk_vector.specialists_run} specialist domain(s) ran. "
                f"Insufficient corroboration to issue an automated verdict. "
                f"Routing to human review."
            ),
            evidence=evidence,
            trigger_async=trigger_async,
            trigger_reason=trigger_reason,
            rule_name="thin_evidence_escalate",
        )

    # --- LLM synthesis (genuinely ambiguous: moderate aggregate, specialists agree, sufficient evidence) ---
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    user_message = _build_user_message(risk_vector, specialist_scores)

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            temperature=0,
            timeout=0.5,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        )
    except APITimeoutError:
        return _timeout_fallback(risk_vector)

    raw = response.choices[0].message.content.strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Arbiter returned invalid JSON:\n{raw}") from exc

    # trigger_async and trigger_reason are always determined by deterministic policy,
    # not the LLM. The LLM is only responsible for verdict, confidence, reasoning,
    # and evidence. This keeps the trigger contract auditable and consistent.
    trigger_async, trigger_reason = _decide_async_trigger(data["verdict"], risk_vector)
    return ArbiterOutput(
        verdict=data["verdict"],
        confidence=data["confidence"],
        reasoning=data["reasoning"],
        evidence=data["evidence"],
        trigger_async=trigger_async,
        trigger_reason=trigger_reason,
        rule_name="llm_synthesis",
    )
