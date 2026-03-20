"""
FraudMind LangGraph Graph -- Version 2, Milestone 3 + P0 hard rules

Graph flow:
    START --> hard_rules
              ├── matched  --> END  (verdict set directly, no scoring)
              └── no match --> [parallel: ato, payment, identity, promo, ring, payload]
                              --> council_join --> risk_aggregation --> arbiter --> END

Hard rules run first. If a rule matches, the graph short-circuits to END
without invoking any specialist, aggregation, or LLM.
"""

import operator
from typing import Annotated, Optional

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send
from typing_extensions import TypedDict

from src.agents.ato_agent import score_ato
from src.agents.identity_agent import score_identity
from src.agents.payload_agent import score_payload
from src.agents.payment_agent import score_payment
from src.agents.promo_agent import score_promo
from src.agents.ring_detection_agent import score_ring
from src.aggregation.risk_aggregation import aggregate_scores
from src.arbiter.arbiter import run_arbiter
from src.rules.hard_rules import hard_rules_check
from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.promo_schemas import PromoSignals
from src.schemas.ring_schemas import RingSignals
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class FraudState(TypedDict, total=False):
    # Entity identification
    primary_entity_id: str
    primary_entity_type: str       # "account" | "buyer" | "seller" | "merchant" | "user"
    counterparty_id: Optional[str]
    transaction_id: Optional[str]
    device_id: Optional[str]
    payment_method_id: Optional[str]
    event_type: str                # "authentication" | "transaction" | "onboarding" | "profile_update"
    routing_tier: Optional[str]   # observability only; graph always runs full council

    # Input signals per specialist
    ato_signals: Optional[MockATOSignals]
    payment_signals: Optional[PaymentSignals]
    identity_signals: Optional[IdentitySignals]
    promo_signals: Optional[PromoSignals]
    ring_signals: Optional[RingSignals]
    payload_signals: Optional[PayloadSignals]

    # Output scores per specialist
    ato_score: Optional[SpecialistScore]
    payment_score: Optional[SpecialistScore]
    identity_score: Optional[SpecialistScore]
    promo_score: Optional[SpecialistScore]
    ring_score: Optional[SpecialistScore]
    payload_score: Optional[SpecialistScore]

    # Pipeline outputs
    risk_vector: Optional[RiskVector]
    arbiter_output: Optional[ArbiterOutput]

    # Operational metadata
    failed_agents: Annotated[list[str], operator.add]


# ---------------------------------------------------------------------------
# Specialists
# ---------------------------------------------------------------------------

# (scorer_fn, signals_key, score_key)
_SPECIALISTS: dict[str, tuple] = {
    "ato":      (score_ato,      "ato_signals",      "ato_score"),
    "payment":  (score_payment,  "payment_signals",  "payment_score"),
    "identity": (score_identity, "identity_signals", "identity_score"),
    "promo":    (score_promo,    "promo_signals",    "promo_score"),
    "ring":     (score_ring,     "ring_signals",     "ring_score"),
    "payload":  (score_payload,  "payload_signals",  "payload_score"),
}


def _make_specialist_node(name: str, scorer_fn, signals_key: str, score_key: str):
    def node(state: FraudState) -> dict:
        signals = state.get(signals_key)
        if signals is None:
            return {}
        try:
            return {score_key: scorer_fn(signals)}
        except Exception as e:
            return {"failed_agents": [f"{name}: {e}"]}
    node.__name__ = f"{name}_node"
    return node


def route_to_specialists(state: FraudState) -> list[Send]:
    """Fan out to all specialists whose input signals are present."""
    return [
        Send(name, state)
        for name, (_, signals_key, _) in _SPECIALISTS.items()
        if state.get(signals_key) is not None
    ]


# ---------------------------------------------------------------------------
# Hard rules node
# ---------------------------------------------------------------------------

_HARD_RULE_EVIDENCE: dict[str, list[str]] = {
    "confirmed_ring":    ["known_ring_signature_match", "linked_accounts_with_fraud_confirmed"],
    "known_bot":         ["tls_fingerprint_known_bot", "user_agent_is_headless"],
    "extreme_velocity":  ["transactions_last_1h"],
    "trusted_account":   ["account_age_days", "known_device", "home_geography", "normal_spend_ratio"],
}

_HARD_RULE_REASONING: dict[str, str] = {
    "confirmed_ring":   "Entity matches a confirmed fraud ring signature with multiple fraud-linked accounts. No scoring required.",
    "known_bot":        "TLS fingerprint and headless browser both confirm automated session. No scoring required.",
    "extreme_velocity": "20+ transactions in one hour indicates card testing. No scoring required.",
    "trusted_account":  "Account over 730 days old on a known device, home geography, and normal spend ratio. No scoring required.",
}

_HARD_RULE_CONFIDENCE: dict[str, float] = {
    "confirmed_ring":   0.98,
    "known_bot":        0.95,
    "extreme_velocity": 0.90,
    "trusted_account":  0.92,
}


def hard_rules_node(state: FraudState) -> dict:
    """
    Evaluate hard rules before any specialist scoring.
    If a rule matches, sets arbiter_output directly and the graph routes to END.
    If no rule matches, returns {} and the graph continues to specialists.
    """
    result = hard_rules_check(state)
    if not result.matched:
        return {}

    return {
        "arbiter_output": ArbiterOutput(
            verdict=result.verdict,
            confidence=_HARD_RULE_CONFIDENCE[result.rule_name],
            reasoning=_HARD_RULE_REASONING[result.rule_name],
            evidence=_HARD_RULE_EVIDENCE[result.rule_name],
            trigger_async=False,
            trigger_reason=None,
            rule_name=result.rule_name,
        )
    }


def _route_after_hard_rules(state: FraudState):
    """Short-circuit to END if a hard rule already produced a verdict."""
    if state.get("arbiter_output") is not None:
        return END
    return route_to_specialists(state)


# ---------------------------------------------------------------------------
# Pipeline nodes
# ---------------------------------------------------------------------------

def council_join(state: FraudState) -> dict:
    """Fan-in convergence point. Passes control to risk_aggregation."""
    return {}


def risk_aggregation_node(state: FraudState) -> dict:
    try:
        return {"risk_vector": aggregate_scores(
            ato_score=state.get("ato_score"),
            payment_score=state.get("payment_score"),
            identity_score=state.get("identity_score"),
            promo_score=state.get("promo_score"),
            ring_score=state.get("ring_score"),
            payload_score=state.get("payload_score"),
        )}
    except Exception as e:
        return {"failed_agents": [f"risk_aggregation: {e}"]}


def arbiter_node(state: FraudState) -> dict:
    risk_vector: Optional[RiskVector] = state.get("risk_vector")
    if risk_vector is None:
        return {"failed_agents": ["arbiter: no risk_vector available"]}
    specialist_scores = {
        name: state.get(score_key)
        for name, (_, _, score_key) in _SPECIALISTS.items()
    }
    try:
        return {"arbiter_output": run_arbiter(risk_vector, specialist_scores)}
    except Exception as e:
        return {"failed_agents": [f"arbiter: {e}"]}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_fraud_graph() -> StateGraph:
    graph = StateGraph(FraudState)

    graph.add_node("hard_rules", hard_rules_node)

    for name, (scorer_fn, signals_key, score_key) in _SPECIALISTS.items():
        graph.add_node(name, _make_specialist_node(name, scorer_fn, signals_key, score_key))

    graph.add_node("council_join", council_join)
    graph.add_node("risk_aggregation", risk_aggregation_node)
    graph.add_node("arbiter", arbiter_node)

    graph.add_edge(START, "hard_rules")
    graph.add_conditional_edges("hard_rules", _route_after_hard_rules)

    for name in _SPECIALISTS:
        graph.add_edge(name, "council_join")

    graph.add_edge("council_join", "risk_aggregation")
    graph.add_edge("risk_aggregation", "arbiter")
    graph.add_edge("arbiter", END)

    return graph.compile()


fraud_graph = build_fraud_graph()
