"""
FraudMind LangGraph Graph -- Version 2, Milestone 3

Graph flow:
    START --> [parallel: ato, payment, identity, promo, ring, payload]
          --> council_join --> risk_aggregation --> arbiter --> END

All six specialists run in parallel. Only those with signals present execute.
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

    for name, (scorer_fn, signals_key, score_key) in _SPECIALISTS.items():
        graph.add_node(name, _make_specialist_node(name, scorer_fn, signals_key, score_key))

    graph.add_node("council_join", council_join)
    graph.add_node("risk_aggregation", risk_aggregation_node)
    graph.add_node("arbiter", arbiter_node)

    graph.add_conditional_edges(START, route_to_specialists)

    for name in _SPECIALISTS:
        graph.add_edge(name, "council_join")

    graph.add_edge("council_join", "risk_aggregation")
    graph.add_edge("risk_aggregation", "arbiter")
    graph.add_edge("arbiter", END)

    return graph.compile()


fraud_graph = build_fraud_graph()
