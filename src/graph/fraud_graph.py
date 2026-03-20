"""
FraudMind LangGraph Graph -- Version 2, Milestone 3

All six specialist agents always run in parallel (full council).

Graph flow:
    START --> set_routing_tier --> [parallel fan-out via Send] --> council_join
          --> risk_aggregation --> arbiter --> END
"""

import operator
from typing import Annotated, Optional

from langgraph.graph import END, StateGraph
from langgraph.types import Send
from typing_extensions import TypedDict

from src.agents.ato_agent import score_ato
from src.agents.identity_agent import score_identity
from src.agents.payload_agent import score_payload
from src.agents.payment_agent import score_payment
from src.agents.promo_agent import score_promo
from src.agents.ring_detection_agent import score_ring
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.final_schemas import FinalVerdict
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.promo_schemas import PromoSignals
from src.schemas.ring_schemas import RingSignals
from src.aggregation.risk_aggregation import aggregate_scores
from src.arbiter.arbiter import run_arbiter
from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class FraudState(TypedDict, total=False):
    """
    Shared state passed between all nodes in the fraud graph.

    All fields are optional (total=False) so a session can carry any subset
    of signals. Multi-entity identification fields match the architecture.md
    canonical FraudState definition.

    failed_agents uses an Annotated reducer so that multiple parallel
    nodes can each append failure entries without overwriting each other.
    Each entry is a string of the form "agent_name: error message".
    """

    # Multi-entity identification
    primary_entity_id: str
    primary_entity_type: str          # "account" | "buyer" | "seller" | "merchant" | "user"
    counterparty_id: Optional[str]
    transaction_id: Optional[str]
    device_id: Optional[str]
    payment_method_id: Optional[str]
    event_type: str                   # "authentication" | "transaction" | "onboarding" | "profile_update"

    # Routing metadata (always full_council; kept for observability)
    routing_tier: Optional[str]

    # Input signals per specialist
    ato_signals: Optional[MockATOSignals]
    payment_signals: Optional[PaymentSignals]
    identity_signals: Optional[IdentitySignals]
    promo_signals: Optional[PromoSignals]
    ring_signals: Optional[RingSignals]
    payload_signals: Optional[PayloadSignals]

    # Output scores per specialist (SpecialistScore: score, primary_signals, signals_evaluated)
    ato_score: Optional[SpecialistScore]
    payment_score: Optional[SpecialistScore]
    identity_score: Optional[SpecialistScore]
    promo_score: Optional[SpecialistScore]
    ring_score: Optional[SpecialistScore]
    payload_score: Optional[SpecialistScore]

    # Risk aggregation (Milestone 2)
    risk_vector: Optional[RiskVector]

    # Arbiter verdict (Milestone 3)
    arbiter_output: Optional[ArbiterOutput]

    # Post-council (future milestones)
    red_team_challenge: Optional[str]
    final_verdict: Optional[FinalVerdict]

    # Operational metadata
    failed_agents: Annotated[list[str], operator.add]
    investigation_start_time: Optional[str]


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

_ALL_AGENTS = {"ato", "payment", "identity", "promo", "ring", "payload"}

_SIGNAL_GUARD: dict[str, str] = {
    "ato":      "ato_signals",
    "payment":  "payment_signals",
    "identity": "identity_signals",
    "promo":    "promo_signals",
    "ring":     "ring_signals",
    "payload":  "payload_signals",
}


def set_routing_tier(state: FraudState) -> dict:
    """Always routes full council. Kept for graph structure consistency."""
    return {"routing_tier": "full_council"}


def route_to_specialists(state: FraudState) -> list[Send]:
    """Fan out to all specialist nodes in parallel. Skips any whose signals are absent."""
    return [
        Send(agent, state)
        for agent, sig_key in _SIGNAL_GUARD.items()
        if state.get(sig_key) is not None
    ]


# ---------------------------------------------------------------------------
# Specialist nodes
# ---------------------------------------------------------------------------

def ato_node(state: FraudState) -> dict:
    """Run the ATO scorer. Returns ato_score or records failure."""
    signals: Optional[MockATOSignals] = state.get("ato_signals")
    if signals is None:
        return {}
    try:
        return {"ato_score": score_ato(signals)}
    except Exception as e:
        return {"failed_agents": [f"ato: {e}"]}


def payment_node(state: FraudState) -> dict:
    """Run the Payment scorer. Returns payment_score or records failure."""
    signals: Optional[PaymentSignals] = state.get("payment_signals")
    if signals is None:
        return {}
    try:
        return {"payment_score": score_payment(signals)}
    except Exception as e:
        return {"failed_agents": [f"payment: {e}"]}


def identity_node(state: FraudState) -> dict:
    """Run the Identity scorer. Returns identity_score or records failure."""
    signals: Optional[IdentitySignals] = state.get("identity_signals")
    if signals is None:
        return {}
    try:
        return {"identity_score": score_identity(signals)}
    except Exception as e:
        return {"failed_agents": [f"identity: {e}"]}


def promo_node(state: FraudState) -> dict:
    """Run the Promo scorer. Returns promo_score or records failure."""
    signals: Optional[PromoSignals] = state.get("promo_signals")
    if signals is None:
        return {}
    try:
        return {"promo_score": score_promo(signals)}
    except Exception as e:
        return {"failed_agents": [f"promo: {e}"]}


def ring_node(state: FraudState) -> dict:
    """
    Run the Ring Detection scorer. This node always runs if ring_signals are present.
    Returns ring_score or records failure.
    """
    signals: Optional[RingSignals] = state.get("ring_signals")
    if signals is None:
        return {}
    try:
        return {"ring_score": score_ring(signals)}
    except Exception as e:
        return {"failed_agents": [f"ring: {e}"]}


def payload_node(state: FraudState) -> dict:
    """Run the Payload scorer. Returns payload_score or records failure."""
    signals: Optional[PayloadSignals] = state.get("payload_signals")
    if signals is None:
        return {}
    try:
        return {"payload_score": score_payload(signals)}
    except Exception as e:
        return {"failed_agents": [f"payload: {e}"]}


def council_join(state: FraudState) -> dict:
    """
    Fan-in convergence node. All parallel specialist branches terminate here.

    This node is invoked once per completing parallel branch and runs a final
    time when all branches have finished. Passes control to risk_aggregation.
    """
    return {}


def risk_aggregation_node(state: FraudState) -> dict:
    """
    Aggregate all available specialist scores into a single RiskVector.

    Reads whichever specialist scores are present in state (None scores are
    excluded), computes a weighted aggregate, standard deviation, and identifies
    the dominant domain. Stores the result as risk_vector in state.

    If no specialist scores are available (e.g. all failed), records the
    failure and returns without a risk_vector.
    """
    try:
        risk_vector = aggregate_scores(
            ato_score=state.get("ato_score"),
            payment_score=state.get("payment_score"),
            identity_score=state.get("identity_score"),
            promo_score=state.get("promo_score"),
            ring_score=state.get("ring_score"),
            payload_score=state.get("payload_score"),
        )
        return {"risk_vector": risk_vector}
    except Exception as e:
        return {"failed_agents": [f"risk_aggregation: {e}"]}


def arbiter_node(state: FraudState) -> dict:
    """
    Produce the final verdict from the RiskVector.

    Applies three-tier logic: deterministic block/allow for clear-cut cases,
    GPT-4o LLM synthesis for everything in between. Falls back to escalate
    on LLM timeout. Stores the result as arbiter_output in state.

    If no risk_vector is present (all specialists failed), records the
    failure and returns without an arbiter_output.
    """
    risk_vector: Optional[RiskVector] = state.get("risk_vector")
    if risk_vector is None:
        return {"failed_agents": ["arbiter: no risk_vector available"]}

    specialist_scores: dict[str, Optional[SpecialistScore]] = {
        "ato":      state.get("ato_score"),
        "payment":  state.get("payment_score"),
        "identity": state.get("identity_score"),
        "promo":    state.get("promo_score"),
        "ring":     state.get("ring_score"),
        "payload":  state.get("payload_score"),
    }

    try:
        output = run_arbiter(risk_vector, specialist_scores)
        return {"arbiter_output": output}
    except Exception as e:
        return {"failed_agents": [f"arbiter: {e}"]}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_fraud_graph() -> StateGraph:
    """
    Build and compile the Version 2 fraud graph (Milestone 3).

    Topology:
        START → set_routing_tier → [parallel: ato, payment, identity, promo, ring, payload]
                                 → council_join → risk_aggregation → arbiter → END

    Returns:
        A compiled LangGraph StateGraph ready to invoke.
    """
    graph = StateGraph(FraudState)

    graph.add_node("set_routing_tier", set_routing_tier)
    graph.add_node("ato", ato_node)
    graph.add_node("payment", payment_node)
    graph.add_node("identity", identity_node)
    graph.add_node("promo", promo_node)
    graph.add_node("ring", ring_node)
    graph.add_node("payload", payload_node)
    graph.add_node("council_join", council_join)
    graph.add_node("risk_aggregation", risk_aggregation_node)
    graph.add_node("arbiter", arbiter_node)

    graph.set_entry_point("set_routing_tier")
    graph.add_conditional_edges("set_routing_tier", route_to_specialists)

    for specialist in ("ato", "payment", "identity", "promo", "ring", "payload"):
        graph.add_edge(specialist, "council_join")

    graph.add_edge("council_join", "risk_aggregation")
    graph.add_edge("risk_aggregation", "arbiter")
    graph.add_edge("arbiter", END)

    return graph.compile()


# Module-level compiled graph for direct import
fraud_graph = build_fraud_graph()
