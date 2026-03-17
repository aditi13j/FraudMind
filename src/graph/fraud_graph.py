"""
FraudMind LangGraph Graph -- Version 2

Six specialist agents run in parallel with conditional routing.
Ring Detection always runs regardless of routing tier.

Graph flow:
    START --> set_routing_tier --> [parallel fan-out via Send] --> council_join --> END

Routing tiers (set routing_tier in input state before invoking):
    fast         -- Ring Detection only (single-domain, high prior confidence)
    standard     -- ATO + Payment + Ring Detection
    full_council -- All 6 specialists (default when routing_tier is not set)

Ring Detection always runs regardless of tier if ring_signals are present.
If a known_ring_signature_match is detected in ring_signals, the tier is forced
to full_council regardless of the caller's routing_tier value.
"""

import operator
from typing import Annotated, Optional

from langgraph.graph import END, StateGraph
from langgraph.types import Send
from typing_extensions import TypedDict

from src.agents.ato_agent import run_ato_agent
from src.agents.identity_agent import run_identity_agent
from src.agents.payload_agent import run_payload_agent
from src.agents.payment_agent import run_payment_agent
from src.agents.promo_agent import run_promo_agent
from src.agents.ring_detection_agent import run_ring_detection_agent
from src.schemas.ato_schemas import ATOVerdict, MockATOSignals
from src.schemas.final_schemas import FinalVerdict
from src.schemas.identity_schemas import IdentitySignals, IdentityVerdict
from src.schemas.payload_schemas import PayloadSignals, PayloadVerdict
from src.schemas.payment_schemas import PaymentSignals, PaymentVerdict
from src.schemas.promo_schemas import PromoSignals, PromoVerdict
from src.schemas.ring_schemas import RingSignals, RingVerdict


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class FraudState(TypedDict, total=False):
    """
    Shared state passed between all nodes in the fraud graph.

    All fields are optional (total=False) so a session can carry any subset
    of signals. Multi-entity identification fields match the architecture.md
    canonical FraudState definition.

    agents_unavailable uses an Annotated reducer so that multiple parallel
    nodes can each append failure entries without overwriting each other.
    """

    # Multi-entity identification
    primary_entity_id: str
    primary_entity_type: str          # "user" | "passenger" | "driver" | "merchant"
    counterparty_id: Optional[str]
    transaction_id: Optional[str]
    device_id: Optional[str]
    payment_method_id: Optional[str]
    event_type: str                   # "login" | "payment" | "ride_request" | "signup"

    # Routing metadata
    routing_tier: Optional[str]       # "fast" | "standard" | "full_council"

    # Input signals per specialist
    ato_signals: Optional[MockATOSignals]
    payment_signals: Optional[PaymentSignals]
    identity_signals: Optional[IdentitySignals]
    promo_signals: Optional[PromoSignals]
    ring_signals: Optional[RingSignals]
    payload_signals: Optional[PayloadSignals]

    # Output verdicts per specialist
    ato_verdict: Optional[ATOVerdict]
    payment_verdict: Optional[PaymentVerdict]
    identity_verdict: Optional[IdentityVerdict]
    promo_verdict: Optional[PromoVerdict]
    ring_verdict: Optional[RingVerdict]
    payload_verdict: Optional[PayloadVerdict]

    # Post-council (Version 4)
    red_team_challenge: Optional[str]
    final_verdict: Optional[FinalVerdict]

    # Operational metadata
    agents_unavailable: Annotated[list[str], operator.add]
    investigation_start_time: Optional[str]


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

_FULL_COUNCIL_AGENTS = {"ato", "payment", "identity", "promo", "ring", "payload"}
_STANDARD_AGENTS = {"ato", "payment", "ring"}
_FAST_AGENTS = {"ring"}


def set_routing_tier(state: FraudState) -> dict:
    """
    Determine and write the routing tier into state.

    If routing_tier is already set to a valid value, respect it unless a known
    ring signature match forces an upgrade to full_council.

    Returns a partial state update dict with routing_tier populated.
    """
    ring_signals: Optional[RingSignals] = state.get("ring_signals")
    force_full = ring_signals is not None and ring_signals.known_ring_signature_match

    current_tier = state.get("routing_tier")
    if force_full or current_tier not in ("fast", "standard", "full_council"):
        return {"routing_tier": "full_council"}
    return {"routing_tier": current_tier}


def route_to_specialists(state: FraudState) -> list[Send]:
    """
    Conditional edge function: fan out to the correct specialist nodes in parallel.

    Called after set_routing_tier has written routing_tier into state. Returns a
    list of Send objects that LangGraph dispatches concurrently.

    Ring Detection always runs if ring_signals are present, regardless of tier.
    """
    tier = state.get("routing_tier", "full_council")

    if tier == "fast":
        active_agent_names = set(_FAST_AGENTS)
    elif tier == "standard":
        active_agent_names = set(_STANDARD_AGENTS)
    else:
        active_agent_names = set(_FULL_COUNCIL_AGENTS)

    # Map agent name to the signals key that must be present to run it
    signal_guard: dict[str, str] = {
        "ato":     "ato_signals",
        "payment": "payment_signals",
        "identity":"identity_signals",
        "promo":   "promo_signals",
        "ring":    "ring_signals",
        "payload": "payload_signals",
    }

    sends: list[Send] = []
    for agent_name in active_agent_names:
        if state.get(signal_guard[agent_name]) is not None:
            sends.append(Send(agent_name, state))

    return sends


# ---------------------------------------------------------------------------
# Specialist nodes
# ---------------------------------------------------------------------------

def ato_node(state: FraudState) -> dict:
    """Run the ATO Agent. Returns ato_verdict or marks agent unavailable on failure."""
    signals: Optional[MockATOSignals] = state.get("ato_signals")
    if signals is None:
        return {}
    try:
        return {"ato_verdict": run_ato_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["ato"]}


def payment_node(state: FraudState) -> dict:
    """Run the Payment Agent. Returns payment_verdict or marks agent unavailable on failure."""
    signals: Optional[PaymentSignals] = state.get("payment_signals")
    if signals is None:
        return {}
    try:
        return {"payment_verdict": run_payment_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["payment"]}


def identity_node(state: FraudState) -> dict:
    """Run the Identity Agent. Returns identity_verdict or marks agent unavailable on failure."""
    signals: Optional[IdentitySignals] = state.get("identity_signals")
    if signals is None:
        return {}
    try:
        return {"identity_verdict": run_identity_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["identity"]}


def promo_node(state: FraudState) -> dict:
    """Run the Promo Agent. Returns promo_verdict or marks agent unavailable on failure."""
    signals: Optional[PromoSignals] = state.get("promo_signals")
    if signals is None:
        return {}
    try:
        return {"promo_verdict": run_promo_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["promo"]}


def ring_node(state: FraudState) -> dict:
    """
    Run the Ring Detection Agent. This node always runs if ring_signals are present.
    Returns ring_verdict or marks agent unavailable on failure.
    """
    signals: Optional[RingSignals] = state.get("ring_signals")
    if signals is None:
        return {}
    try:
        return {"ring_verdict": run_ring_detection_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["ring"]}


def payload_node(state: FraudState) -> dict:
    """Run the Payload Agent. Returns payload_verdict or marks agent unavailable on failure."""
    signals: Optional[PayloadSignals] = state.get("payload_signals")
    if signals is None:
        return {}
    try:
        return {"payload_verdict": run_payload_agent(signals)}
    except Exception:
        return {"agents_unavailable": ["payload"]}


def council_join(state: FraudState) -> dict:
    """
    Fan-in convergence node. All parallel specialist branches terminate here.

    This node is invoked once per completing parallel branch and runs a final
    time when all branches have finished. No state mutations are needed here
    in Version 2 -- the Arbiter Agent (Version 4) will synthesize verdicts.
    """
    return {}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_fraud_graph() -> StateGraph:
    """
    Build and compile the Version 2 fraud graph.

    Topology:
        START → set_routing_tier → [parallel: ato, payment, identity, promo, ring, payload]
                                 → council_join → END

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

    graph.set_entry_point("set_routing_tier")
    graph.add_conditional_edges("set_routing_tier", route_to_specialists)

    for specialist in ("ato", "payment", "identity", "promo", "ring", "payload"):
        graph.add_edge(specialist, "council_join")

    graph.add_edge("council_join", END)

    return graph.compile()


# Module-level compiled graph for direct import
fraud_graph = build_fraud_graph()
