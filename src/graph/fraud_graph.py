"""
FraudMind LangGraph Graph -- Version 1

Wires the ATO Agent and Payment Agent into a sequential graph with shared
FraudState. Each node runs its agent if the relevant signals are present
in state, then writes its verdict back to state.

Graph flow:
    START --> ato_node --> payment_node --> END
"""

from typing import Optional

from langgraph.graph import END, StateGraph
from typing_extensions import TypedDict

from src.agents.ato_agent import run_ato_agent
from src.agents.payment_agent import run_payment_agent
from src.schemas.ato_schemas import ATOVerdict, MockATOSignals
from src.schemas.payment_schemas import PaymentSignals, PaymentVerdict


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class FraudState(TypedDict, total=False):
    """
    Shared state passed between all nodes in the fraud graph.

    Both agents read from and write to this state. Fields are optional so
    that a session can carry ATO signals only, payment signals only, or both.
    """

    account_id: str
    ato_signals: Optional[MockATOSignals]
    payment_signals: Optional[PaymentSignals]
    ato_verdict: Optional[ATOVerdict]
    payment_verdict: Optional[PaymentVerdict]


# ---------------------------------------------------------------------------
# Graph nodes
# ---------------------------------------------------------------------------

def ato_node(state: FraudState) -> dict:
    """
    Run the ATO Agent if ATO signals are present in state.

    Returns an update dict with the ato_verdict key populated, or an empty
    dict if no ATO signals were provided.
    """
    signals: Optional[MockATOSignals] = state.get("ato_signals")
    if signals is None:
        return {}
    verdict = run_ato_agent(signals)
    return {"ato_verdict": verdict}


def payment_node(state: FraudState) -> dict:
    """
    Run the Payment Agent if payment signals are present in state.

    Returns an update dict with the payment_verdict key populated, or an
    empty dict if no payment signals were provided.
    """
    signals: Optional[PaymentSignals] = state.get("payment_signals")
    if signals is None:
        return {}
    verdict = run_payment_agent(signals)
    return {"payment_verdict": verdict}


# ---------------------------------------------------------------------------
# Graph assembly
# ---------------------------------------------------------------------------

def build_fraud_graph() -> StateGraph:
    """
    Build and compile the Version 1 fraud graph.

    Returns:
        A compiled LangGraph StateGraph ready to invoke.
    """
    graph = StateGraph(FraudState)

    graph.add_node("ato", ato_node)
    graph.add_node("payment", payment_node)

    graph.set_entry_point("ato")
    graph.add_edge("ato", "payment")
    graph.add_edge("payment", END)

    return graph.compile()


# Module-level compiled graph for direct import
fraud_graph = build_fraud_graph()
