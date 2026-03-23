"""
FraudMind Analyst Copilot

Two pages:
  Financial Brief  — money saved, money leaking, top culprits
  Rule Proposals   — approve / reject system-generated rules

Run with:
    streamlit run src/analyst_copilot/app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from src.schemas.investigation_record import InvestigationRecord
from src.sentinel.memory_store import MemoryStore
from src.sentinel.pattern_detection import run_pattern_detection
from src.sentinel.red_team_agent import red_team_rule
from src.sentinel.rule_applier import apply_proposal
from src.sentinel.rule_proposer import ProposalStore

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="FraudMind",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
  /* Palette:
     ink     #1e293b  — primary text (slate-900, warm dark navy)
     slate   #475569  — secondary text
     muted   #94a3b8  — captions, labels
     border  #e2e8f0  — card borders
     surface #f8fafc  — card backgrounds
     green   #059669  — blocked / good (emerald-600)
     amber   #d97706  — escalated / at risk (amber-600)
     rose    #e11d48  — lost / fraud (rose-600)
     indigo  #6366f1  — info / neutral (indigo-500)
  */
  .stat-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 20px 24px;
    text-align: center;
  }
  .stat-val {
    font-size: 2rem;
    font-weight: 800;
    line-height: 1.1;
  }
  .stat-lbl {
    font-size: 0.72rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 6px;
  }
  .proposal-card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 16px;
  }
  .tag { display:inline-block; padding:2px 9px; border-radius:5px;
         font-size:0.73rem; font-family:monospace; margin:2px; }
  .tag-fraud { background:#ffe4e6; color:#9f1239; }
  .tag-plain { background:#f1f5f9; color:#475569; }
  .leak-row {
    display:flex; align-items:center; padding:10px 0;
    border-bottom:1px solid #f1f5f9;
  }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------

memory_store   = MemoryStore()
proposal_store = ProposalStore()


@st.cache_data(ttl=3600)
def _cached_patterns(time_window_hours: int = 48, min_count: int = 2) -> list:
    """Pattern detection results cached for 1 hour — one LLM call shared across all page loads."""
    return run_pattern_detection(time_window_hours=time_window_hours, min_count=min_count)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_FRAUD_TAGS = {"ring_fraud", "identity_fraud", "ato", "bot_session", "promo_abuse"}


def _tag_pills(tags: list) -> str:
    parts = []
    for t in tags:
        cls = "tag tag-fraud" if (t in _FRAUD_TAGS or t.endswith("_fraud")) else "tag tag-plain"
        parts.append(f'<span class="{cls}">{t}</span>')
    return " ".join(parts)


def _fmt(amount: float) -> str:
    return f"${amount:,.0f}"


def _stat_card(label: str, value: str, color: str, sub: str = "") -> str:
    return (
        f'<div class="stat-card" style="border-top:3px solid {color}">'
        f'<div class="stat-val" style="color:{color}">{value}</div>'
        f'<div class="stat-lbl">{label}</div>'
        + (f'<div style="font-size:0.8rem;color:#94a3b8;margin-top:4px">{sub}</div>' if sub else "")
        + f'</div>'
    )


# ---------------------------------------------------------------------------
# Page 1: Financial Brief
# ---------------------------------------------------------------------------

def page_financial_brief() -> None:
    st.markdown("## Financial Brief")

    records = memory_store.all_records()

    if not records:
        st.info("No investigation records yet.")
        return

    # ── Top-line numbers ────────────────────────────────────────────────────
    blocked   = [r for r in records if r.arbiter_verdict == "block"]
    escalated = [r for r in records if r.arbiter_verdict == "escalate"]
    lost      = [r for r in records if r.analyst_verdict == "false_positive"]

    blocked_usd   = sum(r.amount_usd or 0 for r in blocked)
    escalated_usd = sum(r.amount_usd or 0 for r in escalated)
    lost_usd      = sum(r.amount_usd or 0 for r in lost)

    c1, c2, c3 = st.columns(3)
    c1.markdown(_stat_card("Fraud Blocked", _fmt(blocked_usd),
                            "#059669", f"{len(blocked)} cases stopped"),
                unsafe_allow_html=True)
    c2.markdown(_stat_card("At Risk — Escalated", _fmt(escalated_usd),
                            "#d97706", f"{len(escalated)} cases pending"),
                unsafe_allow_html=True)
    c3.markdown(_stat_card("Confirmed Lost", _fmt(lost_usd),
                            "#e11d48", f"{len(lost)} false positive(s) confirmed"),
                unsafe_allow_html=True)

    st.divider()

    # ── Where money is bleeding — by pattern ────────────────────────────────
    st.markdown("### Where money is bleeding")
    st.caption("Fraud patterns ranked by total exposure across blocked and escalated cases.")

    # Aggregate $ by tag across blocked + escalated
    tag_exposure: dict[str, float] = {}
    tag_cases:    dict[str, int]   = {}
    for r in blocked + escalated:
        amt = r.amount_usd or 0
        for tag in r.pattern_tags:
            tag_exposure[tag] = tag_exposure.get(tag, 0) + amt
            tag_cases[tag]    = tag_cases.get(tag, 0) + 1

    if tag_exposure:
        sorted_tags = sorted(tag_exposure.items(), key=lambda x: x[1], reverse=True)
        max_exposure = sorted_tags[0][1] or 1

        # Table header
        col_tag, col_cases, col_exp, col_bar = st.columns([2, 1, 1, 3])
        col_tag.markdown("**Pattern**")
        col_cases.markdown("**Cases**")
        col_exp.markdown("**Exposure**")
        col_bar.markdown("")

        for tag, exposure in sorted_tags:
            is_fraud = tag in _FRAUD_TAGS or tag.endswith("_fraud")
            tag_html = (f'<span class="tag tag-fraud">{tag}</span>' if is_fraud
                        else f'<span class="tag tag-plain">{tag}</span>')
            col_tag, col_cases, col_exp, col_bar = st.columns([2, 1, 1, 3])
            col_tag.markdown(tag_html, unsafe_allow_html=True)
            col_cases.markdown(str(tag_cases[tag]))
            col_exp.markdown(f"**{_fmt(exposure)}**")
            col_bar.progress(exposure / max_exposure)
    else:
        st.success("No blocked or escalated cases.")

    st.divider()

    # ── Escalated cases — need eyes ─────────────────────────────────────────
    if escalated:
        st.markdown("### Escalations needing review")
        st.caption("These cases were not blocked — the system was uncertain. Review and label them.")

        for r in sorted(escalated, key=lambda x: x.amount_usd or 0, reverse=True):
            amt = r.amount_usd or 0
            entity = r.entity_id or r.case_id[:8]
            tags_html = _tag_pills(r.pattern_tags)
            labeled = r.analyst_verdict or "unlabeled"
            label_color = {"confirm_fraud": "#e11d48", "false_positive": "#059669",
                           "uncertain": "#d97706", "unlabeled": "#94a3b8"}.get(labeled, "#94a3b8")

            with st.expander(f"{entity}  —  {_fmt(amt)}  —  {labeled}", expanded=False):
                st.markdown(tags_html, unsafe_allow_html=True)
                st.markdown("")
                st.write(r.investigation_narrative)
                st.divider()
                if r.analyst_verdict:
                    st.success(f"Labeled: {r.analyst_verdict}")
                else:
                    b1, b2, b3, _ = st.columns([1, 1, 1, 4])
                    if b1.button("✅ Confirm Fraud", key=f"cf_{r.case_id}"):
                        memory_store.update_analyst_verdict(r.case_id, "confirm_fraud")
                        st.rerun()
                    if b2.button("❌ False Positive", key=f"fp_{r.case_id}"):
                        memory_store.update_analyst_verdict(r.case_id, "false_positive")
                        st.rerun()
                    if b3.button("⏭ Skip", key=f"sk_{r.case_id}"):
                        st.rerun()


# ---------------------------------------------------------------------------
# Page 2: Rule Proposals
# ---------------------------------------------------------------------------

def _render_proposed_change(proposal) -> None:
    rt = proposal.rule_type
    pc = proposal.proposed_change
    if rt == "weight_adjustment":
        field    = pc.get("field", "?")
        cur      = pc.get("current_value", "?")
        proposed = pc.get("proposed_value", "?")
        st.markdown(f"`{field}` — current: `{cur}` → proposed: **`{proposed}`**")
        st.caption(pc.get("rationale", ""))
    elif rt == "hard_rule":
        st.code(pc.get("condition", ""), language="python")
        st.markdown(f"Verdict: `{pc.get('verdict','?')}`")
        st.caption(pc.get("rationale", ""))
    else:  # sentinel_filter
        st.markdown(f"`{pc.get('action','?')}` on `{pc.get('target','?')}`")
        st.caption(pc.get("rationale", ""))


def page_proposals() -> None:
    st.markdown("## Rule Proposals")
    st.caption("System-generated rule changes. Approve to queue for deployment, reject to dismiss.")

    pending = proposal_store.load_pending()
    records = memory_store.all_records()

    if not pending:
        st.success("Queue is clear — no pending proposals.")
        return

    for proposal in pending:
        # Estimate $ impact: sum exposure across matching tags
        tag_set = set(proposal.pattern_tags)
        matching = [r for r in records
                    if tag_set & set(r.pattern_tags) and r.arbiter_verdict in ("block", "escalate")]
        estimated_impact = sum(r.amount_usd or 0 for r in matching)

        # FP rate from labeled records
        labeled = [r for r in records
                   if tag_set & set(r.pattern_tags) and r.analyst_verdict is not None]
        fp_rate_str = ""
        if labeled:
            fp_n = sum(1 for r in labeled if r.analyst_verdict == "false_positive")
            fp_rate = fp_n / len(labeled) * 100
            fp_color = "#059669" if fp_rate < 5 else "#d97706" if fp_rate < 20 else "#e11d48"
            fp_rate_str = f'<span style="color:{fp_color};font-weight:600">{fp_rate:.0f}% FP rate</span> on labeled cases'

        rt_label = {"hard_rule": "Hard Rule", "weight_adjustment": "Weight Adjustment",
                    "sentinel_filter": "Sentinel Filter"}.get(proposal.rule_type, proposal.rule_type)
        rt_color = {"hard_rule": "#e11d48", "weight_adjustment": "#d97706",
                    "sentinel_filter": "#6366f1"}.get(proposal.rule_type, "#94a3b8")

        st.markdown(
            f'<div class="proposal-card" style="border-left:4px solid {rt_color}">'
            f'<div style="display:flex;justify-content:space-between;align-items:flex-start">'
            f'<div>'
            f'<span style="font-size:1.1rem;font-weight:700;color:#1e293b">{proposal.rule_name}</span>'
            f'&nbsp;&nbsp;<span style="font-size:0.75rem;color:{rt_color};font-weight:600;'
            f'text-transform:uppercase">{rt_label}</span>'
            f'</div>'
            f'<div style="text-align:right">'
            f'<div style="font-size:1.5rem;font-weight:800;color:#059669">{_fmt(estimated_impact)}</div>'
            f'<div style="font-size:0.72rem;color:#94a3b8;text-transform:uppercase">estimated exposure covered</div>'
            f'</div></div>'
            f'<div style="margin-top:10px;color:#475569">{proposal.description}</div>'
            f'<div style="margin-top:8px">{_tag_pills(proposal.pattern_tags)}</div>'
            + (f'<div style="margin-top:8px;font-size:0.85rem">{fp_rate_str}</div>' if fp_rate_str else "")
            + f'</div>',
            unsafe_allow_html=True,
        )

        with st.expander("See proposed change", expanded=False):
            _render_proposed_change(proposal)
            st.markdown(f"**Expected impact:** {proposal.expected_impact}")
            st.markdown(f"**Risk:** {proposal.risk}")

        col_approve, col_reject, col_rt, _ = st.columns([1, 1, 1, 3])
        if col_approve.button("✅ Approve", key=f"approve_{proposal.proposal_id}",
                              use_container_width=True, type="primary"):
            result = apply_proposal(proposal)
            proposal_store.update_status(proposal.proposal_id, "approved")
            st.success(result)
            st.rerun()
        if col_rt.button("🔴 Red Team", key=f"rt_{proposal.proposal_id}",
                         use_container_width=True):
            with st.spinner("Red team agent running adversarial scenarios…"):
                report = red_team_rule(proposal)
            color = {"approve": "🟢", "revise": "🟡", "reject": "🔴"}.get(report.recommendation, "⚪")
            st.markdown(
                f"**{color} Red Team: {report.recommendation.upper()}** — "
                f"{report.recommendation_reasoning}  \n"
                f"`{report.attempts_bypassed_rule}/{report.attempts_total}` bypass rule · "
                f"`{report.attempts_bypassed_system}/{report.attempts_total}` bypass system"
            )
            with st.expander("Bypass scenarios", expanded=False):
                for i, s in enumerate(report.scenarios, 1):
                    fired = "✅ rule fired" if s.rule_fired else f"❌ evaded → caught by: {s.caught_by or 'none'}"
                    st.markdown(f"**{i}. {s.description}**  \n`{fired}` · system verdict: `{s.system_verdict}`")
                    st.json(s.signal_overrides)
        if col_reject.button("❌ Reject", key=f"reject_{proposal.proposal_id}",
                             use_container_width=True):
            proposal_store.update_status(proposal.proposal_id, "rejected")
            st.rerun()

        st.divider()


# ---------------------------------------------------------------------------
# Sidebar & navigation
# ---------------------------------------------------------------------------

PAGES = {
    "Financial Brief": page_financial_brief,
    "Rule Proposals":  page_proposals,
}

if "page" not in st.session_state:
    st.session_state.page = "Financial Brief"

st.sidebar.markdown("## 🛡️ FraudMind")
st.sidebar.divider()

for name in PAGES:
    if st.sidebar.button(name, key=f"nav_{name}", use_container_width=True,
                         type="primary" if st.session_state.page == name else "secondary"):
        st.session_state.page = name
        st.rerun()

st.sidebar.divider()
_records = memory_store.all_records()
_blocked_usd = sum(r.amount_usd or 0 for r in _records if r.arbiter_verdict == "block")
_pending = sum(1 for p in proposal_store._load_all() if p.get("status") == "pending")
st.sidebar.metric("Fraud blocked", _fmt(_blocked_usd))
st.sidebar.caption(f"{_pending} proposals pending")

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

PAGES[st.session_state.page]()
