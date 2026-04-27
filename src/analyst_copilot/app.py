"""
FraudMind Analyst Copilot — Milestone 7C

Four pages:
  Dashboard      — financial KPIs, bleeding patterns, Sentinel confidence
  Investigations — case queue with full detail panel
  Proposals      — rule proposals with approve / reject / red-team
  Patterns       — pattern intelligence grouped by finding type

Run with:
    streamlit run src/analyst_copilot/app.py
"""

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from src.schemas.investigation_record import InvestigationRecord
from src.sentinel.memory_store import MemoryStore
from src.sentinel.pattern_detection import run_pattern_detection
from src.sentinel.red_team_agent import red_team_rule
from src.sentinel.rule_applier import apply_proposal
from src.sentinel.rule_proposer import ProposalStore, revise_rule

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="FraudMind Analyst Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
/* Card containers */
.fm-card {
    background: #1a1a2e;
    border: 1px solid #2d2d4e;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 12px;
}
.fm-card-red   { border-left: 4px solid #ff4b4b; }
.fm-card-amber { border-left: 4px solid #ff8c00; }
.fm-card-green { border-left: 4px solid #00c853; }
.fm-card-blue  { border-left: 4px solid #4b8bff; }

/* Financial metric cards */
.fm-metric {
    background: #1a1a2e;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    border: 1px solid #2d2d4e;
}
.fm-metric-value {
    font-size: 2rem;
    font-weight: 700;
    line-height: 1.1;
}
.fm-metric-label {
    font-size: 0.78rem;
    color: #888;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
}
.fm-metric-sub {
    font-size: 0.85rem;
    color: #aaa;
    margin-top: 6px;
}

/* Verdict badges */
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}
.badge-red    { background: #ff4b4b22; color: #ff4b4b; border: 1px solid #ff4b4b55; }
.badge-amber  { background: #ff8c0022; color: #ff8c00; border: 1px solid #ff8c0055; }
.badge-green  { background: #00c85322; color: #00c853; border: 1px solid #00c85355; }
.badge-blue   { background: #4b8bff22; color: #4b8bff; border: 1px solid #4b8bff55; }

/* Pattern tag pills */
.tag-pill {
    display: inline-block;
    background: #2d2d4e;
    color: #ccc;
    border-radius: 6px;
    padding: 2px 8px;
    font-size: 0.75rem;
    margin: 2px;
    font-family: monospace;
}
.tag-pill-fraud { background: #ff4b4b22; color: #ff4b4b; }
.tag-pill-bot   { background: #ff8c0022; color: #ff8c00; }

/* Score bar */
.score-bar-track {
    background: #2d2d4e;
    border-radius: 4px;
    height: 8px;
    margin: 4px 0 12px 0;
}
.score-bar-fill-red   { background: #ff4b4b; border-radius: 4px; height: 8px; }
.score-bar-fill-amber { background: #ff8c00; border-radius: 4px; height: 8px; }
.score-bar-fill-green { background: #00c853; border-radius: 4px; height: 8px; }

/* Narrative block */
.narrative-box {
    background: #1a1a2e;
    border-left: 3px solid #4b8bff;
    border-radius: 0 8px 8px 0;
    padding: 14px 18px;
    font-size: 0.95rem;
    line-height: 1.6;
    color: #ddd;
    margin: 12px 0;
}

/* Queue item */
.queue-item {
    padding: 10px 12px;
    border-radius: 8px;
    margin-bottom: 6px;
    cursor: pointer;
    border: 1px solid #2d2d4e;
}
.queue-item-active {
    background: #2d2d4e;
    border-color: #4b8bff;
}

/* Anomaly highlight */
.anomaly { color: #ff4b4b; font-weight: 600; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------

memory_store   = MemoryStore()
proposal_store = ProposalStore()

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _verdict_badge(verdict: str) -> str:
    cls = {
        "block":    "badge-red",
        "escalate": "badge-amber",
        "step_up":  "badge-amber",
        "allow":    "badge-green",
    }.get(verdict, "badge-blue")
    return f'<span class="badge {cls}">{verdict.upper()}</span>'


def _assessment_badge(assessment: str) -> str:
    cls = {
        "likely_correct":          "badge-red",
        "possible_false_positive": "badge-blue",
        "uncertain":               "badge-amber",
    }.get(assessment, "badge-blue")
    return f'<span class="badge {cls}">{assessment.replace("_", " ").upper()}</span>'


def _tag_pills(tags: list) -> str:
    parts = []
    for t in tags:
        if t.endswith("_fraud"):
            cls = "tag-pill tag-pill-fraud"
        elif t in ("bot_session", "credential_stuffing"):
            cls = "tag-pill tag-pill-bot"
        else:
            cls = "tag-pill"
        parts.append(f'<span class="{cls}">{t}</span>')
    return " ".join(parts)


def _score_bar(score: float) -> str:
    if score > 0.70:
        fill_cls = "score-bar-fill-red"
    elif score > 0.35:
        fill_cls = "score-bar-fill-amber"
    else:
        fill_cls = "score-bar-fill-green"
    width = f"{score * 100:.0f}%"
    return (
        f'<div class="score-bar-track">'
        f'<div class="{fill_cls}" style="width:{width}"></div>'
        f'</div>'
    )


def _fmt_usd(amount) -> str:
    if amount is None:
        return "$0"
    return f"${amount:,.0f}"


def _metric_card(label: str, value: str, sub: str, color: str) -> str:
    return (
        f'<div class="fm-metric" style="border-left:4px solid {color}">'
        f'<div class="fm-metric-value" style="color:{color}">{value}</div>'
        f'<div class="fm-metric-label">{label}</div>'
        f'<div class="fm-metric-sub">{sub}</div>'
        f'</div>'
    )


def _financial_summary(records: list) -> dict:
    blocked_usd    = sum(r.amount_usd or 0 for r in records if r.arbiter_verdict == "block")
    escalated_usd  = sum(r.amount_usd or 0 for r in records if r.arbiter_verdict == "escalate")
    lost_usd       = sum(r.amount_usd or 0 for r in records if r.analyst_verdict == "false_positive")
    blocked_count  = sum(1 for r in records if r.arbiter_verdict == "block")
    escalated_count= sum(1 for r in records if r.arbiter_verdict == "escalate")
    unlabeled_count= sum(1 for r in records if r.analyst_verdict is None)
    return {
        "blocked_usd":      blocked_usd,
        "escalated_usd":    escalated_usd,
        "lost_usd":         lost_usd,
        "blocked_count":    blocked_count,
        "escalated_count":  escalated_count,
        "unlabeled_count":  unlabeled_count,
    }


# ---------------------------------------------------------------------------
# Page: Dashboard
# ---------------------------------------------------------------------------

def page_dashboard() -> None:
    st.markdown("## 📊 Dashboard")

    records   = memory_store.all_records()
    proposals = proposal_store.load_pending()
    fin       = _financial_summary(records)

    # Row 1 — financial KPIs
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(_metric_card("💸 Blocked",         _fmt_usd(fin["blocked_usd"]),
                              f"{fin['blocked_count']} cases", "#ff4b4b"),
                unsafe_allow_html=True)
    c2.markdown(_metric_card("⚠️ In Review",        _fmt_usd(fin["escalated_usd"]),
                              f"{fin['escalated_count']} cases", "#ff8c00"),
                unsafe_allow_html=True)
    c3.markdown(_metric_card("💀 Confirmed Lost",   _fmt_usd(fin["lost_usd"]),
                              "false positives labeled", "#ff4b4b"),
                unsafe_allow_html=True)
    c4.markdown(_metric_card("📋 Needs Review",     str(fin["unlabeled_count"]),
                              "cases awaiting your label", "#4b8bff"),
                unsafe_allow_html=True)

    st.divider()

    # Where money is bleeding
    st.markdown("### 🔴 Where money is bleeding")

    findings = run_pattern_detection(time_window_hours=48, min_count=2, store=memory_store)
    findings_sorted = sorted(findings, key=lambda f: f.count, reverse=True)

    if not findings_sorted:
        st.success("✅ No active patterns in the last 48 hours.")
    else:
        cards_html = ""
        for f in findings_sorted:
            color_cls = "fm-card-red" if f.finding_type == "emerging_fraud" else "fm-card-amber"
            badge_color = "#ff4b4b" if f.finding_type == "emerging_fraud" else "#ff8c00"
            cards_html += (
                f'<div class="fm-card {color_cls}">'
                f'{_tag_pills(f.pattern_tags)}'
                f'<div style="margin-top:8px">'
                f'<strong style="color:#fff">{f.count} cases</strong>&nbsp;'
                f'<span class="badge" style="background:{badge_color}22;color:{badge_color};'
                f'border:1px solid {badge_color}55">{f.finding_type.replace("_"," ").upper()}</span>'
                f'</div>'
                f'<div style="margin-top:6px;color:#aaa;font-style:italic;font-size:0.9rem">'
                f'{f.suggestion}</div>'
                f'</div>'
            )
        st.markdown(cards_html, unsafe_allow_html=True)

    st.divider()

    # Sentinel confidence
    st.markdown("### 📊 Sentinel confidence")
    counter = collections.Counter(r.assessment for r in records)
    col_lc, col_fp, col_un = st.columns(3)
    col_lc.metric("✅ Likely Correct",    counter.get("likely_correct", 0))
    col_fp.metric("⚠️ Possible FP",       counter.get("possible_false_positive", 0))
    col_un.metric("❓ Uncertain",          counter.get("uncertain", 0))

    st.divider()

    # Pending proposals
    pending_count = len(proposals)
    st.markdown(
        f"### ⏳ Pending proposals\n\n"
        f"**{pending_count}** proposal{'s' if pending_count != 1 else ''} awaiting review. "
        f"Go to **Proposals** page to review."
    )


# ---------------------------------------------------------------------------
# Page: Investigations
# ---------------------------------------------------------------------------

def _render_case(record: InvestigationRecord, idx: int, total: int) -> None:
    entity = record.entity_id or record.case_id[:8]

    # TOP STRIP
    top_left, top_right = st.columns([5, 1])
    amt_color = "#ff4b4b" if record.arbiter_verdict == "block" else "#ff8c00"
    amt_html  = (
        f'&nbsp;&nbsp;<span style="font-size:1.3rem;font-weight:700;color:{amt_color}">'
        f'{_fmt_usd(record.amount_usd)}</span>'
        if record.amount_usd else ""
    )
    top_left.markdown(
        f'<span style="font-size:1.2rem;font-weight:700;color:#fff">{entity}</span>'
        f'&nbsp;&nbsp;{_verdict_badge(record.arbiter_verdict)}'
        f'&nbsp;&nbsp;{_assessment_badge(record.assessment)}'
        f'{amt_html}',
        unsafe_allow_html=True,
    )
    with top_right:
        pcol, ncol = st.columns(2)
        if pcol.button("← Prev", key=f"prev_{idx}", disabled=(idx == 0)):
            st.session_state["case_index"] = idx - 1
            st.rerun()
        if ncol.button("Next →", key=f"next_{idx}", disabled=(idx == total - 1)):
            st.session_state["case_index"] = idx + 1
            st.rerun()

    st.caption(
        f"Trigger: {record.trigger_reason or '—'}  ·  "
        f"Created: {record.created_at[:10] if record.created_at else '—'}  ·  "
        f"Case {idx + 1} of {total}"
    )

    # Narrative
    st.markdown(
        f'<div class="narrative-box">💬 {record.investigation_narrative}</div>',
        unsafe_allow_html=True,
    )

    # Pattern tags
    st.markdown(_tag_pills(record.pattern_tags), unsafe_allow_html=True)
    st.divider()

    # Domain scores
    st.markdown("**Risk Breakdown**")
    score_left, score_right = st.columns([3, 1])
    rv = record.risk_vector
    with score_left:
        for domain in rv.available_domains:
            score = rv.scores[domain]
            st.markdown(
                f'<span style="font-family:monospace;color:#aaa">{domain:<10}</span>'
                f'<strong style="color:#fff"> {score:.2f}</strong>'
                + _score_bar(score),
                unsafe_allow_html=True,
            )
    with score_right:
        agg = rv.aggregate
        agg_color = "#ff4b4b" if agg > 0.70 else "#ff8c00" if agg > 0.35 else "#00c853"
        st.markdown(
            f'<div style="text-align:center">'
            f'<div style="font-size:2.5rem;font-weight:800;color:{agg_color}">{agg:.2f}</div>'
            f'<div style="color:#888;font-size:0.8rem;text-transform:uppercase">Aggregate Risk</div>'
            f'<div style="margin-top:8px;color:#aaa;font-size:0.85rem">'
            f'dominant: <strong>{rv.dominant_domain}</strong><br>'
            f'specialists: {rv.specialists_run}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # Enrichment
    if record.enriched_signals:
        st.markdown("**📊 Entity Signals**")
        signal_items = list(record.enriched_signals.items())
        cols = st.columns(min(len(signal_items), 5))
        for i, (k, v) in enumerate(signal_items):
            col = cols[i % len(cols)]
            is_anomaly = (
                (k == "account_age_days"      and isinstance(v, (int, float)) and v < 30) or
                (k == "prior_chargebacks"     and isinstance(v, (int, float)) and v > 0) or
                (k == "device_reuse_count"    and isinstance(v, (int, float)) and v > 3) or
                (k == "linked_entities_count" and isinstance(v, (int, float)) and v > 2)
            )
            display_v = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v)
            val_html = (
                f'<span class="anomaly">{display_v}</span>' if is_anomaly
                else f'<span style="color:#ddd">{display_v}</span>'
            )
            col.markdown(
                f'<div style="font-size:0.72rem;color:#888;text-transform:uppercase">{k}</div>'
                + val_html,
                unsafe_allow_html=True,
            )
        st.divider()

    # Analyst action
    st.markdown("**⚖️ Your Verdict**")
    if record.analyst_verdict:
        msg = {
            "confirm_fraud":   ("🚨 Confirmed Fraud", "error"),
            "false_positive":  ("✅ False Positive — case cleared", "success"),
            "uncertain":       ("🤔 Marked Uncertain", "warning"),
        }.get(record.analyst_verdict, (record.analyst_verdict, "info"))
        getattr(st, msg[1])(msg[0])
    else:
        b1, b2, b3 = st.columns([1, 1, 1])
        if b1.button("✅ Confirm Fraud",  key=f"cf_{record.case_id}",  use_container_width=True, type="primary"):
            memory_store.update_analyst_verdict(record.case_id, "confirm_fraud")
            st.session_state["case_index"] = min(idx + 1, total - 1)
            st.rerun()
        if b2.button("❌ False Positive", key=f"fp_{record.case_id}",  use_container_width=True):
            memory_store.update_analyst_verdict(record.case_id, "false_positive")
            st.session_state["case_index"] = min(idx + 1, total - 1)
            st.rerun()
        if b3.button("⏭ Skip",            key=f"sk_{record.case_id}",  use_container_width=True):
            st.session_state["case_index"] = min(idx + 1, total - 1)
            st.rerun()

    # Tool trace
    if record.tool_trace:
        with st.expander("🔍 Sentinel investigation trace", expanded=False):
            for step in record.tool_trace:
                st.markdown(
                    f'`{step["call_order"]}.` **`{step["tool_name"]}`** — {step.get("result_summary", "")}'
                )


def page_investigations() -> None:
    st.markdown("## 🔎 Investigations")

    records = list(reversed(memory_store.all_records()))
    if not records:
        st.info("No investigation records yet.")
        return

    if "case_index" not in st.session_state:
        st.session_state["case_index"] = 0
    st.session_state["case_index"] = max(0, min(st.session_state["case_index"], len(records) - 1))
    active_idx = st.session_state["case_index"]

    left_col, right_col = st.columns([1, 3])

    with left_col:
        st.markdown("**🗂 Queue**")
        for i, r in enumerate(records):
            entity  = (r.entity_id or r.case_id[:8])[:12]
            tag_str = r.pattern_tags[0] if r.pattern_tags else "—"
            amt_str = f"  {_fmt_usd(r.amount_usd)}" if r.amount_usd else ""
            icon    = {"block": "🔴", "escalate": "🟡", "allow": "🟢"}.get(r.arbiter_verdict, "⚪")
            line    = f"{icon} {entity}  {tag_str}{amt_str}"

            if i == active_idx:
                st.markdown(
                    f'<div class="fm-card queue-item queue-item-active" style="font-size:0.85rem">{line}</div>',
                    unsafe_allow_html=True,
                )
            else:
                if st.button(line, key=f"q_{i}", use_container_width=True):
                    st.session_state["case_index"] = i
                    st.rerun()

    with right_col:
        _render_case(records[active_idx], active_idx, len(records))


# ---------------------------------------------------------------------------
# Page: Proposals
# ---------------------------------------------------------------------------

def _render_proposed_change(proposal) -> None:
    rt = proposal.rule_type
    pc = proposal.proposed_change
    if rt == "weight_adjustment":
        field    = pc.get("field", "?")
        cur      = pc.get("current_value", "?")
        proposed = pc.get("proposed_value", "?")
        st.markdown(
            f'<span style="font-family:monospace;color:#aaa">{field}</span>'
            f'&nbsp;&nbsp;<span style="color:#888">{cur}</span>'
            f'&nbsp;→&nbsp;<strong style="color:#ff8c00">{proposed}</strong>',
            unsafe_allow_html=True,
        )
        st.caption(pc.get("rationale", ""))
    elif rt == "hard_rule":
        st.code(pc.get("condition", ""), language="python")
        st.markdown(_verdict_badge(pc.get("verdict", "block")), unsafe_allow_html=True)
        st.caption(pc.get("rationale", ""))
    else:  # sentinel_filter
        st.markdown(
            f'`{pc.get("action","?")}` on `{pc.get("target","?")}`'
        )
        st.caption(pc.get("rationale", ""))


def page_proposals() -> None:
    st.markdown("## 📐 Rule Proposals")
    st.caption("System-generated rule changes. Approve to queue for deployment, reject to dismiss.")

    pending = proposal_store.load_pending()
    records = memory_store.all_records()

    if not pending:
        st.markdown(
            '<div class="fm-card fm-card-green">✅ No pending proposals. Queue is clear.</div>',
            unsafe_allow_html=True,
        )
        return

    for proposal in pending:
        color_cls = {
            "hard_rule":         "fm-card-red",
            "weight_adjustment": "fm-card-amber",
            "sentinel_filter":   "fm-card-blue",
        }.get(proposal.rule_type, "fm-card-blue")

        # FP rate from labeled records matching proposal tags
        tag_set = set(proposal.pattern_tags)
        labeled = [r for r in records
                   if tag_set & set(r.pattern_tags) and r.analyst_verdict is not None]
        fp_rate_html = ""
        if labeled:
            fp_n  = sum(1 for r in labeled if r.analyst_verdict == "false_positive")
            fp_pct = fp_n / len(labeled) * 100
            fp_color = "#00c853" if fp_pct < 5 else "#ff8c00" if fp_pct < 15 else "#ff4b4b"
            fp_rate_html = (
                f'<div style="margin-top:6px;font-size:0.85rem">'
                f'<span style="color:{fp_color};font-weight:600">{fp_pct:.0f}% FP rate</span>'
                f' across {len(labeled)} labeled cases</div>'
            )

        rt_label = {
            "hard_rule":         "Hard Rule",
            "weight_adjustment": "Weight Adjustment",
            "sentinel_filter":   "Sentinel Filter",
        }.get(proposal.rule_type, proposal.rule_type)

        st.markdown(
            f'<div class="fm-card {color_cls}">'
            f'<strong style="font-size:1.05rem;color:#fff">{proposal.rule_name}</strong>'
            f'&nbsp;&nbsp;<span style="font-size:0.78rem;color:#aaa;text-transform:uppercase">'
            f'{rt_label}</span>'
            f'<div style="margin-top:6px;color:#ccc">{proposal.description}</div>'
            f'<div style="margin-top:8px">{_tag_pills(proposal.pattern_tags)}</div>'
            f'<div style="margin-top:4px;font-size:0.82rem;color:#888">'
            f'Based on {proposal.pattern_count} cases</div>'
            f'{fp_rate_html}'
            f'</div>',
            unsafe_allow_html=True,
        )

        with st.expander("See proposed change", expanded=False):
            _render_proposed_change(proposal)
            imp_col, risk_col = st.columns(2)
            imp_col.markdown(f"**📈 Expected impact**\n\n{proposal.expected_impact}")
            risk_col.markdown(f"**⚠️ Risk**\n\n{proposal.risk}")

        rt_key = f"rt_report_{proposal.proposal_id}"
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
                st.session_state[rt_key] = red_team_rule(proposal)

        if rt_key in st.session_state:
            report = st.session_state[rt_key]
            icon   = {"approve": "🟢", "revise": "🟡", "reject": "🔴"}.get(report.recommendation, "⚪")
            st.markdown(
                f"**{icon} Red Team: {report.recommendation.upper()}** — "
                f"{report.recommendation_reasoning}  \n"
                f"`{report.attempts_bypassed_rule}/{report.attempts_total}` bypass rule · "
                f"`{report.attempts_bypassed_system}/{report.attempts_total}` bypass system"
            )
            with st.expander("Bypass scenarios", expanded=False):
                for i, s in enumerate(report.scenarios, 1):
                    fired = "✅ rule fired" if s.rule_fired else f"❌ evaded → caught by: {s.caught_by or 'none'}"
                    st.markdown(f"**{i}. {s.description}**  \n`{fired}` · system verdict: `{s.system_verdict}`")
                    st.json(s.signal_overrides)

            if report.recommendation in ("revise", "reject"):
                if st.button("🔄 Generate Revised Rule", key=f"revise_{proposal.proposal_id}"):
                    with st.spinner("Rule Proposer revising based on red team findings…"):
                        revised = revise_rule(proposal, report)
                        proposal_store.save(revised)
                    st.success(f"Revised proposal **{revised.rule_name}** added to queue.")
                    del st.session_state[rt_key]
                    st.rerun()

        if col_reject.button("❌ Reject", key=f"reject_{proposal.proposal_id}",
                             use_container_width=True):
            proposal_store.update_status(proposal.proposal_id, "rejected")
            st.rerun()

        st.divider()


# ---------------------------------------------------------------------------
# Page: Patterns
# ---------------------------------------------------------------------------

def page_patterns() -> None:
    st.markdown("## 🔎 Pattern Intelligence")

    findings = run_pattern_detection(time_window_hours=48, min_count=2, store=memory_store)

    if not findings:
        st.success("No patterns detected.")
        return

    max_count = max(f.count for f in findings) or 1

    # Group by finding_type
    groups: dict[str, list] = {}
    for f in findings:
        groups.setdefault(f.finding_type, []).append(f)

    color_map = {
        "emerging_fraud":        "fm-card-red",
        "false_positive_cluster": "fm-card-green",
        "novel_behavior":        "fm-card-amber",
    }

    for finding_type, group_findings in groups.items():
        st.subheader(finding_type.replace("_", " ").title())
        for f in sorted(group_findings, key=lambda x: x.count, reverse=True):
            cls = color_map.get(finding_type, "fm-card-blue")

            # Assessment distribution text
            if f.assessment_distribution:
                dist_str = ", ".join(
                    f'{cnt} {a}' for a, cnt in f.assessment_distribution.items()
                )
            else:
                dist_str = ""

            st.markdown(
                f'<div class="fm-card {cls}">'
                f'{_tag_pills(f.pattern_tags)}'
                f'<div style="margin-top:8px">'
                f'<span style="font-size:1.4rem;font-weight:700;color:#fff">{f.count}</span>'
                f'<span style="color:#888;font-size:0.8rem"> cases</span>'
                f'</div>'
                f'<div style="margin:6px 0;font-style:italic;color:#aaa;font-size:0.9rem">'
                f'{f.suggestion}</div>'
                + (f'<div style="font-size:0.78rem;color:#666">{dist_str}</div>' if dist_str else "")
                + f'</div>',
                unsafe_allow_html=True,
            )
            st.progress(f.count / max_count)


# ---------------------------------------------------------------------------
# Sidebar & navigation
# ---------------------------------------------------------------------------

PAGES = {
    "Dashboard":      page_dashboard,
    "Investigations": page_investigations,
    "Proposals":      page_proposals,
    "Patterns":       page_patterns,
}

if "page" not in st.session_state:
    st.session_state["page"] = "Dashboard"

st.sidebar.markdown("# 🛡️ FraudMind")
st.sidebar.markdown("**Analyst Copilot**")
st.sidebar.divider()

for name in PAGES:
    is_active = st.session_state["page"] == name
    if st.sidebar.button(
        name,
        key=f"nav_{name}",
        use_container_width=True,
        type="primary" if is_active else "secondary",
    ):
        st.session_state["page"] = name
        st.rerun()

st.sidebar.divider()
_all_records = memory_store.all_records()
_pending_count = len(proposal_store.load_pending())
st.sidebar.caption(f"{len(_all_records)} investigation records")
st.sidebar.caption(f"{_pending_count} proposals pending")

# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

PAGES[st.session_state["page"]]()
