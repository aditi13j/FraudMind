Milestone 7C — Analyst Copilot: financial focus, color, and actionable UI.

Files to change:
  src/schemas/investigation_record.py
  src/sentinel/memory_store.py
  src/analyst_copilot/app.py
  requirements.txt

Do not touch any other files.

## Step 1 — Add amount_usd to InvestigationRecord

File: src/schemas/investigation_record.py

Add this field after arbiter_confidence:

    amount_usd: Optional[float] = Field(
        default=None,
        description="Transaction amount in USD associated with this case. Used for financial impact metrics.",
    )

## Step 2 — Add update_analyst_verdict to MemoryStore

File: src/sentinel/memory_store.py

Add this method to MemoryStore:

    def update_analyst_verdict(self, case_id: str, verdict: str) -> None:
        records = self._load_all()
        for r in records:
            if r.get("case_id") == case_id:
                r["analyst_verdict"] = verdict
                break
        self._path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
        )

## Step 3 — Rewrite app.py completely

File: src/analyst_copilot/app.py

### App config

Call st.set_page_config at the top:
    st.set_page_config(
        page_title="FraudMind Analyst Copilot",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

### CSS injection

Immediately after set_page_config, inject this CSS block via
st.markdown(..., unsafe_allow_html=True):

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

### Helper functions

_verdict_badge(verdict: str) -> str
    Returns an HTML span with class badge-red for "block",
    badge-amber for "escalate" and "step_up",
    badge-green for "allow".
    Text is the verdict in uppercase.

_assessment_badge(assessment: str) -> str
    Returns an HTML span with class badge-red for "likely_correct",
    badge-blue for "possible_false_positive",
    badge-amber for "uncertain".

_tag_pills(tags: list[str]) -> str
    Returns HTML span elements.
    Tags ending in "_fraud" get class tag-pill-fraud.
    "bot_session" and "credential_stuffing" get class tag-pill-bot.
    All others get class tag-pill.

_score_bar(score: float) -> str
    Returns HTML div with class score-bar-track containing a div
    with width="{score*100:.0f}%".
    Fill class: score-bar-fill-red if score > 0.70,
                score-bar-fill-amber if score > 0.35,
                score-bar-fill-green otherwise.

_fmt_usd(amount: float | None) -> str
    Returns "$0" if None.
    Returns "$1,234" formatted with commas, no decimals.

_metric_card(label: str, value: str, sub: str, color: str) -> str
    Returns HTML div with class "fm-metric" and a left border
    in the given color (#ff4b4b, #ff8c00, #00c853, #4b8bff).
    Contains metric-value, metric-label, metric-sub divs.

### Financial computation helper

_financial_summary(records: list[InvestigationRecord]) -> dict
    Returns a dict with these keys:
        blocked_usd:   sum of amount_usd where arbiter_verdict == "block"  (or 0)
        escalated_usd: sum of amount_usd where arbiter_verdict == "escalate" (or 0)
        lost_usd:      sum of amount_usd where analyst_verdict == "false_positive" (or 0)
        blocked_count: count of block verdicts
        escalated_count: count of escalate verdicts
        unlabeled_count: count where analyst_verdict is None
    Use 0 when amount_usd is None.

### Page: Dashboard

Function: page_dashboard()

Load all records from memory_store. Load all proposals from proposal_store.

Compute financial summary using _financial_summary(records).

Row 1 — four financial metric cards using st.columns(4).
Render each as st.markdown(_metric_card(...), unsafe_allow_html=True):
  Col 1: label="💸 Blocked",  value=_fmt_usd(blocked_usd),
         sub=f"{blocked_count} cases", color="#ff4b4b"
  Col 2: label="⚠️ In Review", value=_fmt_usd(escalated_usd),
         sub=f"{escalated_count} cases", color="#ff8c00"
  Col 3: label="💀 Confirmed Lost", value=_fmt_usd(lost_usd),
         sub="false positives labeled", color="#ff4b4b"
  Col 4: label="📋 Needs Review", value=str(unlabeled_count),
         sub="cases awaiting your label", color="#4b8bff"

st.divider()

Section: "🔴 Where money is bleeding"
  Run run_pattern_detection(time_window_hours=48, min_count=2, store=memory_store).
  Sort findings by count descending.
  If no findings: st.success("✅ No active patterns in the last 48 hours.")
  For each finding render an fm-card with class fm-card-red or fm-card-amber
  based on finding_type ("emerging_fraud" = red, else amber):
    - Pattern tags rendered as _tag_pills()
    - Bold count + finding_type badge
    - suggestion text from the finding in italic
  Render all cards via st.markdown(..., unsafe_allow_html=True)

st.divider()

Section: "📊 Sentinel confidence"
  Use collections.Counter on record.assessment.
  Show three columns (one per assessment value) each with an st.metric:
    likely_correct → label "✅ Likely Correct", color green
    possible_false_positive → label "⚠️ Possible FP", color amber
    uncertain → label "❓ Uncertain", color blue

Section: "⏳ Pending proposals"
  Show pending count as a large bold number with a link-style note:
  "Go to Proposals page to review."

### Page: Investigations

Function: page_investigations()

Load all records reversed (most recent first).

If empty: st.info("No investigation records yet.").

Session state key: "case_index" defaulting to 0.
Clamp to valid range after loading.

Layout: st.columns([1, 3]).

LEFT COLUMN — queue rail:
  st.markdown("**🗂 Queue**")
  For each record (index i):
    Build a short line: verdict icon + case_id[:8] + first tag + amount if present.
    If i == active index: render as fm-card with class queue-item queue-item-active,
      no button.
    Else: st.button with the line as label, key=f"q_{i}",
      on click set case_index=i and rerun.

RIGHT COLUMN — case detail via _render_case(record, idx, total):

  TOP STRIP (two columns [5, 1]):
    Left: entity_id or case_id[:8], verdict badge, assessment badge,
          amount_usd if present in a large bold green or red span,
          all rendered as st.markdown(..., unsafe_allow_html=True).
    Right: Prev ← and Next → buttons. On click update case_index and rerun.

  st.caption with trigger_reason and created_at date.

  NARRATIVE:
    st.markdown with class narrative-box:
    "💬 " + investigation_narrative
    Render via unsafe_allow_html=True.

  PATTERN TAGS:
    st.markdown(_tag_pills(record.pattern_tags), unsafe_allow_html=True)

  st.divider()

  DOMAIN SCORES — "Risk Breakdown" header:
    Two columns.
    Left column: for each domain in risk_vector.available_domains:
      One line: domain name (monospace, 10 chars wide) + score to 2dp
      _score_bar(score) rendered via unsafe_allow_html=True
    Right column: aggregate score as a large number, color red if > 0.70,
      amber if > 0.35, green otherwise. Label "Aggregate Risk".
      Below it: dominant_domain and specialists_run.

  st.divider()

  ENRICHMENT — "📊 Entity Signals" header:
    Only if enriched_signals is non-empty.
    Render as st.columns (one per signal).
    Anomaly rules (show value in red using HTML span class="anomaly"):
      account_age_days < 30
      prior_chargebacks > 0
      device_reuse_count > 3
      linked_entities_count > 2
    Format prior_step_up_results as a comma-joined string.
    All values rendered via st.markdown unsafe_allow_html=True.

  st.divider()

  ANALYST ACTION — "⚖️ Your Verdict" header:
    If analyst_verdict already set:
      Show a colored success/warning/info box depending on value.
    Else:
      Three full-width styled buttons using st.columns([1,1,1]):
        "✅ Confirm Fraud"  → update_analyst_verdict, advance, rerun
        "❌ False Positive" → update_analyst_verdict, advance, rerun
        "⏭ Skip"           → advance, rerun

  TOOL TRACE:
    st.expander("🔍 Sentinel investigation trace", expanded=False)
    For each step: call_order, tool_name in bold monospace, result_summary.

### Page: Proposals

Function: page_proposals()

Load pending proposals.

If empty:
  st.markdown with a green fm-card: "✅ No pending proposals. Queue is clear."

For each proposal render an fm-card with color matching rule_type:
  hard_rule         → fm-card-red
  weight_adjustment → fm-card-amber
  sentinel_filter   → fm-card-blue

Inside each card (use st.markdown + unsafe_allow_html=True for the card shell,
then st.markdown/st.code/st.columns normally for the interior):

  Header line: rule_name in bold + rule_type badge + pattern_count cases

  Based on N cases matching these tags: _tag_pills(proposal.pattern_tags)

  "What changes" section:
    weight_adjustment:
      Large text: field + " → " with current_value in grey and proposed_value
      in color. Example: DOMAIN_WEIGHTS.ring  0.30 → 0.38
      st.caption with rationale
    hard_rule:
      st.code(condition, language="python")
      verdict badge
      st.caption with rationale
    sentinel_filter:
      action and target as monospace text
      st.caption with rationale

  Two columns for impact and risk:
    Left: "📈 Expected impact" + expected_impact text
    Right: "⚠️ Risk" + risk text

  Historical FP rate (if matching labeled records exist):
    Compute from memory_store.all_records() as described in Step 4 of previous CLAUDE.md.
    Show as a colored metric: green if < 5%, amber if < 15%, red if >= 15%.

  Action buttons in two columns:
    "✅ Approve" → proposal_store.update_status(id, "approved"), rerun
    "❌ Reject"  → show st.text_input for optional reason, then update_status, rerun

### Page: Patterns

Function: page_patterns()

Header: "🔎 Pattern Intelligence"

Run pattern detection (48h window, min_count=2).

If empty: st.success("No patterns detected.")

Max count for bar scaling.

Group findings by finding_type.
For each group:
  Subheader with finding_type formatted as title case.
  For each finding in group sorted by count desc:
    Render an fm-card with appropriate color.
    Inside:
      _tag_pills(finding.pattern_tags)
      Count as large bold number + small "cases" label
      st.progress(finding.count / max_count) for relative volume
      suggestion text in italic grey
      assessment_distribution as small text (e.g. "8 likely_correct, 2 uncertain")

### Sidebar

Replace the current st.sidebar.radio with styled navigation.

At the top of the sidebar:
  st.sidebar.markdown("# 🛡️ FraudMind")
  st.sidebar.markdown("**Analyst Copilot**")
  st.sidebar.divider()

Navigation buttons (not radio):
  For each page name, render st.sidebar.button.
  Highlight the active page using session_state["page"].
  Default page: "Dashboard".

At the bottom of the sidebar:
  st.sidebar.divider()
  Count of records and pending proposals as small caption text.

### Navigation wiring

Use st.session_state["page"] to track current page.
Map page names to functions:
  "Dashboard":      page_dashboard
  "Investigations": page_investigations
  "Proposals":      page_proposals
  "Patterns":       page_patterns

Call PAGES[st.session_state["page"]]() at the bottom.

## Step 4 — Add streamlit to requirements.txt

Add:
  streamlit>=1.35.0

## Do not change
- Any specialist agents
- Any sentinel files except memory_store.py
- Any schema files except investigation_record.py
- fraud_graph.py, arbiter.py, scoring_config.py
- pattern_detection.py, rule_proposer.py
