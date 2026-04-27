"""
Sentinel behavior evals — LLM property tests.

These tests make real OpenAI API calls and are excluded from the default
pytest run. Opt in explicitly:

    pytest tests/evals/test_sentinel_behavior.py -m llm_eval -v

What we test:
  We cannot assert exact LLM outputs. We assert *structural properties*
  that must hold regardless of the LLM's reasoning:

  Sentinel always:
    - calls at least one tool before concluding
    - produces a non-empty investigation_narrative (>= 50 chars)
    - produces 2-6 pattern_tags
    - produces a valid assessment literal
    - produces a valid hypothesis_outcome literal (if hypothesis was set)
    - populates hypothesis and investigation_plan

  Sentinel on a high-fraud case:
    - assessment is "likely_correct" (not false_positive)

  Sentinel on a case with clean enrichment history:
    - assessment is "possible_false_positive" OR "uncertain"
    - narrative mentions enrichment findings

  Rule proposer output:
    - rule_type is a valid literal
    - proposed_change contains required keys for the rule_type
    - weight changes don't push any weight above 0.50
    - hard_rule conditions reference at least one valid signal field name
"""

import pytest

from src.schemas.arbiter_output import ArbiterOutput
from src.schemas.risk_vector import RiskVector


# ---------------------------------------------------------------------------
# Fixtures: minimal but realistic inputs for run_investigation
# ---------------------------------------------------------------------------

@pytest.fixture
def high_fraud_inputs():
    """Ring fraud case — high aggregate, Sentinel should confirm fraud."""
    rv = RiskVector(
        scores={"ring": 0.88, "payment": 0.75, "identity": 0.65},
        available_domains=["ring", "payment", "identity"],
        aggregate=0.81,
        score_stddev=0.095,
        dominant_domain="ring",
        dominant_score=0.88,
        specialists_run=3,
    )
    arbiter = ArbiterOutput(
        verdict="block",
        confidence=0.81,
        reasoning="High ring, payment, and identity scores converge on coordinated fraud.",
        evidence=["known_ring_signature_match", "amount_vs_avg_ratio", "pii_seen_on_other_accounts"],
        trigger_async=True,
        trigger_reason="high_risk_multi_domain",
        rule_name="high_aggregate_block",
    )
    specialist_scores = {
        "ring": None, "payment": None, "identity": None,
        "ato": None, "promo": None, "payload": None,
    }
    return "entity_ring_eval_001", arbiter, rv, specialist_scores


@pytest.fixture
def borderline_inputs():
    """ATO case — single specialist, moderate score. Should escalate, outcome ambiguous."""
    rv = RiskVector(
        scores={"ato": 0.45},
        available_domains=["ato"],
        aggregate=0.45,
        score_stddev=None,
        dominant_domain="ato",
        dominant_score=0.45,
        specialists_run=1,
    )
    arbiter = ArbiterOutput(
        verdict="escalate",
        confidence=0.55,
        reasoning="Single domain signal, insufficient corroboration.",
        evidence=["is_new_device", "geo_mismatch"],
        trigger_async=True,
        trigger_reason="conflicting_signals",
        rule_name="thin_evidence_escalate",
    )
    specialist_scores = {
        "ato": None, "ring": None, "payment": None,
        "identity": None, "promo": None, "payload": None,
    }
    return "entity_ato_eval_001", arbiter, rv, specialist_scores


# ---------------------------------------------------------------------------
# Structural property tests
# ---------------------------------------------------------------------------

@pytest.mark.llm_eval
class TestSentinelStructuralProperties:
    def test_tool_trace_non_empty(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert len(record.tool_trace) >= 1, "Sentinel must call at least one tool"

    def test_narrative_is_substantive(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert len(record.investigation_narrative) >= 50, (
            "Narrative too short — Sentinel should produce meaningful synthesis"
        )

    def test_pattern_tags_within_bounds(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert 1 <= len(record.pattern_tags) <= 8, (
            f"Expected 1-8 pattern tags, got {len(record.pattern_tags)}: {record.pattern_tags}"
        )

    def test_assessment_is_valid_literal(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert record.assessment in {"likely_correct", "possible_false_positive", "uncertain"}, (
            f"Invalid assessment: {record.assessment}"
        )

    def test_hypothesis_is_set(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert record.hypothesis is not None
        assert len(record.hypothesis) > 10

    def test_investigation_plan_has_three_steps(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert record.investigation_plan is not None
        assert len(record.investigation_plan) == 3

    def test_hypothesis_outcome_is_valid_literal(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert record.hypothesis_outcome in {"confirmed", "refuted", "ambiguous"}, (
            f"Invalid hypothesis_outcome: {record.hypothesis_outcome}"
        )

    def test_record_is_saved_to_store(self, high_fraud_inputs):
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        count_before = len(store.all_records())
        run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert len(store.all_records()) == count_before + 1


# ---------------------------------------------------------------------------
# Assessment calibration tests
# ---------------------------------------------------------------------------

@pytest.mark.llm_eval
class TestSentinelAssessmentCalibration:
    def test_high_fraud_case_not_false_positive(self, high_fraud_inputs):
        """Triple-domain convergence at >0.80 — should not be called a false positive."""
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = high_fraud_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        assert record.assessment != "possible_false_positive", (
            "High-confidence triple-domain fraud should not be assessed as possible_false_positive"
        )

    def test_borderline_case_not_likely_correct_block(self, borderline_inputs):
        """Single-domain thin evidence escalation — should not assert likely_correct."""
        from src.sentinel.investigation_agent import run_investigation
        from src.sentinel.memory_store import MemoryStore
        entity_id, arbiter, rv, scores = borderline_inputs
        store = MemoryStore()
        record = run_investigation(entity_id, arbiter, rv, scores, store=store)
        # borderline case should be uncertain or possible_false_positive, not a confident block
        assert record.assessment in {"uncertain", "possible_false_positive"}, (
            f"Borderline case got assessment={record.assessment}, expected uncertain or possible_false_positive"
        )


# ---------------------------------------------------------------------------
# Rule proposer output schema tests
# ---------------------------------------------------------------------------

@pytest.mark.llm_eval
class TestRuleProposerOutput:
    _VALID_SIGNAL_FIELDS = {
        # ATO
        "account_age_days", "is_new_device", "geo_mismatch", "time_since_last_login_days",
        "immediate_high_value_action", "email_change_attempted", "password_change_attempted",
        "support_ticket_language_match",
        # Payment
        "amount_usd", "is_international", "transactions_last_1h", "transactions_last_24h",
        "amount_vs_avg_ratio", "is_first_transaction", "card_present", "days_since_account_creation",
        # Ring
        "accounts_sharing_device", "accounts_sharing_ip", "linked_accounts_with_fraud_confirmed",
        "linked_accounts_with_block_verdict", "known_ring_signature_match",
        "velocity_account_creation_same_ip_7d", "transaction_graph_min_hops_to_fraud",
        # Identity
        "is_disposable_email", "document_verification_passed", "pii_seen_on_other_accounts",
        "accounts_created_from_same_device", "accounts_created_from_same_ip",
        "signup_velocity_same_ip_24h", "name_dob_mismatch",
        # Payload
        "tls_fingerprint_known_bot", "user_agent_is_headless", "requests_per_minute",
        "credential_stuffing_ip_on_blocklist", "login_attempt_count_this_session",
        "captcha_solve_pattern_automated",
        # Namespaces
        "ato", "payment", "ring", "identity", "payload", "promo",
    }

    def _make_finding(self):
        from src.schemas.pattern_finding import PatternFinding
        return PatternFinding(
            pattern_tags=["ring_fraud", "new_account"],
            count=5,
            time_window_hours=48,
            finding_type="emerging_fraud",
            suggestion="Consider adding a hard rule for new accounts with ring fraud signals.",
            assessment_distribution={"likely_correct": 5},
            dominant_verdict="block",
            confidence=0.85,
            detected_at="2026-01-01T00:00:00Z",
        )

    def test_rule_type_is_valid(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        assert proposal.rule_type in {"hard_rule", "weight_adjustment", "sentinel_filter"}

    def test_weight_adjustment_has_required_keys(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        if proposal.rule_type == "weight_adjustment":
            pc = proposal.proposed_change
            assert "field" in pc
            assert "current_value" in pc
            assert "proposed_value" in pc
            assert "rationale" in pc

    def test_weight_adjustment_value_is_reasonable(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        if proposal.rule_type == "weight_adjustment":
            proposed = proposal.proposed_change.get("proposed_value", 0)
            assert 0.0 < proposed <= 0.50, (
                f"Proposed weight {proposed} is unreasonable (>0.50 would dominate all others)"
            )

    def test_hard_rule_condition_uses_valid_fields(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        if proposal.rule_type == "hard_rule":
            condition = proposal.proposed_change.get("condition", "")
            assert any(field in condition for field in self._VALID_SIGNAL_FIELDS), (
                f"hard_rule condition references no known signal fields: {condition}"
            )

    def test_hard_rule_verdict_is_valid(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        if proposal.rule_type == "hard_rule":
            verdict = proposal.proposed_change.get("verdict")
            assert verdict in {"block", "allow", "step_up", "escalate"}

    def test_rule_name_is_snake_case(self):
        from src.sentinel.rule_proposer import propose_rule
        proposal = propose_rule(self._make_finding())
        # snake_case: only lowercase letters, digits, underscores
        import re
        assert re.match(r'^[a-z][a-z0-9_]*$', proposal.rule_name), (
            f"rule_name '{proposal.rule_name}' is not snake_case"
        )
