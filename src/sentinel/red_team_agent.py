"""
Red Team Agent -- P1-4

Stress-tests an approved RuleProposal by generating adversarial signal
combinations and running them through the pipeline.

For hard_rule proposals:
    Generates N scenarios where the rule's condition is just barely False
    (minimum perturbation to evade). Checks whether the full pipeline still
    catches the case via other rules or scoring.

For weight_adjustment proposals:
    Generates cases that sit in the boundary zone around the new threshold
    to identify potential over-blocking or under-blocking.

For sentinel_filter proposals:
    Generates cases that test whether the filter suppresses valid triggers.

report = red_team_rule(proposal)
  → report.bypass_rate          — fraction of scenarios that evade the rule
  → report.attempts_bypassed_system  — how many also slip through the full system
  → report.recommendation       — "approve" | "revise" | "reject"
"""

import ast
import json
import os
from datetime import datetime, timezone
from typing import Optional

from dotenv import load_dotenv
from openai import OpenAI

from src.graph.fraud_graph import fraud_graph
from src.rules.hard_rules import hard_rules_check
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.red_team_report import BypassScenario, RedTeamReport
from src.schemas.ring_schemas import RingSignals
from src.schemas.rule_proposal import RuleProposal

load_dotenv()

# ---------------------------------------------------------------------------
# Adversarial scenario generation prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a fraud ring operator trying to evade a new fraud detection rule.
You will be given a rule condition or change, plus the available signal fields.
Generate {n} adversarial scenarios: each is a realistic fraudster who tries to
look legitimate by setting signals to values that avoid triggering the rule,
while still committing fraud.

For each scenario output:
  - description: one sentence explaining the evasion strategy
  - signal_overrides: a flat dict of ONLY the signal fields you want to change
    from their fraudulent defaults. Use the exact field names listed.
    Values must be valid Python literals (bool, int, float, str).

Output a JSON array of {n} objects, each with "description" and "signal_overrides".
No other keys. No markdown.

Available signal fields:
  ato:      account_age_days(int), is_new_device(bool), geo_mismatch(bool),
            time_since_last_login_days(int), immediate_high_value_action(bool),
            email_change_attempted(bool), password_change_attempted(bool)
  payment:  amount_usd(float), is_international(bool), transactions_last_1h(int),
            transactions_last_24h(int), amount_vs_avg_ratio(float),
            is_first_transaction(bool), card_present(bool),
            days_since_account_creation(int)
  ring:     accounts_sharing_device(int), accounts_sharing_ip(int),
            linked_accounts_with_fraud_confirmed(int),
            linked_accounts_with_block_verdict(int),
            known_ring_signature_match(bool),
            velocity_account_creation_same_ip_7d(int),
            transaction_graph_min_hops_to_fraud(int)
  identity: is_disposable_email(bool), document_verification_passed(bool),
            pii_seen_on_other_accounts(int), accounts_created_from_same_device(int),
            accounts_created_from_same_ip(int), signup_velocity_same_ip_24h(int),
            name_dob_mismatch(bool)
  payload:  tls_fingerprint_known_bot(bool), user_agent_is_headless(bool),
            requests_per_minute(float), credential_stuffing_ip_on_blocklist(bool),
            login_attempt_count_this_session(int),
            captcha_solve_pattern_automated(bool)\
"""

# ---------------------------------------------------------------------------
# Base fraudster signal profile
# (moderately fraudulent — suspicious but not immediately obvious)
# ---------------------------------------------------------------------------

_BASE_ATO = dict(
    account_id="rt_test", account_age_days=45,
    is_new_device=True, device_id="dev_rt",
    login_geo="Lagos, NG", account_home_geo="New York, US",
    geo_mismatch=True, time_since_last_login_days=30,
    immediate_high_value_action=True, email_change_attempted=False,
    password_change_attempted=False, support_ticket_language_match=False,
)

_BASE_PAYMENT = dict(
    transaction_id="txn_rt", account_id="rt_test",
    amount_usd=800.0, merchant_category="electronics",
    merchant_country="US", account_home_country="US",
    is_international=False, transactions_last_1h=3, transactions_last_24h=6,
    avg_transaction_amount_30d=80.0, amount_vs_avg_ratio=10.0,
    is_first_transaction=False, card_present=False,
    days_since_account_creation=45,
)

_BASE_RING = dict(
    primary_entity_id="rt_test", primary_entity_type="account",
    device_id="dev_rt", ip_address_hash="ip_rt",
    accounts_sharing_device=3, accounts_sharing_ip=5,
    linked_account_ids=["a", "b"],
    linked_accounts_with_block_verdict=1,
    linked_accounts_with_fraud_confirmed=1,
    shared_payment_method_across_accounts=True, payment_method_account_count=2,
    known_ring_signature_match=False,
    velocity_account_creation_same_ip_7d=3,
    transaction_graph_min_hops_to_fraud=3,
)

_BASE_IDENTITY = dict(
    account_id="rt_test", account_age_days=45,
    email_domain="gmail.com", is_disposable_email=False,
    phone_country_matches_ip_country=False,
    address_provided=True, address_is_commercial=False,
    document_verification_passed=True,
    pii_seen_on_other_accounts=0,
    accounts_created_from_same_device=1,
    accounts_created_from_same_ip=2,
    signup_velocity_same_ip_24h=1,
    name_dob_mismatch=False,
)

_BASE_PAYLOAD = dict(
    session_id="sess_rt", account_id="rt_test",
    user_agent_string="Mozilla/5.0", user_agent_is_headless=False,
    tls_fingerprint_ja3="legit_ja3", tls_fingerprint_known_bot=False,
    http_header_order_anomaly=False, accept_language_missing=False,
    mouse_movement_entropy=0.5, keystroke_dynamics_score=0.6,
    requests_per_minute=12.0, request_timing_variance_ms=320.0,
    captcha_solve_time_ms=None, captcha_solve_pattern_automated=None,
    credential_stuffing_ip_on_blocklist=False,
    login_attempt_count_this_session=1,
    api_endpoint_sequence_anomaly=False,
)

# Signal field → (domain, base_dict)
_FIELD_DOMAIN: dict[str, str] = {
    **{k: "ato"      for k in _BASE_ATO if k not in ("account_id", "device_id")},
    **{k: "payment"  for k in _BASE_PAYMENT if k not in ("transaction_id", "account_id")},
    **{k: "ring"     for k in _BASE_RING if k not in ("primary_entity_id", "primary_entity_type", "device_id", "ip_address_hash", "linked_account_ids")},
    **{k: "identity" for k in _BASE_IDENTITY if k not in ("account_id", "email_domain")},
    **{k: "payload"  for k in _BASE_PAYLOAD if k not in ("session_id", "account_id", "user_agent_string", "tls_fingerprint_ja3")},
}


# ---------------------------------------------------------------------------
# Scenario generation
# ---------------------------------------------------------------------------

def _generate_scenarios(proposal: RuleProposal, n: int, client: OpenAI) -> list[dict]:
    """Ask the LLM to generate n adversarial signal override dicts."""
    rt = proposal.rule_type
    if rt == "hard_rule":
        target = f"Rule condition to evade:\n{proposal.proposed_change.get('condition', '')}"
    elif rt == "weight_adjustment":
        field = proposal.proposed_change.get("field", "")
        old   = proposal.proposed_change.get("current_value", "?")
        new   = proposal.proposed_change.get("proposed_value", "?")
        target = (
            f"Weight change: {field} from {old} → {new}. "
            f"Generate cases that sit in the boundary zone near the detection threshold."
        )
    else:
        target = f"Sentinel filter: {proposal.proposed_change}"

    prompt = _SYSTEM_PROMPT.replace("{n}", str(n))
    response = client.chat.completions.create(
        model="gpt-4o",
        temperature=0.7,        # some variation across scenarios
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": prompt},
            {"role": "user",   "content": target},
        ],
    )
    raw = json.loads(response.choices[0].message.content)
    # LLM may wrap in a key or return array directly
    if isinstance(raw, list):
        return raw
    for v in raw.values():
        if isinstance(v, list):
            return v
    return []


# ---------------------------------------------------------------------------
# State builder
# ---------------------------------------------------------------------------

def _apply_overrides(base: dict, overrides: dict) -> dict:
    merged = base.copy()
    for k, v in overrides.items():
        if k in merged:
            merged[k] = v
    return merged


def _build_state(overrides: dict) -> dict:
    """
    Apply overrides to the base signal profile and build a FraudState dict.
    Only domains that have at least one overridden field are included,
    plus the base ATO + payment as a minimum.
    """
    # Determine which domains are touched by overrides
    touched: set[str] = {"ato", "payment"}
    for field in overrides:
        domain = _FIELD_DOMAIN.get(field)
        if domain:
            touched.add(domain)

    state: dict = {
        "primary_entity_id": "rt_test",
        "primary_entity_type": "account",
        "event_type": "transaction",
        "failed_agents": [],
    }

    domain_overrides: dict[str, dict] = {d: {} for d in touched}
    for field, value in overrides.items():
        domain = _FIELD_DOMAIN.get(field)
        if domain and domain in domain_overrides:
            domain_overrides[domain][field] = value

    if "ato" in touched:
        try:
            state["ato_signals"] = MockATOSignals(**_apply_overrides(_BASE_ATO, domain_overrides["ato"]))
        except Exception:
            pass
    if "payment" in touched:
        try:
            state["payment_signals"] = PaymentSignals(**_apply_overrides(_BASE_PAYMENT, domain_overrides["payment"]))
        except Exception:
            pass
    if "ring" in touched:
        try:
            base = _apply_overrides(_BASE_RING, domain_overrides["ring"])
            base.setdefault("linked_account_ids", ["a", "b"])
            state["ring_signals"] = RingSignals(**base)
        except Exception:
            pass
    if "identity" in touched:
        try:
            state["identity_signals"] = IdentitySignals(**_apply_overrides(_BASE_IDENTITY, domain_overrides["identity"]))
        except Exception:
            pass
    if "payload" in touched:
        try:
            state["payload_signals"] = PayloadSignals(**_apply_overrides(_BASE_PAYLOAD, domain_overrides["payload"]))
        except Exception:
            pass

    return state


# ---------------------------------------------------------------------------
# Scenario evaluation
# ---------------------------------------------------------------------------

def _eval_scenario(scenario: dict, rule_name: str, rule_type: str) -> BypassScenario:
    """Run one adversarial scenario through the pipeline and record results."""
    overrides = scenario.get("signal_overrides", {})
    description = scenario.get("description", "")
    state = _build_state(overrides)

    # Check whether the specific rule fires
    hr_result = hard_rules_check(state)
    rule_fired = (hr_result.matched and hr_result.rule_name == rule_name)

    # Run full pipeline for system verdict
    try:
        result = fraud_graph.invoke(state)
        arbiter = result.get("arbiter_output")
        system_verdict = arbiter.verdict if arbiter else "unknown"
    except Exception:
        system_verdict = "error"

    # What caught it, if the rule didn't?
    caught_by: Optional[str] = None
    if not rule_fired and system_verdict == "block":
        caught_by = hr_result.rule_name if hr_result.matched else "scoring_pipeline"

    return BypassScenario(
        description=description,
        signal_overrides=overrides,
        rule_fired=rule_fired,
        system_verdict=system_verdict,
        caught_by=caught_by,
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def red_team_rule(proposal: RuleProposal, n_attempts: int = 6) -> RedTeamReport:
    """
    Stress-test an approved RuleProposal with n_attempts adversarial scenarios.

    Args:
        proposal:   The RuleProposal to test (typically status='approved').
        n_attempts: Number of adversarial scenarios to generate and evaluate.

    Returns:
        A RedTeamReport with bypass statistics and a recommendation.
    """
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    rt = proposal.rule_type
    condition_tested = (
        proposal.proposed_change.get("condition", "")
        if rt == "hard_rule"
        else json.dumps(proposal.proposed_change)
    )

    raw_scenarios = _generate_scenarios(proposal, n_attempts, client)
    # Guard: take up to n_attempts, skip malformed entries
    raw_scenarios = [s for s in raw_scenarios if isinstance(s, dict)][:n_attempts]

    scenarios: list[BypassScenario] = [
        _eval_scenario(s, proposal.rule_name, rt) for s in raw_scenarios
    ]

    bypassed_rule   = sum(1 for s in scenarios if not s.rule_fired)
    bypassed_system = sum(1 for s in scenarios if s.system_verdict in ("allow", "step_up"))
    total           = len(scenarios)
    bypass_rate     = round(bypassed_rule / total, 3) if total else 0.0

    # Recommendation logic
    if bypass_rate >= 0.5:
        recommendation = "reject"
        reasoning = (
            f"{bypassed_rule}/{total} scenarios evade the rule — "
            "condition is too narrow to be effective."
        )
    elif bypass_rate >= 0.25 or bypassed_system > 0:
        recommendation = "revise"
        reasoning = (
            f"{bypassed_rule}/{total} bypass the rule "
            f"({bypassed_system} also slip through the full system) — "
            "condition needs broadening or complementary rules."
        )
    else:
        recommendation = "approve"
        reasoning = (
            f"Only {bypassed_rule}/{total} scenarios evade the rule "
            "and none bypass the full system — rule is robust."
        )

    return RedTeamReport(
        proposal_id=proposal.proposal_id,
        rule_name=proposal.rule_name,
        rule_type=rt,
        condition_tested=condition_tested,
        attempts_total=total,
        attempts_bypassed_rule=bypassed_rule,
        attempts_bypassed_system=bypassed_system,
        bypass_rate=bypass_rate,
        scenarios=scenarios,
        recommendation=recommendation,
        recommendation_reasoning=reasoning,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
