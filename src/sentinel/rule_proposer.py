"""
Rule Proposer -- Milestone 6

Reads a PatternFinding and produces a RuleProposal via one GPT-4o call.
The LLM acts as a fraud rule engineer: it chooses the rule type, names the
rule, writes the description, proposes the specific change, and assesses
expected impact and risk.

ProposalStore handles persistence at data/rule_proposals.json using the
same append-then-rewrite pattern as MemoryStore.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.pattern_finding import PatternFinding
from src.schemas.rule_proposal import RuleProposal

load_dotenv()

_DB_PATH        = Path(__file__).resolve().parents[2] / "data" / "rule_proposals.db"
_JSON_PATH_LEGACY = Path(__file__).resolve().parents[2] / "data" / "rule_proposals.json"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
"""
_CREATE_INDEX = "CREATE INDEX IF NOT EXISTS idx_status ON proposals (status);"

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a fraud rule engineer working on FraudMind.
You receive a pattern finding from recent fraud investigations.
Propose one specific rule change to address this pattern.

Rule types:
  weight_adjustment — change a weight in DOMAIN_WEIGHTS in scoring_config.py
  hard_rule         — add a new instant block/allow condition to hard_rules.py
  sentinel_filter   — change when Sentinel investigation triggers

Choose weight_adjustment for emerging_fraud findings with high count.
Choose hard_rule for false_positive_cluster findings.
Choose sentinel_filter for high volume low-value patterns.

AVAILABLE SIGNAL FIELDS (only use these — no other fields exist):

MockATOSignals:
  account_age_days, is_new_device, geo_mismatch, time_since_last_login_days,
  immediate_high_value_action, email_change_attempted, password_change_attempted,
  support_ticket_language_match

PaymentSignals:
  amount_usd, is_international, transactions_last_1h, transactions_last_24h,
  amount_vs_avg_ratio, is_first_transaction, card_present, days_since_account_creation

RingSignals:
  accounts_sharing_device, accounts_sharing_ip, linked_accounts_with_fraud_confirmed,
  linked_accounts_with_block_verdict, known_ring_signature_match,
  velocity_account_creation_same_ip_7d, transaction_graph_min_hops_to_fraud

IdentitySignals:
  is_disposable_email, document_verification_passed, pii_seen_on_other_accounts,
  accounts_created_from_same_device, accounts_created_from_same_ip,
  signup_velocity_same_ip_24h, name_dob_mismatch

PayloadSignals:
  tls_fingerprint_known_bot, user_agent_is_headless, requests_per_minute,
  credential_stuffing_ip_on_blocklist, login_attempt_count_this_session,
  captcha_solve_pattern_automated

DOMAIN_WEIGHTS (current values):
  ring=0.30, payment=0.25, ato=0.20, identity=0.15, payload=0.07, promo=0.03

For hard_rule conditions, variables are named exactly:
  ato (MockATOSignals), payment (PaymentSignals), ring (RingSignals),
  identity (IdentitySignals), payload (PayloadSignals)
  Each may be None — always guard with `X is not None and`.
  Example: "ato is not None and ato.account_age_days < 30 and ato.geo_mismatch"

proposed_change must follow the exact format for the chosen rule type:

weight_adjustment:
{
    "file": "scoring_config.py",
    "field": "DOMAIN_WEIGHTS.<key>",
    "current_value": <current float from above>,
    "proposed_value": <new float, must keep all weights summing to ~1.0>,
    "rationale": "<one sentence>"
}

hard_rule:
{
    "condition": "<valid Python using only the signal fields listed above>",
    "verdict": "block" | "allow" | "step_up" | "escalate",
    "rationale": "<one sentence>"
}

sentinel_filter:
{
    "action": "remove_trigger" | "add_filter",
    "target": "<trigger_reason or filter description>",
    "rationale": "<one sentence>"
}

Output JSON only:
{
  "rule_type": "weight_adjustment" | "hard_rule" | "sentinel_filter",
  "rule_name": "short_snake_case_name",
  "description": "plain English one sentence",
  "proposed_change": {...exact format per rule type above...},
  "expected_impact": "one sentence",
  "risk": "one sentence"
}\
"""


# ---------------------------------------------------------------------------
# Public interface: propose_rule
# ---------------------------------------------------------------------------

def propose_rule(finding: PatternFinding) -> RuleProposal:
    """
    Produce a RuleProposal from a PatternFinding using one GPT-4o call.

    Args:
        finding: A PatternFinding from run_pattern_detection.

    Returns:
        A RuleProposal with status="pending".
    """
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    user_content = json.dumps({
        "pattern_tags": finding.pattern_tags,
        "count": finding.count,
        "time_window_hours": finding.time_window_hours,
        "assessment_distribution": finding.assessment_distribution,
        "dominant_verdict": finding.dominant_verdict,
        "confidence": finding.confidence,
        "finding_type": finding.finding_type,
        "suggestion": finding.suggestion,
    }, indent=2)

    response = client.chat.completions.create(
        model="gpt-4o",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ],
    )

    data = json.loads(response.choices[0].message.content.strip())

    return RuleProposal(
        pattern_tags=finding.pattern_tags,
        pattern_count=finding.count,
        pattern_finding_type=finding.finding_type,
        rule_type=data["rule_type"],
        rule_name=data["rule_name"],
        description=data["description"],
        proposed_change=data["proposed_change"],
        expected_impact=data["expected_impact"],
        risk=data["risk"],
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# ProposalStore
# ---------------------------------------------------------------------------

class ProposalStore:
    """SQLite store for RuleProposals at data/rule_proposals.db."""

    def __init__(self, path: Path = _DB_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)
        self._migrate_json()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _migrate_json(self) -> None:
        if not _JSON_PATH_LEGACY.exists():
            return
        try:
            raw = json.loads(_JSON_PATH_LEGACY.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        with self._connect() as conn:
            for r in raw:
                pid = r.get("proposal_id", "")
                if not pid:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO proposals (proposal_id, status, created_at, data) VALUES (?,?,?,?)",
                    (pid, r.get("status", "pending"), r.get("created_at", ""), json.dumps(r)),
                )
        _JSON_PATH_LEGACY.rename(_JSON_PATH_LEGACY.with_suffix(".json.migrated"))

    def _load_all(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM proposals ORDER BY created_at ASC"
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def save(self, proposal: RuleProposal) -> None:
        """Insert or replace a proposal."""
        data = proposal.model_dump()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO proposals (proposal_id, status, created_at, data) VALUES (?,?,?,?)",
                (proposal.proposal_id, proposal.status, proposal.created_at, json.dumps(data)),
            )

    def load_pending(self) -> list[RuleProposal]:
        """Return all proposals with status='pending'."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM proposals WHERE status='pending' ORDER BY created_at ASC"
            ).fetchall()
        return [RuleProposal(**json.loads(r["data"])) for r in rows]

    def update_status(self, proposal_id: str, status: str) -> None:
        """Update the status field both in the data blob and the indexed column."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if row is None:
                return
            data = json.loads(row["data"])
            data["status"] = status
            conn.execute(
                "UPDATE proposals SET status=?, data=? WHERE proposal_id=?",
                (status, json.dumps(data), proposal_id),
            )
