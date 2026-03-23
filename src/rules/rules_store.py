"""
Rules Store

SQLite table at data/rules.db. Single source of truth for dynamic fraud rules.

Three rule types:
  weight_adjustment  overrides to DOMAIN_WEIGHTS in scoring_config
  hard_rule          analyst-approved conditions evaluated at runtime in hard_rules.py
  sentinel_filter    trigger suppression / addition (consumed by investigation_agent)

Zero .py file modification. rule_applier writes here; hard_rules.py and
scoring_config.py read from here at startup. Approving a rule change
produces no diff in any .py file.
"""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "rules.db"

_DOMAIN_WEIGHTS_DEFAULTS: dict[str, float] = {
    "ring":     0.30,
    "payment":  0.25,
    "ato":      0.20,
    "identity": 0.15,
    "payload":  0.07,
    "promo":    0.03,
}

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS rules (
    id             TEXT PRIMARY KEY,
    rule_type      TEXT NOT NULL,
    rule_name      TEXT NOT NULL UNIQUE,
    condition_json TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     TEXT NOT NULL,
    approved_by    TEXT
);
"""
_CREATE_INDEX = (
    "CREATE INDEX IF NOT EXISTS idx_type_status ON rules (rule_type, status);"
)


class RulesStore:
    """
    Append-style SQLite store for dynamic fraud rules.

    insert_rule is idempotent on rule_name: a second call with the same
    name updates condition_json and reactivates the rule.
    """

    def __init__(self, path: Path = _DB_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_rule(
        self,
        rule_type: str,
        rule_name: str,
        condition_json: dict,
        approved_by: Optional[str] = None,
    ) -> str:
        """
        Insert or update a rule. Returns the rule id.

        On rule_name conflict: updates condition_json, resets status to
        'active', and updates approved_by.
        """
        rule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO rules
                    (id, rule_type, rule_name, condition_json, status, created_at, approved_by)
                VALUES (?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(rule_name) DO UPDATE SET
                    condition_json = excluded.condition_json,
                    status         = 'active',
                    approved_by    = excluded.approved_by
                """,
                (rule_id, rule_type, rule_name,
                 json.dumps(condition_json), now, approved_by),
            )
        return rule_id

    def deactivate_rule(self, rule_name: str) -> None:
        """Set a rule's status to 'inactive' (soft delete)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE rules SET status='inactive' WHERE rule_name=?",
                (rule_name,),
            )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_active_hard_rules(self) -> list[dict]:
        """
        Return all active hard_rule rows as dicts ready for eval.

        Each dict has: rule_name, condition (str), verdict (str).
        Ordered by created_at ascending so older rules fire first.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rule_name, condition_json
                FROM rules
                WHERE rule_type = 'hard_rule' AND status = 'active'
                ORDER BY created_at ASC
                """
            ).fetchall()
        result = []
        for r in rows:
            entry = json.loads(r["condition_json"])
            entry["rule_name"] = r["rule_name"]
            result.append(entry)
        return result

    def get_active_domain_weights(self) -> dict[str, float]:
        """
        Return DOMAIN_WEIGHTS merged with active weight_adjustment overrides.

        Starts from hardcoded defaults; each active weight_adjustment row
        overwrites the matching key. Latest write wins (ordered by created_at).
        """
        weights = _DOMAIN_WEIGHTS_DEFAULTS.copy()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT condition_json
                FROM rules
                WHERE rule_type = 'weight_adjustment' AND status = 'active'
                ORDER BY created_at ASC
                """
            ).fetchall()
        for row in rows:
            change = json.loads(row["condition_json"])
            field = change.get("field", "")          # "DOMAIN_WEIGHTS.ring"
            value = change.get("proposed_value")
            if field.startswith("DOMAIN_WEIGHTS.") and value is not None:
                key = field.split(".", 1)[1]
                if key in weights:
                    weights[key] = float(value)
        return weights

    def get_active_sentinel_filters(self) -> list[dict]:
        """Return all active sentinel_filter entries."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rule_name, condition_json
                FROM rules
                WHERE rule_type = 'sentinel_filter' AND status = 'active'
                ORDER BY created_at ASC
                """
            ).fetchall()
        result = []
        for r in rows:
            entry = json.loads(r["condition_json"])
            entry["rule_name"] = r["rule_name"]
            result.append(entry)
        return result

    def all_rules(self) -> list[dict]:
        """Return all rules as dicts, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM rules ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]
