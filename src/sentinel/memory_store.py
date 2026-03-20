"""
Sentinel Memory Store

Simple JSON file store at data/investigation_records.json.
Persists InvestigationRecords across runs and supports tag-based
similarity queries for the Sentinel agent.
"""

import json
import os
from pathlib import Path
from typing import Optional

from src.schemas.investigation_record import InvestigationRecord

_STORE_PATH = Path(__file__).resolve().parents[2] / "data" / "investigation_records.json"


class MemoryStore:
    """
    Append-only JSON file store for InvestigationRecords.

    All reads load the full file; all writes append to it. This is
    intentionally simple -- the store is a learning artifact, not a
    production database.
    """

    def __init__(self, path: Path = _STORE_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("[]", encoding="utf-8")

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, record: InvestigationRecord) -> None:
        """
        Append record to the JSON store.

        Loads the current list, appends, and rewrites the file atomically
        enough for a single-process learning system.
        """
        records = self._load_all()
        records.append(record.model_dump())
        self._path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query_similar(
        self,
        pattern_tags: list[str],
        limit: int = 5,
    ) -> list[dict]:
        """
        Return the most similar past records as full dicts.

        Similarity is measured by the number of pattern_tags shared with
        the query. Records are ranked by match count (descending) then by
        created_at (most recent first). Returns up to `limit` records.

        Args:
            pattern_tags: Tags from the current case to match against.
            limit:        Maximum number of records to return.

        Returns:
            List of record dicts, most similar first.
        """
        if not pattern_tags:
            return []

        query_set = set(pattern_tags)
        records = self._load_all()

        scored: list[tuple[int, str, dict]] = []  # (match_count, created_at, record)
        for r in records:
            stored_tags = set(r.get("pattern_tags", []))
            match_count = len(query_set & stored_tags)
            if match_count > 0:
                scored.append((match_count, r.get("created_at", ""), r))

        scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
        return [r for _, _, r in scored[:limit]]

    def update_analyst_verdict(self, case_id: str, verdict: str) -> None:
        """Set analyst_verdict on a record by case_id."""
        records = self._load_all()
        for r in records:
            if r.get("case_id") == case_id:
                r["analyst_verdict"] = verdict
                break
        self._path.write_text(
            json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def load_record(self, case_id: str) -> Optional[InvestigationRecord]:
        """Return a single record by case_id, or None if not found."""
        for r in self._load_all():
            if r.get("case_id") == case_id:
                return InvestigationRecord(**r)
        return None

    def all_records(self) -> list[InvestigationRecord]:
        """Return every stored record, oldest first."""
        return [InvestigationRecord(**r) for r in self._load_all()]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_all(self) -> list[dict]:
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, FileNotFoundError):
            return []
