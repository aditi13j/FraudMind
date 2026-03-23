"""
Sentinel Memory Store

SQLite store at data/investigation_records.db (source of truth).
Chroma vector DB at data/chroma/ (semantic similarity index).

Records are written to both on save. query_similar uses Chroma embeddings
(text-embedding-3-small) so Sentinel retrieves semantically similar past
cases, not just tag-identical ones.

Backwards-compatible with the old JSON file store: if
data/investigation_records.json exists it is migrated automatically on the
first instantiation and then renamed to *.migrated so it is not imported twice.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction
from dotenv import load_dotenv

from src.schemas.investigation_record import InvestigationRecord

load_dotenv()

_DB_PATH    = Path(__file__).resolve().parents[2] / "data" / "investigation_records.db"
_JSON_PATH  = Path(__file__).resolve().parents[2] / "data" / "investigation_records.json"
_CHROMA_PATH = Path(__file__).resolve().parents[2] / "data" / "chroma"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS records (
    case_id     TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_created_at ON records (created_at);
"""


class MemoryStore:
    """
    SQLite + Chroma store for InvestigationRecords.

    SQLite holds the full record JSON.
    Chroma holds text-embedding-3-small embeddings of (narrative + tags)
    for semantic similarity queries.
    """

    def __init__(self, path: Path = _DB_PATH) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_CREATE_INDEX)
        self._migrate_json()

        # Vector index
        _CHROMA_PATH.mkdir(parents=True, exist_ok=True)
        self._chroma = chromadb.PersistentClient(path=str(_CHROMA_PATH))
        self._ef = OpenAIEmbeddingFunction(
            api_key=os.environ.get("OPENAI_API_KEY", ""),
            model_name="text-embedding-3-small",
        )
        self._collection = self._chroma.get_or_create_collection(
            name="investigation_records",
            embedding_function=self._ef,
        )
        self._backfill()

    # ------------------------------------------------------------------
    # Connection helper
    # ------------------------------------------------------------------

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
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
    # Migration from legacy JSON file
    # ------------------------------------------------------------------

    def _migrate_json(self) -> None:
        if not _JSON_PATH.exists():
            return
        try:
            raw = json.loads(_JSON_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if not raw:
            _JSON_PATH.rename(_JSON_PATH.with_suffix(".json.migrated"))
            return
        with self._connect() as conn:
            for r in raw:
                case_id    = r.get("case_id", "")
                created_at = r.get("created_at", "")
                if not case_id:
                    continue
                conn.execute(
                    "INSERT OR IGNORE INTO records (case_id, created_at, data) VALUES (?,?,?)",
                    (case_id, created_at, json.dumps(r)),
                )
        _JSON_PATH.rename(_JSON_PATH.with_suffix(".json.migrated"))

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, record: InvestigationRecord) -> None:
        """Persist to SQLite and upsert embedding into Chroma."""
        data = record.model_dump()
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO records (case_id, created_at, data) VALUES (?,?,?)",
                (record.case_id, record.created_at, json.dumps(data)),
            )
        self._upsert_chroma(data)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def query_similar(self, query_text: str, limit: int = 5) -> list[dict]:
        """
        Return the most semantically similar past records as full dicts.

        Embeds query_text with text-embedding-3-small and queries Chroma.
        Falls back to an empty list if the collection is empty.

        Args:
            query_text: Free-text description of the current case —
                        narrative, signals, domain context, and tags.
            limit:      Maximum number of records to return.

        Returns:
            List of record dicts, most similar first.
        """
        if not query_text:
            return []
        count = self._collection.count()
        if count == 0:
            return []
        results = self._collection.query(
            query_texts=[query_text],
            n_results=min(limit, count),
        )
        case_ids = results["ids"][0]
        all_data = {r["case_id"]: r for r in self._load_all()}
        return [all_data[cid] for cid in case_ids if cid in all_data]

    def update_analyst_verdict(self, case_id: str, verdict: str) -> None:
        """Set analyst_verdict on a record by case_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM records WHERE case_id=?", (case_id,)
            ).fetchone()
            if row is None:
                return
            data = json.loads(row["data"])
            data["analyst_verdict"] = verdict
            conn.execute(
                "UPDATE records SET data=? WHERE case_id=?",
                (json.dumps(data), case_id),
            )

    def load_record(self, case_id: str) -> Optional[InvestigationRecord]:
        """Return a single record by case_id, or None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM records WHERE case_id=?", (case_id,)
            ).fetchone()
        if row is None:
            return None
        return InvestigationRecord(**json.loads(row["data"]))

    def all_records(self) -> list[InvestigationRecord]:
        """Return every stored record, oldest first."""
        return [InvestigationRecord(**r) for r in self._load_all()]

    def get_archetypes(self, min_cases: int = 3) -> list[dict]:
        """
        Derive case archetypes by clustering stored records on pattern tags.

        Each archetype summarises what Sentinel has learned about a recurring
        pattern: how often it appears, how often it's a false positive, what
        the dominant verdict is, and a representative narrative excerpt.

        Only tag combinations seen in at least `min_cases` records are returned.
        Sorted by case_count descending.

        Returns a list of dicts with keys:
            tags            - sorted list of tags defining this archetype
            case_count      - number of records matching this tag set
            fp_rate         - fraction labeled false_positive by an analyst
            dominant_assessment - most common Sentinel assessment
            dominant_verdict    - most common arbiter verdict
            hypothesis_confirmed_rate - fraction where hypothesis_outcome=="confirmed"
            example_narrative   - first 200 chars of the most recent narrative
        """
        records = self._load_all()
        if not records:
            return []

        # Group by frozenset of pattern_tags
        groups: dict[frozenset, list[dict]] = {}
        for r in records:
            key = frozenset(r.get("pattern_tags") or [])
            if not key:
                continue
            groups.setdefault(key, []).append(r)

        archetypes = []
        for tag_set, recs in groups.items():
            if len(recs) < min_cases:
                continue

            labeled = [r for r in recs if r.get("analyst_verdict")]
            fp_count = sum(1 for r in labeled if r.get("analyst_verdict") == "false_positive")
            fp_rate = round(fp_count / len(labeled), 3) if labeled else None

            assessments: dict[str, int] = {}
            for r in recs:
                a = r.get("assessment", "uncertain")
                assessments[a] = assessments.get(a, 0) + 1
            dominant_assessment = max(assessments, key=assessments.__getitem__)

            verdicts: dict[str, int] = {}
            for r in recs:
                v = r.get("arbiter_verdict", "unknown")
                verdicts[v] = verdicts.get(v, 0) + 1
            dominant_verdict = max(verdicts, key=verdicts.__getitem__)

            confirmed = sum(
                1 for r in recs if r.get("hypothesis_outcome") == "confirmed"
            )
            total_with_outcome = sum(
                1 for r in recs if r.get("hypothesis_outcome") is not None
            )
            confirmed_rate = (
                round(confirmed / total_with_outcome, 3)
                if total_with_outcome else None
            )

            # Most recent narrative snippet
            latest = max(recs, key=lambda r: r.get("created_at", ""))
            narrative = latest.get("investigation_narrative", "")[:200]

            archetypes.append({
                "tags":                       sorted(tag_set),
                "case_count":                 len(recs),
                "fp_rate":                    fp_rate,
                "dominant_assessment":        dominant_assessment,
                "dominant_verdict":           dominant_verdict,
                "hypothesis_confirmed_rate":  confirmed_rate,
                "example_narrative":          narrative,
            })

        archetypes.sort(key=lambda a: a["case_count"], reverse=True)
        return archetypes

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_all(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT data FROM records ORDER BY created_at ASC"
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    @staticmethod
    def _doc_text(record: dict) -> str:
        """Text to embed: narrative + space-joined tag list."""
        narrative = record.get("investigation_narrative", "")
        tags = " ".join(record.get("pattern_tags", []))
        return f"{narrative} Tags: {tags}"

    def _upsert_chroma(self, record: dict) -> None:
        self._collection.upsert(
            ids=[record["case_id"]],
            documents=[self._doc_text(record)],
            metadatas=[{
                "arbiter_verdict": record.get("arbiter_verdict", ""),
                "created_at": record.get("created_at", ""),
            }],
        )

    def _backfill(self) -> None:
        """Upsert any SQLite records missing from the Chroma index."""
        records = self._load_all()
        if not records:
            return
        existing_ids = set(self._collection.get()["ids"])
        missing = [r for r in records if r.get("case_id") not in existing_ids]
        if not missing:
            return
        self._collection.upsert(
            ids=[r["case_id"] for r in missing],
            documents=[self._doc_text(r) for r in missing],
            metadatas=[{
                "arbiter_verdict": r.get("arbiter_verdict", ""),
                "created_at": r.get("created_at", ""),
            } for r in missing],
        )
