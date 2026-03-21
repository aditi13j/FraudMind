"""
Pattern Detection Agent -- Milestone 5B

Analyzes tag co-occurrences across recent InvestigationRecords and produces
PatternFindings. Pure Python for counting; one GPT-4o call to synthesize
suggestions and classify each finding.
"""

import json
import os
from collections import Counter
from datetime import datetime, timezone, timedelta
from itertools import combinations
from typing import Optional

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

from src.schemas.pattern_finding import PatternFinding
from src.sentinel.memory_store import MemoryStore

load_dotenv()

_memory_store = MemoryStore()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a fraud pattern analyst.
You receive tag co-occurrence statistics from recent investigations.
For each pattern produce:
  - tag_key: the exact pattern_tags value from the input (copy it verbatim as a JSON array)
  - suggestion: specific actionable recommendation (one sentence)
  - finding_type: "emerging_fraud" | "false_positive_cluster" | "novel_pattern"

Use finding_type = "false_positive_cluster" when \
assessment_distribution shows > 40% possible_false_positive.
Use finding_type = "emerging_fraud" when count is high \
and dominant_verdict is block with likely_correct assessment.
Use finding_type = "novel_pattern" for everything else.

Output a JSON array only. Each element must have tag_key, suggestion, finding_type.\
"""


# ---------------------------------------------------------------------------
# Step 1: Time-window filter
# ---------------------------------------------------------------------------

def _records_in_window(store: MemoryStore, time_window_hours: int) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=time_window_hours)
    result = []
    for r in store._load_all():
        try:
            ts = datetime.fromisoformat(r["created_at"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= cutoff:
                result.append(r)
        except (KeyError, ValueError):
            continue
    return result


# ---------------------------------------------------------------------------
# Step 2: Count tag co-occurrences
# ---------------------------------------------------------------------------

def _count_combinations(records: list[dict], min_count: int) -> dict[tuple, list[dict]]:
    """
    For each record, emit all single tags and all pairs.
    Group records by combination. Return only combinations with >= min_count records.
    """
    groups: dict[tuple, list[dict]] = {}

    for r in records:
        tags = r.get("pattern_tags", [])
        combos: list[tuple] = [(t,) for t in tags]
        combos += [tuple(sorted(pair)) for pair in combinations(tags, 2)]
        for combo in combos:
            groups.setdefault(combo, []).append(r)

    return {combo: recs for combo, recs in groups.items() if len(recs) >= min_count}


# ---------------------------------------------------------------------------
# Step 3: Collect stats per combination
# ---------------------------------------------------------------------------

def _build_pattern_stats(
    combo: tuple,
    records: list[dict],
    time_window_hours: int,
) -> dict:
    """Build the stats dict that will be sent to the LLM for one pattern."""
    assessment_distribution: dict[str, int] = Counter(
        r.get("assessment", "uncertain") for r in records
    )
    verdict_counts: Counter = Counter(r.get("arbiter_verdict", "unknown") for r in records)
    dominant_verdict = verdict_counts.most_common(1)[0][0]

    dominant_assessment = Counter(assessment_distribution).most_common(1)[0][0]
    dominant_count = assessment_distribution[dominant_assessment]
    confidence = round(dominant_count / len(records), 4)

    return {
        "pattern_tags": list(combo),
        "count": len(records),
        "time_window_hours": time_window_hours,
        "assessment_distribution": dict(assessment_distribution),
        "dominant_verdict": dominant_verdict,
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
# Step 4: One LLM call for all patterns
# ---------------------------------------------------------------------------

def _llm_synthesize(pattern_stats: list[dict]) -> list[dict]:
    """
    Send all pattern stats to GPT-4o in one call.
    Returns list of dicts with keys: pattern_tags, suggestion, finding_type.
    """
    user_content = json.dumps(pattern_stats, indent=2)

    model = ChatOpenAI(
        model="gpt-4o",
        temperature=0,
        api_key=os.environ["OPENAI_API_KEY"],
    )

    response = model.invoke([
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ])

    content = response.content.strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]

    return json.loads(content)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def run_pattern_detection(
    time_window_hours: int = 48,
    min_count: int = 2,
    store: Optional[MemoryStore] = None,
) -> list[PatternFinding]:
    """
    Scan recent InvestigationRecords for tag co-occurrence patterns and
    return PatternFindings sorted by count descending.

    Args:
        time_window_hours: Lookback window. Records older than this are ignored.
        min_count:         Minimum occurrences for a combination to qualify.
        store:             MemoryStore instance (uses module default if None).

    Returns:
        List of PatternFindings, most frequent first.
    """
    active_store = store or _memory_store
    detected_at = datetime.now(timezone.utc).isoformat()

    records = _records_in_window(active_store, time_window_hours)
    if not records:
        return []

    groups = _count_combinations(records, min_count)
    if not groups:
        return []

    # Build stats for each qualifying combination
    pattern_stats = [
        _build_pattern_stats(combo, recs, time_window_hours)
        for combo, recs in groups.items()
    ]

    # One LLM call for suggestion + finding_type
    llm_results = _llm_synthesize(pattern_stats)

    # Build a lookup keyed by sorted tag list so order in LLM response doesn't matter.
    # tag_key is a JSON array string like ["geo_mismatch", "new_account"]; normalise to
    # a frozenset-style canonical key for robust matching.
    def _canonical(tags: list) -> str:
        return json.dumps(sorted(tags))

    llm_by_key: dict[str, dict] = {}
    for item in llm_results:
        raw_key = item.get("tag_key", [])
        if isinstance(raw_key, str):
            try:
                raw_key = json.loads(raw_key)
            except (json.JSONDecodeError, TypeError):
                raw_key = []
        llm_by_key[_canonical(raw_key)] = item

    findings: list[PatternFinding] = []
    for stats in pattern_stats:
        key = _canonical(stats["pattern_tags"])
        llm = llm_by_key.get(key, {})
        findings.append(PatternFinding(
            pattern_tags=stats["pattern_tags"],
            count=stats["count"],
            time_window_hours=stats["time_window_hours"],
            assessment_distribution=stats["assessment_distribution"],
            dominant_verdict=stats["dominant_verdict"],
            suggestion=llm.get("suggestion", ""),
            confidence=stats["confidence"],
            finding_type=llm.get("finding_type", "novel_pattern"),
            detected_at=detected_at,
        ))

    findings.sort(key=lambda f: f.count, reverse=True)
    return findings
