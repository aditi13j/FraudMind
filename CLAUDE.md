Build Milestone 5B — Pattern Detection Agent.

New files:
  src/sentinel/pattern_detection.py
  src/schemas/pattern_finding.py

PatternFinding schema (src/schemas/pattern_finding.py):
  pattern_tags: list[str]
  count: int
  time_window_hours: int
  assessment_distribution: dict[str, int]
  dominant_verdict: str
  suggestion: str
  confidence: float
  finding_type: Literal["emerging_fraud", "false_positive_cluster", "novel_pattern"]
  detected_at: str  (ISO timestamp)

Pattern Detection function (src/sentinel/pattern_detection.py):
  run_pattern_detection(
      time_window_hours: int = 48,
      min_count: int = 2,
      store: Optional[MemoryStore] = None
  ) -> list[PatternFinding]

Steps:
1. Load all records from last time_window_hours (pure Python)
2. Count tag co-occurrences across records (pure Python)
   - For each pair of tags that appear together, count occurrences
   - Also count single tags
   - Only keep combinations appearing >= min_count times
3. For each qualifying combination collect:
   - assessment_distribution
   - dominant_verdict
   - list of case_ids
4. One LLM call (GPT-4o, temperature=0) to synthesize:
   - For each pattern: generate suggestion and finding_type
   - Input: all qualifying patterns with their stats
   - Output: list of PatternFindings with suggestion + finding_type filled in
5. Return sorted by count descending

LLM system prompt for Pattern Detection:
You are a fraud pattern analyst.
You receive tag co-occurrence statistics from recent investigations.
For each pattern produce:
  - suggestion: specific actionable recommendation (one sentence)
  - finding_type: "emerging_fraud" | "false_positive_cluster" | "novel_pattern"
Use finding_type = "false_positive_cluster" when 
  assessment_distribution shows > 40% possible_false_positive
Use finding_type = "emerging_fraud" when count is high 
  and dominant_verdict is block with likely_correct assessment
Use finding_type = "novel_pattern" for everything else
Output JSON array only.

Create notebooks/milestone5b_pattern_detection_demo.ipynb:
- Run 3 different cases through full pipeline 
  (ring attack, clean legitimate, ambiguous ATO)
- All 3 go through Sentinel investigation
- Then run pattern detection across all stored records
- Print all PatternFindings
- Show which finding_type each pattern gets

Do not modify any existing files.