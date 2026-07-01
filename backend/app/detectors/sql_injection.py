import re
from typing import Optional, List
from backend.app.detectors.base import BaseDetector, DetectorResult

class SqlInjectionDetector(BaseDetector):
    """
    SQL Injection Detector.
    Detects classic SQL injection strings, tautologies, union select statements, and destructive commands.
    """
    def __init__(self):
        system_instruction = (
            "You are an AI Security Gatekeeper specialized in detecting SQL Injections. "
            "Examine prompt payloads for SQL injection patterns, union queries, tautologies (e.g. 1=1), "
            "and comment markers. "
            "Return a structured JSON response specifying the score (0.00 to 1.00), "
            "confidence (0.00 to 1.00), matched_patterns, and explainable reason."
        )
        super().__init__(system_instruction=system_instruction)

    def detect(
        self,
        prompt: str,
        file_bytes: Optional[bytes] = None,
        file_name: Optional[str] = None
    ) -> DetectorResult:
        if not prompt:
            return DetectorResult(score=0.0, confidence=1.0, matched_patterns=[], reason="Empty prompt.")

        return self._local_detect(prompt)

    def _local_detect(self, prompt: str) -> DetectorResult:
        prompt_lower = prompt.lower()
        matched_patterns = []

        # 1. Tautology (e.g. '1'='1', "1"="1", or 1=1)
        tautology_patterns = [
            r"(?i)('|\")\s*(?:or|and)\s*\1?\d+\1?\s*=\s*\1?\d+\1?",
            r"(?i)('|\")\s*(?:or|and)\s*('|\")?[a-zA-Z]+\2?\s*=\s*\2?[a-zA-Z]+\2?",
            r"(?i)\bor\s+\d+\s*=\s*\d+",
            r"(?i)\bor\s+['\"][a-zA-Z]+['\"]\s*=\s*['\"][a-zA-Z]+['\"]"
        ]
        
        has_tautology = False
        for pat in tautology_patterns:
            if re.search(pat, prompt_lower):
                has_tautology = True
                matched_patterns.append("SQL_TAUTOLOGY")

        # 2. Union and Select patterns
        union_patterns = [
            r"(?i)\bunion\s+(?:all\s+)?select\b",
            r"(?i)\bselect\s+.*\s+from\s+users\b",
            r"(?i)\bselect\s+.*\s+from\s+information_schema\b"
        ]
        
        has_union = False
        for pat in union_patterns:
            if re.search(pat, prompt_lower):
                has_union = True
                matched_patterns.append("SQL_UNION_SELECT")

        # 3. SQL Comments & Destructive command patterns
        destructive_patterns = [
            r"(?i)\bdrop\s+(?:table|database|index)\b",
            r"(?i)\bdelete\s+from\b",
            r"(?i)\binsert\s+into\b",
            r"(?i)\bupdate\b.*\bset\b",
            r"(?i)--\s*$",
            r"(?i)\/\*.*\*\/",
            r"(?i)\bexec(?:ute)?\s*\("
        ]
        
        has_destructive = False
        for pat in destructive_patterns:
            if re.search(pat, prompt_lower):
                has_destructive = True
                matched_patterns.append("SQL_DESTRUCTIVE_COMMAND")

        from backend.app.detectors.base import compute_deterministic_score
        
        pattern_weights = {
            "SQL_TAUTOLOGY": 0.81,
            "SQL_UNION_SELECT": 0.88,
            "SQL_DESTRUCTIVE_COMMAND": 0.92
        }
        
        score, confidence, reason = compute_deterministic_score(
            prompt=prompt,
            matched_patterns=matched_patterns,
            detector_severity="CRITICAL",
            default_weight=0.80,
            pattern_weights=pattern_weights,
            detector_name="SQL Injection"
        )
        
        return DetectorResult(
            score=score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            reason=reason
        )
