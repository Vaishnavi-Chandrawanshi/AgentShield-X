import re
from typing import Optional, List
from backend.app.detectors.base import BaseDetector, DetectorResult

class CodeExecutionDetector(BaseDetector):
    """
    Code Execution Detector.
    Detects attempts to execute code or scripts in various runtime languages (Python, NodeJS, PHP, Java, C#, etc.).
    """
    def __init__(self):
        system_instruction = (
            "You are an AI Security Gatekeeper specialized in detecting Code Execution attempts. "
            "Examine prompt payloads for code blocks or commands that execute programs, use system imports, "
            "call subprocesses, or run scripts in languages like Python, Javascript, PHP, or Java. "
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

        # 1. Python Code Execution / Import statements
        python_patterns = [
            r"(?:^|;|\n)\s*import\s+(os|sys|subprocess|socket|pty|shutil|requests|urllib)\b",
            r"(?:^|;|\n)\s*from\s+(os|subprocess)\s+import\b",
            r"\bexec\s*\(", r"\beval\s*\("
        ]
        has_python = False
        for pat in python_patterns:
            if re.search(pat, prompt):
                has_python = True
                matched_patterns.append("CODE_EXEC_PYTHON")

        # 2. JavaScript / Node.js Process Execution
        js_patterns = [
            r"require\(['\"](child_process|fs|net|path)['\"]\)|\bprocess\.(?:exit|stdout|stderr|env)\b",
            r"eval\s*\([^)]*\)", r"Function\s*\(\s*['\"]"
        ]
        has_js = False
        for pat in js_patterns:
            if re.search(pat, prompt):
                has_js = True
                matched_patterns.append("CODE_EXEC_JS")

        # 3. PHP script execution / Shell commands
        php_patterns = [
            r"shell_exec\(|system\(|passthru\(|exec\(|popen\(|proc_open\(|eval\(|eval\s*\b"
        ]
        has_php = False
        for pat in php_patterns:
            if re.search(pat, prompt_lower):
                has_php = True
                matched_patterns.append("CODE_EXEC_PHP")

        # 4. Java Process Execution
        java_patterns = [
            r"Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\b"
        ]
        has_java = False
        for pat in java_patterns:
            if re.search(pat, prompt):
                has_java = True
                matched_patterns.append("CODE_EXEC_JAVA")

        from backend.app.detectors.base import compute_deterministic_score
        
        pattern_weights = {
            "CODE_EXEC_PYTHON": 0.88,
            "CODE_EXEC_JS": 0.84,
            "CODE_EXEC_PHP": 0.90,
            "CODE_EXEC_JAVA": 0.86
        }
        
        score, confidence, reason = compute_deterministic_score(
            prompt=prompt,
            matched_patterns=matched_patterns,
            detector_severity="HIGH",
            default_weight=0.75,
            pattern_weights=pattern_weights,
            detector_name="Code Execution"
        )
        
        return DetectorResult(
            score=score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            reason=reason
        )
