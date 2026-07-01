import re
from typing import Optional, List
from backend.app.detectors.base import BaseDetector, DetectorResult

class XssDetector(BaseDetector):
    """
    XSS Detector.
    Detects inline and payload based Cross-Site Scripting (XSS) attempts.
    """
    def __init__(self):
        system_instruction = (
            "You are an AI Security Gatekeeper specialized in detecting XSS (Cross Site Scripting). "
            "Examine prompt payloads for: script tags, HTML event handlers (e.g. onload, onerror), iframe objects, "
            "and javascript: URI schemas. "
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

        # 1. Script Tag Injections
        script_patterns = [
            r"(?i)<script\b[^>]*>(.*?)<\/script>",
            r"(?i)<script\b[^>]*>"
        ]
        has_script = False
        for pat in script_patterns:
            if re.search(pat, prompt_lower):
                has_script = True
                matched_patterns.append("XSS_SCRIPT_TAG")

        # 2. Event Handlers (e.g. onerror, onload, onclick, onmouseover)
        event_handler_patterns = [
            r"(?i)\bon\w+\s*=\s*['\"].*?['\"]",
            r"(?i)<img\b[^>]*\bonerror\s*="
        ]
        has_handler = False
        for pat in event_handler_patterns:
            if re.search(pat, prompt_lower):
                has_handler = True
                matched_patterns.append("XSS_EVENT_HANDLER")

        # 3. JavaScript URI Scheme & frames (iframe, javascript:)
        frame_patterns = [
            r"(?i)<iframe\b[^>]*>",
            r"(?i)href\s*=\s*['\"]javascript:.*['\"]",
            r"(?i)src\s*=\s*['\"]javascript:.*['\"]",
            r"(?i)javascript:\s*\w+"
        ]
        has_frame = False
        for pat in frame_patterns:
            if re.search(pat, prompt_lower):
                has_frame = True
                matched_patterns.append("XSS_JAVASCRIPT_URI")

        # 4. Standard XSS functions (alert, prompt, confirm, eval)
        xss_func_patterns = [
            r"(?i)alert\(.*?\)",
            r"(?i)confirm\(.*?\)",
            r"(?i)prompt\(.*?\)",
            r"(?i)eval\(.*?\)"
        ]
        has_func = False
        for pat in xss_func_patterns:
            if re.search(pat, prompt_lower):
                has_func = True
                matched_patterns.append("XSS_EXPLICIT_FUNCTION")

        from backend.app.detectors.base import compute_deterministic_score
        
        pattern_weights = {
            "XSS_SCRIPT_TAG": 0.920,
            "XSS_EVENT_HANDLER": 0.870,
            "XSS_JAVASCRIPT_URI": 0.850,
            "XSS_EXPLICIT_FUNCTION": 0.720
        }
        
        score, confidence, reason = compute_deterministic_score(
            prompt=prompt,
            matched_patterns=matched_patterns,
            detector_severity="HIGH",
            default_weight=0.75,
            pattern_weights=pattern_weights,
            detector_name="XSS"
        )
        
        return DetectorResult(
            score=score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            reason=reason
        )
