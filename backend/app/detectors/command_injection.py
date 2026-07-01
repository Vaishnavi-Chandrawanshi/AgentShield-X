import re
from typing import Optional, List
from backend.app.detectors.base import BaseDetector, DetectorResult

class CommandInjectionDetector(BaseDetector):
    """
    Command Injection Detector.
    Detects sh/bash commands, powershell, cmd.exe, curl, wget, nc, python -c, perl, ruby, and reverse shell payloads.
    """
    def __init__(self):
        system_instruction = (
            "You are an AI Security Gatekeeper specialized in detecting Command Injections. "
            "Examine prompt payloads for: bash, sh, powershell, cmd.exe, curl, wget, nc, "
            "python -c, perl, ruby, and reverse shell payloads. "
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

        # 1. Reverse Shell Payloads
        reverse_shell_patterns = [
            r"bash\s+-i\s*>\s*&\s*/dev/(?:tcp|udp)/",
            r"nc\s+(?:-e\s+|-[a-zA-Z]*e[a-zA-Z]*\s+)(?:/bin/)?(?:bash|sh|cmd|powershell)",
            r"nc\s+[\d\.]+\s+\d+\s*\|\s*(?:/bin/)?(?:bash|sh)",
            r"python\s+-c\s+['\"].*import\s+socket.*os\.dup2.*['\"]",
            r"perl\s+-e\s+['\"].*socket.*open\(.*STDIN.*['\"]",
            r"php\s+-r\s+['\"].*fsockopen.*exec.*['\"]",
            r"ruby\s+-e\s+['\"].*TCPSocket.*exec.*['\"]",
            r"mkfifo\s+/tmp/\w+\s*;\s*nc\s+[\d\.]+\s+\d+\s*0<\s*/tmp/\w+",
            r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+",
            r"bash\s+-i\s*>&?/dev/tcp/",
            r"nc(?:\.exe)?\s+.*-e\s+(?:cmd\.exe|/bin/sh)"
        ]
        
        has_rev_shell = False
        for pat in reverse_shell_patterns:
            if re.search(pat, prompt, re.IGNORECASE) or "/dev/tcp/" in prompt_lower:
                has_rev_shell = True
                matched_patterns.append("REVERSE_SHELL_PAYLOAD")

        # 2. Command Injection Triggers (shells and downloaders)
        command_injection_patterns = [
            r"\bpowershell(?:\.exe)?\s+(?:-enc|-encodedcommand|-e|-executionpolicy|-nop|-noprofile)",
            r"\bcmd(?:\.exe)?\s+(?:\/c|\/k)",
            r"\b(?:bash|sh|zsh)\s+-i\b",
            r"curl\s+.*\|\s*(?:bash|sh|python|perl|ruby)",
            r"wget\s+.*\|\s*(?:bash|sh|python|perl|ruby)",
            r"chmod\s+\+x\s+.*&&\s*\./",
            r"echo\s+.*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh)",
            r"\bwhoami\b",
            r"\bcat\s+/etc/passwd",
            r"\bcat\s+/etc/shadow"
        ]
        
        has_cmd_injection = False
        for pat in command_injection_patterns:
            if re.search(pat, prompt, re.IGNORECASE):
                has_cmd_injection = True
                matched_patterns.append("COMMAND_INJECTION_TRIGGER")

        # 3. Simple CLI Tool calls (curl, wget, nc, python -c, perl, ruby)
        cli_patterns = [
            r"\bcurl\s+", r"\bwget\s+", r"\bnc(?:\.exe)?\b", 
            r"\bpython\d*(?:\.exe)?\b.*\s+-c\b", 
            r"\bperl\b.*\s+-e\b", 
            r"\bruby\b.*\s+-e\b"
        ]
        has_cli_tool = False
        for pat in cli_patterns:
            if re.search(pat, prompt, re.IGNORECASE):
                has_cli_tool = True
                matched_patterns.append(f"CLI_TOOL_USE")

        from backend.app.detectors.base import compute_deterministic_score
        
        pattern_weights = {
            "REVERSE_SHELL_PAYLOAD": 0.954,
            "COMMAND_INJECTION_TRIGGER": 0.925,
            "CLI_TOOL_USE": 0.580
        }
        
        score, confidence, reason = compute_deterministic_score(
            prompt=prompt,
            matched_patterns=matched_patterns,
            detector_severity="CRITICAL",
            default_weight=0.80,
            pattern_weights=pattern_weights,
            detector_name="Command Injection"
        )
        
        return DetectorResult(
            score=score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            reason=reason
        )
