import re
from typing import Optional, List
from backend.app.detectors.base import BaseDetector, DetectorResult

class SensitiveDataDetector(BaseDetector):
    """
    Sensitive Data Detector.
    Detects Email, Phone, Aadhaar, PAN, Passport, Credit card, API keys, JWT,
    AWS keys, OpenAI keys, Google keys, and GitHub tokens.
    """
    def __init__(self):
        system_instruction = (
            "You are an AI Security Gatekeeper specialized in PII and Sensitive Data detection. "
            "Examine prompt payloads for: emails, phone numbers, Aadhaar, PAN, Passport, "
            "Credit card details, JWT tokens, and API keys (AWS, OpenAI, Google, GitHub). "
            "Return a structured JSON response specifying the score (0.00 to 1.00), "
            "confidence (0.00 to 1.00), matched_patterns, explainable reason, and a sanitized_prompt."
        )
        super().__init__(system_instruction=system_instruction)

    def detect(
        self,
        prompt: str,
        file_bytes: Optional[bytes] = None,
        file_name: Optional[str] = None
    ) -> DetectorResult:
        if not prompt:
            return DetectorResult(score=0.0, confidence=1.0, matched_patterns=[], reason="Empty prompt.", sanitized_prompt="")

        return self._local_detect(prompt)

    def _local_detect(self, prompt: str) -> DetectorResult:
        sanitized = prompt
        matched_patterns = []

        # 1. Email
        email_regex = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        if re.search(email_regex, sanitized):
            matched_patterns.append("EMAIL_ADDRESS")
            sanitized = re.sub(email_regex, "[EMAIL REDACTED]", sanitized)

        # 2. Phone
        phone_regexes = [
            r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{2,4}\)?[- ]?\d{3,4}[- ]?\d{4}\b",
            r"\b(?:\+?\d{1,3}[- ]?)?\d{3}[- ]?\d{4}\b",
            r"\b\d{10}\b"
        ]
        has_phone = False
        for rx in phone_regexes:
            if re.search(rx, sanitized):
                has_phone = True
                sanitized = re.sub(rx, "[PHONE_NUMBER REDACTED]", sanitized)
        if has_phone:
            matched_patterns.append("PHONE_NUMBER")

        # 3. Aadhaar
        aadhaar_regex = r"\b\d{4}[ -]\d{4}[ -]\d{4}\b|\b\d{12}\b"
        if re.search(aadhaar_regex, sanitized):
            matched_patterns.append("AADHAAR_NUMBER")
            sanitized = re.sub(aadhaar_regex, "[AADHAAR REDACTED]", sanitized)

        # 4. PAN
        pan_regex = r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b"
        if re.search(pan_regex, sanitized):
            matched_patterns.append("PAN_NUMBER")
            sanitized = re.sub(pan_regex, "[PAN REDACTED]", sanitized)

        # 5. Passport
        passport_regex = r"\b[a-zA-Z0-9]{7,9}\b"
        if "passport" in prompt.lower() and re.search(passport_regex, prompt):
            matched_patterns.append("PASSPORT_NUMBER")
            matches = re.finditer(passport_regex, sanitized)
            for m in matches:
                val = m.group(0)
                if val.lower() != "passport" and any(char.isdigit() for char in val):
                    sanitized = sanitized.replace(val, "[PASSPORT REDACTED]")

        # 6. Credit Card
        cc_regex = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
        if re.search(cc_regex, sanitized):
            matched_patterns.append("CREDIT_CARD_NUMBER")
            sanitized = re.sub(cc_regex, "[CREDIT_CARD REDACTED]", sanitized)

        # 7. JWT
        jwt_regexes = [
            r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b",
            r"\beyJ[A-Za-z0-9-_=]{30,}\b"
        ]
        has_jwt = False
        for rx in jwt_regexes:
            if re.search(rx, sanitized):
                has_jwt = True
                sanitized = re.sub(rx, "[JWT_TOKEN REDACTED]", sanitized)
        if has_jwt:
            matched_patterns.append("JWT_TOKEN")

        # 8. AWS Keys
        aws_access_key = r"\b(?:AKIA|ASIA|AMZN)[A-Z0-9]{12,24}\b"
        if re.search(aws_access_key, sanitized):
            matched_patterns.append("AWS_ACCESS_KEY")
            sanitized = re.sub(aws_access_key, "[AWS_ACCESS_KEY REDACTED]", sanitized)

        aws_secret_key = r"(?i)(?:aws_secret|aws_key|secret_key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        if re.search(aws_secret_key, sanitized):
            matched_patterns.append("AWS_SECRET_KEY")
            matches = re.finditer(aws_secret_key, sanitized)
            for m in matches:
                secret_val = m.group(1)
                sanitized = sanitized.replace(secret_val, "[AWS_SECRET_KEY REDACTED]")

        # 9. OpenAI Keys
        openai_key = r"\bsk-[a-zA-Z0-9-_]{40,100}\b"
        if re.search(openai_key, sanitized):
            matched_patterns.append("OPENAI_API_KEY")
            sanitized = re.sub(openai_key, "[OPENAI_API_KEY REDACTED]", sanitized)

        # 10. Google Keys
        google_key = r"\bAIza(?:Sy|Mock)[a-zA-Z0-9-_]{30,40}\b"
        if re.search(google_key, sanitized):
            matched_patterns.append("GOOGLE_API_KEY")
            sanitized = re.sub(google_key, "[GOOGLE_API_KEY REDACTED]", sanitized)

        # 11. GitHub Tokens
        github_key = r"\bgh[pousr]_[a-zA-Z0-9]{36,255}\b"
        if re.search(github_key, sanitized):
            matched_patterns.append("GITHUB_TOKEN")
            sanitized = re.sub(github_key, "[GITHUB_TOKEN REDACTED]", sanitized)

        # Generic API Keys fallback
        generic_api_key = r"(?i)(?:api_key|apikey|private_key|token|auth_token|client_secret)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?"
        if re.search(generic_api_key, sanitized):
            matched_patterns.append("GENERIC_API_KEY")
            matches = re.finditer(generic_api_key, sanitized)
            for m in matches:
                secret_val = m.group(1)
                sanitized = sanitized.replace(secret_val, "[API_KEY REDACTED]")

        from backend.app.detectors.base import compute_deterministic_score
        
        pattern_weights = {
            "EMAIL_ADDRESS": 0.30,
            "PHONE_NUMBER": 0.30,
            "AADHAAR_NUMBER": 0.40,
            "PAN_NUMBER": 0.40,
            "PASSPORT_NUMBER": 0.45,
            "CREDIT_CARD_NUMBER": 0.60,
            "JWT_TOKEN": 0.65,
            "AWS_ACCESS_KEY": 0.75,
            "AWS_SECRET_KEY": 0.85,
            "OPENAI_API_KEY": 0.80,
            "GOOGLE_API_KEY": 0.70,
            "GITHUB_TOKEN": 0.75,
            "GENERIC_API_KEY": 0.60
        }
        
        score, confidence, reason = compute_deterministic_score(
            prompt=prompt,
            matched_patterns=matched_patterns,
            detector_severity="MEDIUM",
            default_weight=0.50,
            pattern_weights=pattern_weights,
            detector_name="Sensitive Data"
        )
        
        # If no patterns match, force PII score to 0.00
        if not matched_patterns:
            score = 0.0
            confidence = 1.0
            reason = "No sensitive data elements detected."

        return DetectorResult(
            score=score,
            confidence=confidence,
            matched_patterns=matched_patterns,
            reason=reason,
            sanitized_prompt=sanitized
        )
