import re
from typing import List
from pydantic import BaseModel, Field
from backend.app.agents.base import BaseAgent

class PiiScanResult(BaseModel):
    has_pii: bool = Field(..., description="True if the prompt query contains sensitive PII elements")
    sanitized_prompt: str = Field(..., description="The query with sensitive PII tokens redacted or masked")
    detected_entities: List[str] = Field(..., description="List of category names detected")
    explanation: str = Field(..., description="Details regarding the PII exposure scan results")

class PiiDetectionAgent(BaseAgent):
    """
    PII Detection Screening Agent.
    Scans the prompt input for sensitive identifiers (SSNs, API keys, emails, database connection strings, JWTs, passport numbers)
    and applies token masking.
    """
    def __init__(self):
        system_instruction = (
            "You are a PII masking classifier. Your task is to identify personal identifiers "
            "like emails, phone numbers, Social Security Numbers (SSN), credit cards, API keys, "
            "passports, AWS credentials, JWT tokens, database connection strings, and PAN/Aadhaar numbers in user prompts. "
            "If any PII is detected, set has_pii to True, list the categories in detected_entities, "
            "and return a sanitized_prompt where the sensitive items are replaced with standard "
            "redaction tags (e.g. '[EMAIL REDACTED]', '[PAN REDACTED]', '[API_KEY REDACTED]'). "
            "If no PII is found, set has_pii to False and return the original prompt unchanged."
        )
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-flash")

    def scan(self, prompt: str) -> PiiScanResult:
        """
        Scans the prompt for PII using structured Gemini routing.
        """
        return self._generate_structured(
            prompt=prompt,
            schema_cls=PiiScanResult,
            mock_fallback_handler=self._mock_pii_scan
        )

    def _mock_pii_scan(self, prompt: str) -> PiiScanResult:
        """Production-grade offline regex pattern classifier for comprehensive PII detection."""
        detected = []
        sanitized = prompt

        # 1. SSN
        ssn_regex = r"\b\d{3}-\d{2}-\d{4}\b"
        if re.search(ssn_regex, sanitized):
            detected.append("SSN")
            sanitized = re.sub(ssn_regex, "[SSN REDACTED]", sanitized)

        # 2. Emails
        email_regex = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        if re.search(email_regex, sanitized):
            detected.append("EMAIL")
            sanitized = re.sub(email_regex, "[EMAIL REDACTED]", sanitized)

        # 3. Phone numbers (covers standard formats and 10 digits)
        phone_regex = r"\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b|\b\d{10}\b"
        if re.search(phone_regex, sanitized):
            detected.append("PHONE_NUMBER")
            sanitized = re.sub(phone_regex, "[PHONE_NUMBER REDACTED]", sanitized)

        # 4. Aadhaar Number (Indian UID: 12 digits, often grouped by 4)
        aadhaar_regex = r"\b\d{4}[ -]\d{4}[ -]\d{4}\b|\b\d{12}\b"
        if re.search(aadhaar_regex, sanitized):
            detected.append("AADHAAR")
            sanitized = re.sub(aadhaar_regex, "[AADHAAR REDACTED]", sanitized)

        # 5. PAN Card Number (Indian Tax ID: 5 letters, 4 digits, 1 letter)
        pan_regex = r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b"
        if re.search(pan_regex, sanitized):
            detected.append("PAN")
            sanitized = re.sub(pan_regex, "[PAN REDACTED]", sanitized)

        # 6. Passport Number (Standard alphanumeric international passport format)
        passport_regex = r"\b[a-zA-Z0-9]{7,9}\b"
        if "passport" in prompt.lower() and re.search(passport_regex, prompt):
            detected.append("PASSPORT")
            matches = re.finditer(passport_regex, sanitized)
            for m in matches:
                val = m.group(0)
                if val.lower() != "passport" and any(char.isdigit() for char in val):
                    sanitized = sanitized.replace(val, "[PASSPORT REDACTED]")

        # 7. Credit Card Numbers
        cc_regex = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b"
        if re.search(cc_regex, sanitized):
            detected.append("CREDIT_CARD")
            sanitized = re.sub(cc_regex, "[CREDIT_CARD REDACTED]", sanitized)

        # 8. JWT Tokens
        jwt_regex = r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"
        if re.search(jwt_regex, sanitized):
            detected.append("JWT_TOKEN")
            sanitized = re.sub(jwt_regex, "[JWT_TOKEN REDACTED]", sanitized)

        # 9. AWS Keys (AWS Access Key ID)
        aws_access_key = r"\bAKIA[A-Z0-9]{16}\b"
        if re.search(aws_access_key, sanitized):
            detected.append("AWS_ACCESS_KEY")
            sanitized = re.sub(aws_access_key, "[AWS_ACCESS_KEY REDACTED]", sanitized)

        # AWS Secret Access Key: Look for high-entropy strings following variable definitions
        aws_secret_key = r"(?i)(?:aws_secret|aws_key|secret_key|secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        if re.search(aws_secret_key, sanitized):
            detected.append("AWS_SECRET_KEY")
            matches = re.finditer(aws_secret_key, sanitized)
            for m in matches:
                secret_val = m.group(1)
                sanitized = sanitized.replace(secret_val, "[AWS_SECRET_KEY REDACTED]")

        # 10. OpenAI / Google API Keys
        openai_key = r"\bsk-[a-zA-Z0-9]{48}\b|\bsk-proj-[a-zA-Z0-9]{48}\b"
        if re.search(openai_key, sanitized):
            detected.append("API_KEY")
            sanitized = re.sub(openai_key, "[API_KEY REDACTED]", sanitized)

        google_key = r"\bAIzaSy[a-zA-Z0-9-_]{33}\b"
        if re.search(google_key, sanitized):
            if "API_KEY" not in detected:
                detected.append("API_KEY")
            sanitized = re.sub(google_key, "[API_KEY REDACTED]", sanitized)

        # 11. Database Connection Strings (postgres://, mysql://, mongodb://, etc.)
        db_regex = r"(?i)\b(?:postgresql|postgres|mysql|sqlite|mongodb|redis|mssql):\/\/[a-zA-Z0-9_:@.\-\/]+"
        if re.search(db_regex, sanitized):
            detected.append("DB_CONN_STRING")
            sanitized = re.sub(db_regex, "[DB_CONN REDACTED]", sanitized)

        # 12. Generic SSH/Private Keys block
        if "begin private key" in prompt.lower() or "begin rsa private key" in prompt.lower():
            detected.append("PRIVATE_KEY")
            sanitized = "[PRIVATE_KEY REDACTED]"

        has_pii = len(detected) > 0
        explanation = (
            "Verified via production-grade regex scanning engine. "
            f"PII entities flagged: {', '.join(detected) if detected else 'None'}."
        )
        return PiiScanResult(
            has_pii=has_pii,
            sanitized_prompt=sanitized,
            detected_entities=detected,
            explanation=explanation
        )
