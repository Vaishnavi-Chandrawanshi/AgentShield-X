import json
from pydantic import BaseModel, Field, field_validator
from typing import List
from backend.app.agents.base import BaseAgent

class RiskAssessmentResult(BaseModel):
    overall_risk_score: float = Field(..., description="The synthesized threat index from 0.0 (safe) to 1.0 (critical)")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    policy_action: str = Field(..., description="The security decision verdict: ALLOW, REDACTED, BLOCK, or HUMAN_REVIEW")
    findings: List[str] = Field(default_factory=list, description="Consolidated security findings or alarms")
    decision_reasoning: str = Field(..., description="Detailed technical reasoning justifying the verdict")

    @field_validator("policy_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        upper_v = v.upper()
        if upper_v not in ("ALLOW", "BLOCK", "REDACTED", "HUMAN_REVIEW"):
            raise ValueError("policy_action must be ALLOW, BLOCK, REDACTED, or HUMAN_REVIEW")
        return upper_v

class RiskScoringAgent(BaseAgent):
    """
    Risk Scoring Agent.
    Aggregates findings from sub-agents to compute a dynamic threat score
    and enforce security policies (ALLOW, REDACT, BLOCK, HUMAN_REVIEW).
    """
    def __init__(self):
        system_instruction = (
            "You are a Security Gateway Decision Point. Your role is to analyze a JSON-formatted "
            "consolidated summary of individual agent scans (Prompt Injection, PII, and File scan alerts). "
            "Using these inputs, synthesize a final risk score (0.0 to 1.0) and determine the strict gateway action: "
            "- BLOCK: If risk score > 0.90 (e.g. Critical injection, command execution, malware). "
            "- HUMAN_REVIEW: If risk score is between 0.60 and 0.90 (Suspicious overrides, jailbreaks, review triggers). "
            "- REDACTED: If risk score is between 0.30 and 0.60 (PII disclosures detected but no other high-risk triggers). "
            "- ALLOW: If risk score is below 0.30 (All checks safe). "
            "Return a structured JSON output conforming to the response schema."
        )
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-pro")

    def assess(self, screening_summary_text: str) -> RiskAssessmentResult:
        """
        Synthesizes the overall risk score and gateway action verdict.
        """
        return self._generate_structured(
            prompt=screening_summary_text,
            schema_cls=RiskAssessmentResult,
            mock_fallback_handler=self._mock_risk_assessment
        )

    def _mock_risk_assessment(self, summary_text: str) -> RiskAssessmentResult:
        """Dynamic weighted risk calculation engine matching Phase 3/6 directives."""
        try:
            summary = json.loads(summary_text)
        except Exception:
            summary = {}

        findings = []
        score_sum = 0.05  # Base query risk score

        # 1. Evaluate prompt injection findings
        inj_data = summary.get("prompt_injection", {})
        is_injection = inj_data.get("is_injection", False)
        inj_findings = inj_data.get("findings", [])

        if is_injection:
            if "REVERSE_SHELL_PAYLOAD" in inj_findings or "COMMAND_INJECTION_TRIGGER" in inj_findings:
                score_sum += 0.90
                findings.append("COMMAND_ATTACK")
            elif "JAILBREAK_ATTEMPT" in inj_findings:
                score_sum += 0.85
                findings.append("JAILBREAK")
            elif "INSTRUCTION_OVERRIDE" in inj_findings:
                score_sum += 0.70
                findings.append("PROMPT_INJECTION")

            if "ROLE_ESCALATION_ATTEMPT" in inj_findings or "PROMPT_LEAKAGE_ATTEMPT" in inj_findings:
                score_sum += 0.20
                findings.append("ROLE_ESCALATION")

        # 2. Evaluate PII findings
        pii_data = summary.get("pii_detection", {})
        has_pii = pii_data.get("has_pii", False)
        detected_pii = pii_data.get("detected_entities", [])

        if has_pii:
            # 0.3 base for PII plus 0.05 for each additional class, capped at 0.55
            pii_weight = min(0.55, 0.30 + (len(detected_pii) - 1) * 0.05)
            score_sum += pii_weight
            findings.append("PII_DISCLOSURE")

        # 3. Evaluate File security findings
        file_data = summary.get("file_security", {})
        is_file_safe = file_data.get("is_safe", True)
        file_threats = file_data.get("detected_threats", [])

        if not is_file_safe:
            for threat in file_threats:
                if "MALWARE_EXTENSION" in threat or "Executable Payload" in threat:
                    score_sum += 0.95
                    findings.append("MALWARE")
                elif "OfficeMacroTrigger" in threat or "HIDDEN_MACRO_ARCHIVE" in threat:
                    score_sum += 0.80
                    findings.append("ACTIVE_OFFICE_MACRO")
                elif "PDFMaliciousTriggers" in threat or "PDF_DYNAMIC_ACTION" in threat:
                    score_sum += 0.80
                    findings.append("PDF_DYNAMIC_TRIGGER")
                else:
                    score_sum += 0.70
                    findings.append("SUSPICIOUS_FILE_STRUCTURE")

        # Cap the final score to 1.0
        final_score = min(1.0, score_sum)

        # Map risk score to policy action and severity (Phase 6)
        if final_score > 0.90:
            action = "BLOCK"
            severity = "CRITICAL"
            reasoning = "Critical security threat vector identified. Gateway protection activated to block transaction."
        elif final_score >= 0.60:
            action = "HUMAN_REVIEW"
            severity = "HIGH"
            reasoning = "High risk security telemetry. Held in administrative verification queue."
        elif final_score >= 0.30:
            action = "REDACTED"
            severity = "MEDIUM"
            reasoning = "PII indicators present. Sanitizing and redacting sensitive data."
        else:
            action = "ALLOW"
            severity = "LOW"
            reasoning = "Gateway evaluation clean. Downstream routing permitted."

        return RiskAssessmentResult(
            overall_risk_score=final_score,
            severity=severity,
            policy_action=action,
            findings=findings,
            decision_reasoning=reasoning
        )
