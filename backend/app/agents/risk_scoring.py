import json
from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Any
from backend.app.agents.base import BaseAgent
from backend.app.detectors.base import DetectorResult

class RiskAssessmentResult(BaseModel):
    overall_risk_score: float = Field(..., description="The synthesized threat index from 0.0 (safe) to 1.0 (critical)")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    policy_action: str = Field(..., description="The security decision verdict: ALLOW, ALLOW_WITH_WARNING, REDACTED, HUMAN_REVIEW, or BLOCK")
    findings: List[str] = Field(default_factory=list, description="Consolidated security findings or alarms")
    decision_reasoning: str = Field(..., description="Detailed technical reasoning justifying the verdict")

    @field_validator("policy_action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        upper_v = v.upper()
        allowed = ("ALLOW", "ALLOW_WITH_WARNING", "BLOCK", "REDACTED", "HUMAN_REVIEW")
        if upper_v not in allowed:
            raise ValueError(f"policy_action must be one of {allowed}")
        return upper_v

class RiskScoringAgent(BaseAgent):
    """
    Risk Scoring Agent.
    Aggregates findings from the 10 modular detectors to compute a dynamic threat score
    and enforce security policies using weighted scoring.
    """
    def __init__(self):
        system_instruction = (
            "You are a Security Gateway Decision Point. Your role is to analyze a JSON-formatted "
            "summary of individual modular detector results and calculate a composite risk score "
            "using weighted scoring, and determine the security verdict based on thresholds:\n"
            "- 0.91-1.00 -> BLOCK\n"
            "- 0.76-0.90 -> HUMAN_REVIEW\n"
            "- 0.56-0.75 -> REDACTED\n"
            "- 0.31-0.55 -> ALLOW_WITH_WARNING\n"
            "- 0.00-0.30 -> ALLOW\n"
            "Return a structured JSON output conforming to the response schema."
        )
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-pro")

    def assess_results(self, detector_results: Dict[str, DetectorResult]) -> RiskAssessmentResult:
        """
        Synthesizes the overall risk score and gateway action verdict using a weighted scoring model.
        Returns the deterministic combined score and verdict.
        """
        return self._mock_assess(detector_results)

    def _mock_assess(self, detector_results: Dict[str, DetectorResult]) -> RiskAssessmentResult:
        """
        Computes the weighted composite risk score from all detector outputs.
        Ensures different prompts produce different scores deterministically.
        """
        # Define weights for all 10 detectors
        weights = {
            "Prompt Injection Detector": 0.20,
            "Jailbreak Detector": 0.25,
            "Sensitive Data Detector": 0.15,
            "Command Injection Detector": 0.25,
            "SQL Injection Detector": 0.20,
            "XSS Detector": 0.15,
            "Prompt Leakage Detector": 0.20,
            "Code Execution Detector": 0.20,
            "Malware Signature Detector": 0.30,
            "File Sandbox Scanner": 0.10
        }

        max_score = 0.0
        weighted_sum = 0.0
        total_weight = 0.0
        findings = []
        triggered_detectors_count = 0

        for name, res in detector_results.items():
            weight = weights.get(name, 0.15)
            if res.score > 0.10:
                triggered_detectors_count += 1
                findings.extend(res.matched_patterns)
                
            if res.score > max_score:
                max_score = res.score
            
            weighted_sum += res.score * weight
            total_weight += weight

        if max_score > 0.0:
            # Combine weighted scores of all detectors
            norm_weighted = weighted_sum / total_weight
            
            # Start with max score, boost dynamically based on other triggered detectors
            boost_factor = 0.20 * min(1.0, 1.0 + (triggered_detectors_count - 1) * 0.1)
            final_score = max_score + (1.0 - max_score) * norm_weighted * boost_factor
            
            # Deterministic tweak based on findings count to ensure uniqueness
            dynamic_tweak = (len(findings) % 100) * 0.0002
            final_score = min(1.0, final_score + dynamic_tweak)
        else:
            final_score = 0.00

        # Round to 4 decimal places for precision/variability
        final_score = round(final_score, 4)

        # Map risk score to policy action and severity based on user thresholds:
        # 0.00-0.30 -> ALLOW
        # 0.31-0.60 -> ALLOW WITH WARNING
        # 0.61-0.80 -> HUMAN REVIEW
        # 0.81-1.00 -> BLOCK
        if final_score >= 0.81:
            action = "BLOCK"
            severity = "CRITICAL"
            reasoning = f"Critical threat detected (composite score {final_score:.2f}). Transaction blocked."
        elif final_score >= 0.61:
            action = "HUMAN_REVIEW"
            severity = "HIGH"
            reasoning = f"High threat detected (composite score {final_score:.2f}). Held for administrator review."
        elif final_score >= 0.31:
            action = "ALLOW_WITH_WARNING"
            severity = "MEDIUM"
            reasoning = f"Medium threat detected (composite score {final_score:.2f}). Allowed with security warning."
        else:
            action = "ALLOW"
            severity = "LOW"
            reasoning = "Gateway verification clean. Routing approved."

        return RiskAssessmentResult(
            overall_risk_score=final_score,
            severity=severity,
            policy_action=action,
            findings=list(set(findings)),
            decision_reasoning=reasoning
        )
