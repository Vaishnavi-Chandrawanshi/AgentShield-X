from pydantic import BaseModel, Field
from backend.app.agents.base import BaseAgent

class SecurityReportResult(BaseModel):
    report_markdown: str = Field(..., description="The formatted markdown representing the compliance security audit report")
    compliance_passed: bool = Field(..., description="True if the transaction satisfies organizational safety guidelines")

class ReportGenerationAgent(BaseAgent):
    """
    Report Generation Agent.
    Compiles consolidated transaction logs and threat verdicts into
    compliance markdown audits.
    """
    def __init__(self):
        system_instruction = (
            "You are a compliance security auditor. Your task is to compile a detailed transaction "
            "security audit report. The input will contain gateway execution stats, risk scores, "
            "triggered alerts, and final policies. Organize these details into a clean markdown document "
            "including headers, metadata tables, security checklists, and clear verdicts. "
            "Set compliance_passed to True if the final policy action is ALLOW or REDACTED, "
            "and to False if the policy is BLOCK or HUMAN_REVIEW. Return a structured JSON response."
        )
        # Routed to Gemini 1.5 Pro for rich markdown rendering and summary logic
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-pro")

    def generate(self, audit_details_text: str) -> SecurityReportResult:
        """
        Generates the security compliance report from transaction audit details.
        """
        return self._generate_structured(
            prompt=audit_details_text,
            schema_cls=SecurityReportResult,
            mock_fallback_handler=self._mock_report_generation
        )

    def _mock_report_generation(self, details_text: str) -> SecurityReportResult:
        """Generates a structured markdown audit report string as local fallback."""
        # Simple string analysis to map compliance state
        text_lower = details_text.lower()
        
        is_blocked = "block" in text_lower
        is_review = "human_review" in text_lower
        
        compliance_passed = not (is_blocked or is_review)
        
        status_label = "APPROVED" if compliance_passed else "ALERT / FLAGGED"
        if is_blocked:
            status_label = "BLOCKED"
        elif is_review:
            status_label = "HELD FOR REVIEW"

        report_md = f"""# AgentShield-X Security Audit Log
## Compliance & Gateway Analysis

### 1. Transaction Summary
* **Status**: **{status_label}**
* **Compliance Assessment**: {"PASSED" if compliance_passed else "FAILED"}
* **Audit Metadata**: `{details_text.strip()}`

### 2. Policy Enforcement Checklist
- [x] Input Prompt Injection Scan completed
- [x] Input PII Disclosure Scan completed
- [{"x" if is_blocked or is_review or "pii" in text_lower else " "}] Alert Warnings Triggered
- [{"x" if compliance_passed else " "}] Safe execution validation passed

### 3. Conclusion
This transaction has been analyzed against the organization's downstream LLM firewall policies. 
Verdict decision applied and recorded in compliance history.
"""
        return SecurityReportResult(
            report_markdown=report_md,
            compliance_passed=compliance_passed
        )
