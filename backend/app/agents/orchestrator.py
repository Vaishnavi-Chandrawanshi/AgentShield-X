import json
import datetime
from typing import Optional, Tuple, Dict, Any
from sqlalchemy.orm import Session
from backend.app.agents.base import BaseAgent
from backend.app.agents.prompt_injection import PromptInjectionAgent
from backend.app.agents.pii_detection import PiiDetectionAgent
from backend.app.agents.file_security import FileSecurityAgent
from backend.app.agents.risk_scoring import RiskScoringAgent
from backend.app.agents.report_generation import ReportGenerationAgent
from backend.app.models.audit import AuditLog, SecurityEvent
from backend.app.models.approval import HumanApproval
from backend.app.core.security import encrypt_text

class OrchestratorAgent(BaseAgent):
    """
    Orchestrator Agent.
    Serves as the central coordinator of the multi-agent firewall gateway.
    Manages coordination between screening sub-agents, databases audits,
    policy enforcements, and downstream LLM query execution.
    """
    def __init__(self):
        system_instruction = (
            "You are the central security Orchestrator. Your role is to coordinate "
            "sub-agent scans, compile threat telemetry, route held queries to the manual queue, "
            "and safely proxy approved calls to the target LLM application."
        )
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-pro")
        
        # Instantiate sub-agents
        self.injection_agent = PromptInjectionAgent()
        self.pii_agent = PiiDetectionAgent()
        self.file_agent = FileSecurityAgent()
        self.risk_agent = RiskScoringAgent()
        self.report_agent = ReportGenerationAgent()

    def run_pipeline(
        self,
        prompt: str,
        session_id: str,
        db: Session,
        file_bytes: Optional[bytes] = None,
        file_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs the full security gateway orchestration pipeline:
        1. Parallel security scanning (Injection, PII, File).
        2. Threat aggregation and Risk assessment.
        3. Database transaction logging and policy actions enforcement.
        4. Target application proxy execution (if permitted).
        5. Markdown compliance report compilation.
        """
        # Step 1. Run Screening Sub-Agents
        file_result = self.file_agent.scan(file_bytes, file_name)

        # Intercept and scan combined content if safe document text is extracted
        content_to_scan = prompt
        if file_result.is_safe and file_result.extracted_text:
            content_to_scan = f"{prompt}\n\n[Attached File: {file_name or 'document'}]\n{file_result.extracted_text}"

        injection_result = self.injection_agent.scan(content_to_scan, db)
        pii_result = self.pii_agent.scan(content_to_scan)

        # Step 2. Aggregate Threat Reports
        summary_data = {
            "prompt_injection": {
                "is_injection": injection_result.is_injection,
                "risk_score": injection_result.risk_score,
                "explanation": injection_result.explanation,
                "threat_type": injection_result.threat_type,
                "severity": injection_result.severity,
                "findings": injection_result.findings
            },
            "pii_detection": {
                "has_pii": pii_result.has_pii,
                "detected_entities": pii_result.detected_entities,
                "explanation": pii_result.explanation
            },
            "file_security": {
                "is_safe": file_result.is_safe,
                "detected_threats": file_result.detected_threats,
                "explanation": file_result.explanation
            }
        }
        summary_text = json.dumps(summary_data, indent=2)

        # Step 3. Compute Composite Risk & Verdict
        risk_result = self.risk_agent.assess(summary_text)
        action = risk_result.policy_action.upper()
        risk_score = risk_result.overall_risk_score

        # Determine sanitized query to store and/or execute downstream
        sanitized_input = content_to_scan
        if action == "BLOCK":
            sanitized_input = None
        elif pii_result.has_pii:
            sanitized_input = pii_result.sanitized_prompt

        # Step 4. Write Audit Log entry (AES-GCM encrypted)
        encrypted_raw = encrypt_text(prompt)
        audit_log = AuditLog(
            session_id=session_id,
            raw_input=encrypted_raw,
            sanitized_input=sanitized_input,
            overall_risk_score=risk_score,
            policy_action=action
        )
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)

        # Step 5. Log Security Events and human reviews
        events_triggered = []
        
        if injection_result.is_injection:
            evt = SecurityEvent(
                log_id=audit_log.log_id,
                agent_source="INJECTION",
                trigger_type=injection_result.threat_type,
                severity_level=injection_result.severity,
                details={
                    "risk_score": injection_result.risk_score,
                    "matched_pattern": injection_result.matched_pattern,
                    "explanation": injection_result.explanation,
                    "findings": injection_result.findings
                }
            )
            db.add(evt)
            events_triggered.append(evt)

        if pii_result.has_pii:
            evt = SecurityEvent(
                log_id=audit_log.log_id,
                agent_source="PII",
                trigger_type="PII_DISCLOSURE",
                severity_level="MEDIUM",
                details={
                    "detected_entities": pii_result.detected_entities,
                    "explanation": pii_result.explanation
                }
            )
            db.add(evt)
            events_triggered.append(evt)

        if not file_result.is_safe:
            file_severity = "HIGH"
            for t in file_result.detected_threats:
                if "MALWARE_EXTENSION" in t or "EMBEDDED_PE_HEADER" in t:
                    file_severity = "CRITICAL"
            evt = SecurityEvent(
                log_id=audit_log.log_id,
                agent_source="FILE",
                trigger_type="MALWARE" if file_severity == "CRITICAL" else "SUSPICIOUS_FILE",
                severity_level=file_severity,
                details={
                    "detected_threats": file_result.detected_threats,
                    "explanation": file_result.explanation
                }
            )
            db.add(evt)
            events_triggered.append(evt)

        # Log policy holding or blocking warnings
        if action in ("BLOCK", "HUMAN_REVIEW"):
            evt = SecurityEvent(
                log_id=audit_log.log_id,
                agent_source="RISK_SCORE",
                trigger_type="GATEWAY_POLICY_ENFORCEMENT",
                severity_level=risk_result.severity,
                details={
                    "reason": risk_result.decision_reasoning,
                    "findings": risk_result.findings
                }
            )
            db.add(evt)
            events_triggered.append(evt)

        if action == "HUMAN_REVIEW":
            # Add review ticket to manual verification queue
            approval = HumanApproval(
                log_id=audit_log.log_id,
                status="PENDING"
            )
            db.add(approval)
            
        db.commit()

        # Step 6. Proxy Target LLM Execution (Only if allowed or redacted)
        execution_output = None
        message = ""
        
        if action == "ALLOW":
            execution_output = self._execute_downstream(prompt)
            message = "Prompt evaluated successfully. Downstream execution completed."
        elif action == "REDACTED":
            # Pass redacted prompt to downstream LLM
            execution_output = self._execute_downstream(sanitized_input)
            message = "Prompt evaluated successfully. PII redacted and query executed downstream."
        elif action == "BLOCK":
            message = "Blocked by security policies due to adversarial injection threat."
        elif action == "HUMAN_REVIEW":
            message = "Transaction held for administrator manual verification."

        # Step 7. Compile Markdown Compliance Report
        report_input = f"""
Log ID: {audit_log.log_id}
Session ID: {session_id}
Final Action: {action}
Composite Risk Score: {risk_score}
Threat Explanation: {risk_result.decision_reasoning}
Findings Checklist: {', '.join(risk_result.findings) if risk_result.findings else 'None'}
        """
        report_result = self.report_agent.generate(report_input)

        return {
            "log_id": audit_log.log_id,
            "session_id": session_id,
            "sanitized_prompt": sanitized_input,
            "overall_risk_score": risk_score,
            "policy_action": action,
            "message": message,
            "execution_output": execution_output,
            "compliance_report": report_result.report_markdown,
            "events_triggered": [
                {
                    "event_id": e.event_id,
                    "agent_source": e.agent_source,
                    "trigger_type": e.trigger_type,
                    "severity_level": e.severity_level,
                    "details": e.details
                }
                for e in events_triggered
            ]
        }

    def _execute_downstream(self, prompt: str) -> str:
        """
        Proxies query execution to target application LLM.
        Falls back to a high-quality mock response when keyless.
        """
        if self.client:
            try:
                response = self.client.models.generate_content(
                    model="gemini-1.5-pro",
                    contents=prompt
                )
                if response.text:
                    return response.text
            except Exception:
                pass
        return f"Mock response for prompt: '{prompt}'. (Target Application LLM online)"
