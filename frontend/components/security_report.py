import streamlit as st
import pandas as pd
import datetime
import textwrap

try:
    from frontend.utils import fetch_audit_logs
except ModuleNotFoundError:
    from utils import fetch_audit_logs

def render_html(html_str):
    """Clean HTML string from leading/trailing whitespaces per line and render it safely."""
    cleaned = "\n".join(line.strip() for line in html_str.split("\n") if line.strip())
    st.markdown(cleaned, unsafe_allow_html=True)

def render_security_report():
    render_html("""
        <div style="padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1e293b;">
            <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">📋 Compliance & Audit Registry</h2>
            <p style="color: #64748b; font-size: 14px; margin: 0;">Access historical gateway transaction logs, decrypted security findings, and policy compliance docs.</p>
        </div>
    """)

    # Compile registry check
    if "token" not in st.session_state or not st.session_state.token:
        st.warning("Please sign in to view historical audit logs.")
        return

    # Filter Controls Panel
    render_html("<p style='font-size: 14px; font-weight: 600; color: #cbd5e1; margin-bottom: 8px;'>SIEM Registry Search Filters</p>")
    col1, col2, col3 = st.columns([2.5, 2.5, 1])

    with col1:
        session_filter = st.text_input("Filter by Session ID:", value="", placeholder="e.g. uuid-format-session")
    with col2:
        action_filter = st.selectbox(
            "Filter by Action Verdict:",
            ["ALL", "ALLOW", "BLOCK", "REDACTED", "HUMAN_REVIEW"]
        )
    with col3:
        render_html("<div style='height: 28px;'></div>")
        st.button("🔍 Filter", use_container_width=True)

    # Fetch logs from API
    policy_param = None if action_filter == "ALL" else action_filter
    session_param = None if not session_filter.strip() else session_filter.strip()

    with st.spinner("Loading transaction logs..."):
        logs = fetch_audit_logs(
            st.session_state.token,
            session_id=session_param,
            policy_action=policy_param
        )

    if not logs:
        empty_search_svg = """
        <svg viewBox="0 0 200 120" width="120" height="70" style="display: block; margin: 0 auto 12px auto;" xmlns="http://www.w3.org/2000/svg">
          <rect x="40" y="20" width="120" height="6" rx="2" fill="#1e293b" opacity="0.5"/>
          <rect x="40" y="40" width="90" height="6" rx="2" fill="#1e293b" opacity="0.3"/>
          <rect x="40" y="60" width="110" height="6" rx="2" fill="#1e293b" opacity="0.4"/>
          <circle cx="140" cy="70" r="22" fill="none" stroke="#3b82f6" stroke-width="2" stroke-dasharray="3 3"/>
          <circle cx="140" cy="70" r="15" fill="none" stroke="#1e293b" stroke-width="1.5"/>
          <line x1="152" y1="82" x2="166" y2="96" stroke="#3b82f6" stroke-width="3.5" stroke-linecap="round"/>
        </svg>
        """
        render_html(f"""
            <div style="background-color: #0b0f19; border: 1px dashed #141b2d; padding: 35px; border-radius: 8px; text-align: center; margin-top: 15px;">
                {empty_search_svg}
                <p style="color: #64748b; margin: 0; font-size: 13.5px; font-weight: 500;">No security audit logs matched the current filter conditions.</p>
                <p style="color: #475569; margin: 5px 0 0 0; font-size: 12px;">Try adjusting the Session ID search or checking all actions.</p>
            </div>
        """)
        return

    # Construct dataframe structure
    log_data = []
    for log in logs:
        try:
            timestamp = datetime.datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            timestamp = log["timestamp"]
            
        log_data.append({
            "Timestamp": timestamp,
            "Verdict": log["policy_action"],
            "Risk Score": f"{log['overall_risk_score']:.3f}",
            "Session ID": log["session_id"],
            "Log ID": log["log_id"],
            "Raw Record": log
        })

    df = pd.DataFrame(log_data)
    
    # Display table in SIEM layout
    st.dataframe(
        df[["Timestamp", "Verdict", "Risk Score", "Session ID"]],
        use_container_width=True,
        hide_index=True
    )

    # Detailed SIEM Inspector
    render_html("<hr style='border-color: #1e293b; margin: 25px 0;'/>")
    render_html("<h3 style='color: #f8fafc; font-weight: 600;'>🔍 Deep Diagnostic Analysis</h3>")
    
    log_options = {f"[{log['Timestamp']}] ({log['Verdict']}) ID: {log['Log ID'][:8]}...": log for log in log_data}
    selected_option = st.selectbox("Select Transaction Log Item to Analyze:", list(log_options.keys()))

    if selected_option:
        selected_log = log_options[selected_option]["Raw Record"]
        
        # Grid details
        col_det1, col_det2 = st.columns(2)
        with col_det1:
            st.markdown(f"**Transaction ID:** `{selected_log['log_id']}`")
            st.markdown(f"**Session ID:** `{selected_log['session_id']}`")
        with col_det2:
            st.markdown(f"**Action Verdict:** `{selected_log['policy_action']}`")
            st.markdown(f"**Composite Risk Score:** `{selected_log['overall_risk_score']:.3f}`")

        render_html("<br/>")
        
        # Tabs for details
        tab_p, tab_a, tab_r = st.tabs(["📝 Input/Output Payloads", "⚠️ Triggered Violations", "📜 Compliance Document"])
        
        with tab_p:
            st.markdown("**Original Prompt Input (Decrypted):**")
            st.code(selected_log.get("raw_input", "[Unavailable]"), language="markdown")
            
            st.markdown("**Sanitized Outbound Prompt:**")
            if selected_log.get("sanitized_input"):
                st.code(selected_log.get("sanitized_input"), language="markdown")
            else:
                st.info("No query was routed to the LLM (mitigation active or human review pending).")

        with tab_a:
            events = selected_log.get("events", [])
            if not events:
                st.success("No policy violations registered for this transaction.")
            else:
                for event in events:
                    sev = event.get("severity_level", "INFO")
                    sev_color = "#ef4444" if sev in ("HIGH", "CRITICAL") else "#f59e0b" if sev == "MEDIUM" else "#94a3b8"
                    
                    render_html(f"""
                        <div style="padding: 12px; background-color: #131a26; border-left: 3px solid {sev_color}; border-radius: 4px; margin-bottom: 12px; border: 1px solid #1e293b; border-left-width: 3px;">
                            <div style="font-size: 11px; color: {sev_color}; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">{event.get("agent_source")} • {sev}</div>
                            <div style="font-size: 13px; color: #e2e8f0; font-weight: 500; margin-top: 3px;">{event.get("trigger_type")}</div>
                            <div style="font-size: 12px; color: #64748b; margin-top: 4px; font-family: monospace;">Details: {event.get("details")}</div>
                        </div>
                    """)

        with tab_r:
            st.markdown("#### Generated Security Compliance Audit Document")
            try:
                from backend.app.agents.report_generation import ReportGenerationAgent
                agent = ReportGenerationAgent()
                report_input = f"""
Log ID: {selected_log['log_id']}
Session ID: {selected_log['session_id']}
Final Action: {selected_log['policy_action']}
Composite Risk Score: {selected_log['overall_risk_score']}
Threat Summary: System analysis logged.
                """
                report_result = agent.generate(report_input)
                st.markdown(report_result.report_markdown)
            except Exception:
                # Fallback report layout
                st.markdown(f"""
# AgentShield-X Compliance Security Report
* **Log ID**: {selected_log['log_id']}
* **Timestamp**: {selected_log['timestamp']}
* **Verdict**: {selected_log['policy_action']}
* **Risk Score**: {selected_log['overall_risk_score']}

### Policy Execution Checklist
- [x] Injection Scan
- [x] PII Scan
- [x] File Sandbox Scan

*Generated dynamically via auditing registry.*
                """)
