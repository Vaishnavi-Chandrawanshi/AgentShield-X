import streamlit as st
import uuid

try:
    from frontend.utils import evaluate_prompt_api
except ModuleNotFoundError:
    from utils import evaluate_prompt_api

def render_chat_interface():
    st.markdown("""
        <div style="padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1e293b;">
            <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">🛡️ AI Security Testing Playground</h2>
            <p style="color: #64748b; font-size: 14px; margin: 0;">Audit downstream prompts and attachments against security filters before proxying execution.</p>
        </div>
    """, unsafe_allow_html=True)

    # Browser Session setup
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())
        
    st.sidebar.markdown(f"""
        <div style='background-color: #131a26; border: 1px solid #1e293b; padding: 12px; border-radius: 4px; margin-bottom: 15px;'>
            <span style='font-size: 11px; color: #64748b; font-weight: 600; text-transform: uppercase;'>Sandbox Session ID</span>
            <div style='font-family: monospace; font-size: 11px; color: #cbd5e1; margin-top: 4px;'>{st.session_state.session_id}</div>
        </div>
    """, unsafe_allow_html=True)

    if st.sidebar.button("🔄 Rotate Session ID", use_container_width=True):
        st.session_state.session_id = str(uuid.uuid4())
        st.rerun()

    # Play Console Layout
    col_inp, col_opts = st.columns([2.2, 1])

    with col_inp:
        prompt = st.text_area(
            "Security Input Query Payload:",
            placeholder="Type your LLM prompt here for screening...",
            height=160,
            help="The prompt text to audit for injection attempts, jailbreaks, overrides, and PII disclosures."
        )

    with col_opts:
        st.markdown("<p style='font-size: 14px; font-weight: 500; margin-bottom: 5px;'>Attachment Sandbox Scanning</p>", unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Upload Document:",
            type=["pdf", "docx", "xlsx"],
            help="Files undergo YARA macro rule checks, signature checking, and text extraction."
        )

    submit_button = st.button("🛡️ Execute Gateway Screening", use_container_width=True)

    if submit_button:
        if not prompt.strip() and not uploaded_file:
            st.warning("Please provide a prompt input or upload a sandboxed document.")
            return

        with st.spinner("Executing parallel multi-agent threat checks..."):
            file_bytes = None
            file_name = None
            if uploaded_file:
                file_bytes = uploaded_file.getvalue()
                file_name = uploaded_file.name

            # Run API evaluate
            result = evaluate_prompt_api(
                prompt=prompt,
                session_id=st.session_state.session_id,
                file_bytes=file_bytes,
                file_name=file_name
            )

        if "error" in result:
            st.error(f"Gateway Communication Error: {result['error']}")
            if "detail" in result:
                st.info(result["detail"])
            return

        # Verdict results parsing
        policy_action = result.get("policy_action", "UNKNOWN")
        risk_score = result.get("overall_risk_score", 0.0)
        message = result.get("message", "")
        sanitized_prompt = result.get("sanitized_prompt", "")
        execution_output = result.get("execution_output", "")
        events = result.get("events_triggered", [])

        # Strict Security Styling Palette
        if policy_action == "ALLOW":
            border_c = "#10b981"  # Emerald
            bg_c = "rgba(16, 185, 129, 0.05)"
            text_color = "#10b981"
            action_label = "ALLOW — SAFE GATEWAY TRANSACTION"
        elif policy_action == "REDACTED":
            border_c = "#3b82f6"  # Blue
            bg_c = "rgba(59, 130, 246, 0.05)"
            text_color = "#3b82f6"
            action_label = "REDACTED — DATA MASKED & PROXIED"
        elif policy_action == "HUMAN_REVIEW":
            border_c = "#f59e0b"  # Amber
            bg_c = "rgba(245, 158, 11, 0.05)"
            text_color = "#f59e0b"
            action_label = "HUMAN_REVIEW — ESCALATED FOR REVIEW"
        else: # BLOCK
            border_c = "#ef4444"  # Red
            bg_c = "rgba(239, 68, 68, 0.05)"
            text_color = "#ef4444"
            action_label = "BLOCK — THREAT MITIGATED"

        st.markdown(f"""
            <div style="background-color: {bg_c}; border: 1px solid {border_c}; padding: 18px; border-radius: 4px; margin: 20px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 15px; font-weight: 700; color: {text_color}; letter-spacing: 0.5px;">{action_label}</span>
                    <span style="font-size: 13px; color: #94a3b8; font-family: monospace; font-weight: bold;">Risk Index: {risk_score:.3f}</span>
                </div>
                <p style="font-size: 13px; color: #e2e8f0; margin: 0; line-height: 1.5;">{message}</p>
            </div>
        """, unsafe_allow_html=True)

        # Step 2: Render Multi-Agent Screening Timeline
        st.markdown("<h4 style='color: #f8fafc; font-weight: 600; margin-top: 25px;'>🔍 Agent Screening Log Findings</h4>", unsafe_allow_html=True)
        
        # We render three columns corresponding to each sub-agent findings
        col_f1, col_f2, col_f3 = st.columns(3)
        
        # Check matching event targets
        has_inject_event = any(e.get("agent_source") == "INJECTION" for e in events)
        has_pii_event = any(e.get("agent_source") == "PII" for e in events)
        has_file_event = any(e.get("agent_source") == "FILE" for e in events)

        with col_f1:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 5px;'>Injection Screen</p>", unsafe_allow_html=True)
            if has_inject_event:
                inj_evt = [e for e in events if e.get("agent_source") == "INJECTION"][0]
                st.markdown(f"""
                    <div style="border-left: 3px solid #ef4444; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px; overflow-y: auto;">
                        <span style="font-size: 11px; font-weight: bold; color: #ef4444;">THREAT INDEXED</span><br/>
                        <span style="font-size: 12px; color: #e2e8f0;">{inj_evt.get('trigger_type')}</span>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                    <div style="border-left: 3px solid #10b981; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px;">
                        <span style="font-size: 11px; font-weight: bold; color: #10b981;">CLEAN</span><br/>
                        <span style="font-size: 12px; color: #64748b;">No adversarial patterns identified.</span>
                    </div>
                """, unsafe_allow_html=True)

        with col_f2:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 5px;'>Data Masker (PII)</p>", unsafe_allow_html=True)
            if has_pii_event:
                pii_evt = [e for e in events if e.get("agent_source") == "PII"][0]
                st.markdown(f"""
                    <div style="border-left: 3px solid #3b82f6; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px; overflow-y: auto;">
                        <span style="font-size: 11px; font-weight: bold; color: #3b82f6;">PII DETECTED</span><br/>
                        <span style="font-size: 12px; color: #e2e8f0;">{pii_evt.get('trigger_type')}</span>
                    </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown("""
                    <div style="border-left: 3px solid #10b981; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px;">
                        <span style="font-size: 11px; font-weight: bold; color: #10b981;">CLEAN</span><br/>
                        <span style="font-size: 12px; color: #64748b;">No sensitive parameters matched.</span>
                    </div>
                """, unsafe_allow_html=True)

        with col_f3:
            st.markdown("<p style='font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 5px;'>File Sandbox</p>", unsafe_allow_html=True)
            if uploaded_file:
                if has_file_event:
                    file_evt = [e for e in events if e.get("agent_source") == "FILE"][0]
                    st.markdown(f"""
                        <div style="border-left: 3px solid #ef4444; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px; overflow-y: auto;">
                            <span style="font-size: 11px; font-weight: bold; color: #ef4444;">UNSAFE FILE</span><br/>
                            <span style="font-size: 12px; color: #e2e8f0;">{file_evt.get('trigger_type')}</span>
                        </div>
                    """, unsafe_allow_html=True)
                else:
                    st.markdown("""
                        <div style="border-left: 3px solid #10b981; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px;">
                            <span style="font-size: 11px; font-weight: bold; color: #10b981;">SAFE FILE</span><br/>
                            <span style="font-size: 12px; color: #64748b;">Yara macro scan clean. Text extracted.</span>
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.markdown("""
                    <div style="border-left: 3px solid #475569; background-color: #131a26; padding: 12px; border-radius: 4px; height: 100px;">
                        <span style="font-size: 11px; font-weight: bold; color: #475569;">BYPASSED</span><br/>
                        <span style="font-size: 12px; color: #64748b;">No document attachment provided.</span>
                    </div>
                """, unsafe_allow_html=True)

        st.markdown("<br/>", unsafe_allow_html=True)

        # Downstream execution print
        if policy_action in ("ALLOW", "REDACTED"):
            if policy_action == "REDACTED" and sanitized_prompt:
                with st.expander("📝 View Redacted Prompt Sent to LLM"):
                    st.code(sanitized_prompt, language="markdown")
                    
            st.markdown("<p style='font-size: 14px; font-weight: 600; color: #f8fafc; margin-bottom: 6px;'>💬 Downstream LLM Response Payload</p>", unsafe_allow_html=True)
            st.code(execution_output, language="markdown")
            
        elif policy_action == "HUMAN_REVIEW":
            st.warning("Manual Verification Hold: This request triggered security anomalies and is held in the verification queue. Admin approval is required.")
            
        elif policy_action == "BLOCK":
            st.error("Access Forbidden: Transaction blocked by active AgentShield-X safety policies.")
