import streamlit as st
import uuid
import time
import textwrap

try:
    from frontend.utils import evaluate_prompt_api
except ModuleNotFoundError:
    from utils import evaluate_prompt_api

def render_html(html_str, sidebar=False):
    """Clean HTML string from leading/trailing whitespaces per line and render it safely."""
    cleaned = "\n".join(line.strip() for line in html_str.split("\n") if line.strip())
    if sidebar:
        st.sidebar.markdown(cleaned, unsafe_allow_html=True)
    else:
        st.markdown(cleaned, unsafe_allow_html=True)

def get_detector_icon(detector_name):
    icons = {
        "Prompt Injection Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>""",
        "Jailbreak Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>""",
        "Command Injection Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>""",
        "SQL Injection Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path><path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3"></path></svg>""",
        "XSS Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><polyline points="16 18 22 12 16 6"></polyline><polyline points="8 6 2 12 8 18"></polyline><line x1="10" y1="21" x2="14" y2="3"></line></svg>""",
        "Prompt Leakage Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path></svg>""",
        "Code Execution Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>""",
        "Sensitive Data Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>""",
        "Malware Signature Detector": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>""",
        "File Sandbox Scanner": """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>"""
    }
    return icons.get(detector_name, """<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:4px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="16"></line><line x1="8" y1="12" x2="16" y2="12"></line></svg>""")

def make_risk_gauge(score):
    if score >= 0.75:
        color = "#ef4444"
        label = "CRITICAL"
        bg = "rgba(239, 68, 68, 0.12)"
    elif score >= 0.35:
        color = "#f59e0b"
        label = "MODERATE"
        bg = "rgba(245, 158, 11, 0.12)"
    else:
        color = "#10b981"
        label = "SECURE"
        bg = "rgba(16, 185, 129, 0.12)"
        
    width_pct = max(2, min(100, int(score * 100)))
    
    return f"""
    <div style="background-color: rgba(0,0,0,0.2); border: 1px solid #1e293b; border-radius: 8px; padding: 12px; margin-top: 5px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 10px; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;">Synthesized Risk</span>
            <span style="font-size: 10px; background-color: {bg}; color: {color}; padding: 2px 6px; border-radius: 4px; font-weight: bold; font-family: 'JetBrains Mono', monospace;">{label} ({score:.3f})</span>
        </div>
        <div class="progress-bar-container">
            <div class="progress-bar-fill" style="width: {width_pct}%; background-color: {color}; box-shadow: 0 0 8px {color};"></div>
        </div>
    </div>
    """

def make_confidence_bar(confidence):
    conf_pct = int(confidence * 100)
    if confidence > 0.8:
        color = "#3b82f6"
    elif confidence > 0.5:
        color = "#6366f1"
    else:
        color = "#94a3b8"
        
    return f"""
    <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-family: 'JetBrains Mono', monospace; font-size: 11px; width: 28px; font-weight: bold; color: #cbd5e1;">{conf_pct}%</span>
        <div class="progress-bar-container" style="flex-grow: 1; height: 5px; background-color: #1e293b; border-radius: 3px; overflow: hidden;">
            <div class="progress-bar-fill" style="width: {conf_pct}%; background-color: {color}; height: 100%; transition: width 0.5s ease-in-out;"></div>
        </div>
    </div>
    """

def render_chat_interface():
    # 1. Custom CSS overrides
    render_html("""
        <style>
        /* Google Fonts Inter & JetBrains Mono */
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;700&display=swap');
        
        /* Playground Hero Banner */
        .playground-hero {
            background: linear-gradient(135deg, rgba(13, 18, 34, 0.7) 0%, rgba(6, 9, 17, 0.95) 100%) !important;
            border: 1px solid #1c263b !important;
            border-radius: 12px !important;
            padding: 24px !important;
            margin-bottom: 25px !important;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.03) !important;
            transition: all 0.3s ease !important;
        }
        .playground-hero:hover {
            border-color: #3b82f6 !important;
            box-shadow: 0 12px 35px rgba(59, 130, 246, 0.12) !important;
        }
        .playground-hero-badge {
            display: inline-block !important;
            background-color: rgba(59, 130, 246, 0.12) !important;
            color: #60a5fa !important;
            border: 1px solid rgba(59, 130, 246, 0.25) !important;
            padding: 4px 10px !important;
            border-radius: 20px !important;
            font-size: 10px !important;
            font-weight: 700 !important;
            letter-spacing: 1px !important;
            margin-bottom: 12px !important;
            text-transform: uppercase !important;
        }
        .playground-hero-title {
            font-size: 24px !important;
            font-weight: 800 !important;
            color: #f8fafc !important;
            margin-bottom: 8px !important;
            letter-spacing: -0.5px !important;
        }
        .playground-hero-desc {
            font-size: 13.5px !important;
            color: #94a3b8 !important;
            line-height: 1.6 !important;
            margin: 0 !important;
        }

        /* Section Headings */
        .playground-section-header {
            font-size: 14px !important;
            font-weight: 700 !important;
            color: #f8fafc !important;
            margin-top: 20px !important;
            margin-bottom: 12px !important;
            letter-spacing: 0.5px !important;
            text-transform: uppercase !important;
            display: flex !important;
            align-items: center !important;
            gap: 6px !important;
        }

        /* Detector Cards styling */
        .detector-card {
            background: linear-gradient(135deg, #0b0f19 0%, #070a13 100%) !important;
            border: 1px solid #141b2d !important;
            border-radius: 10px !important;
            padding: 16px !important;
            height: 110px !important;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2) !important;
            transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
            position: relative !important;
            overflow: hidden !important;
        }
        .detector-card:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3) !important;
        }
        .detector-card.clean { border-left: 4px solid #10b981 !important; }
        .detector-card.clean:hover { border-color: #10b981 !important; }
        .detector-card.threat { border-left: 4px solid #ef4444 !important; }
        .detector-card.threat:hover { border-color: #ef4444 !important; }
        .detector-card.bypass { border-left: 4px solid #475569 !important; }
        .detector-card.bypass:hover { border-color: #475569 !important; }

        /* Verdict Banner */
        .verdict-banner {
            border-radius: 10px !important;
            padding: 20px !important;
            margin: 25px 0 !important;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3) !important;
            transition: all 0.3s ease !important;
            position: relative !important;
            overflow: hidden !important;
        }
        .verdict-banner.allow {
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.02) 100%) !important;
            border: 1px solid rgba(16, 185, 129, 0.25) !important;
            border-left: 6px solid #10b981 !important;
        }
        .verdict-banner.allow_warning {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.02) 100%) !important;
            border: 1px solid rgba(245, 158, 11, 0.25) !important;
            border-left: 6px solid #f59e0b !important;
        }
        .verdict-banner.redacted {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.08) 0%, rgba(59, 130, 246, 0.02) 100%) !important;
            border: 1px solid rgba(59, 130, 246, 0.25) !important;
            border-left: 6px solid #3b82f6 !important;
        }
        .verdict-banner.review {
            background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.02) 100%) !important;
            border: 1px solid rgba(245, 158, 11, 0.25) !important;
            border-left: 6px solid #f59e0b !important;
        }
        .verdict-banner.block {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(239, 68, 68, 0.02) 100%) !important;
            border: 1px solid rgba(239, 68, 68, 0.25) !important;
            border-left: 6px solid #ef4444 !important;
        }

        /* Custom Table for Detectors */
        .detector-table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0;
            background-color: #0b0f19;
            border: 1px solid #141b2d;
            border-radius: 8px;
            overflow: hidden;
            margin-top: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .detector-table th {
            background-color: #0d1222;
            color: #94a3b8;
            text-align: left;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 14px 16px;
            border-bottom: 1px solid #141b2d;
        }
        .detector-table td {
            padding: 14px 16px;
            border-bottom: 1px solid #141b2d;
            font-size: 13px;
            color: #cbd5e1;
        }
        .detector-table tr:last-child td {
            border-bottom: none;
        }
        .detector-table tr:hover {
            background-color: #0e1424;
        }

        /* Progress bars */
        .progress-bar-container {
            width: 100%;
            background-color: #1e293b;
            border-radius: 3px;
            overflow: hidden;
            height: 6px;
            display: inline-block;
            vertical-align: middle;
        }
        .progress-bar-fill {
            height: 100%;
            border-radius: 3px;
        }
        </style>
    """)

    # Hero / Enterprise Section
    render_html("""
        <div class="playground-hero">
            <span class="playground-hero-badge">🔒 Secure Gateway Sandbox</span>
            <h1 class="playground-hero-title">AI Security Testing & Sandbox Playground</h1>
            <p class="playground-hero-desc">
                Evaluate and screen user prompts and document attachments against AgentShield-X security guardrails in real-time. 
                Our multi-agent screening pipelines intercept transaction payloads, analyze for vulnerabilities, mask PII, and apply administrative security actions prior to downstream LLM execution.
            </p>
        </div>
    """)

    # Browser Session setup
    if "session_id" not in st.session_state:
        st.session_state.session_id = str(uuid.uuid4())
        
    render_html(f"""
        <div style='background-color: #0b0f19; border: 1px solid #141b2d; padding: 14px; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.15);'>
            <span style='font-size: 11px; color: #64748b; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;'>Sandbox Session ID</span>
            <div style='font-family: "JetBrains Mono", monospace; font-size: 11px; color: #cbd5e1; margin-top: 6px; word-break: break-all;'>{st.session_state.session_id}</div>
        </div>
    """, sidebar=True)

    if st.sidebar.button("🔄 Rotate Session ID", use_container_width=True):
        st.session_state.session_id = str(uuid.uuid4())
        st.rerun()

    # Layout inputs
    col_inp, col_opts = st.columns([2.0, 1.0])

    with col_inp:
        render_html("<div class='playground-section-header'>📝 Prompt Inspection Payload</div>")
        prompt = st.text_area(
            "Security Input Query Payload:",
            placeholder="Type your LLM prompt here for screening...",
            height=160,
            label_visibility="collapsed",
            help="The prompt text to audit for injection attempts, jailbreaks, overrides, and PII disclosures."
        )

    with col_opts:
        render_html("<div class='playground-section-header'>📁 Document Attachment Sandbox</div>")
        uploaded_file = st.file_uploader(
            "Upload Document:",
            type=["pdf", "docx", "xlsx"],
            label_visibility="collapsed",
            help="Files undergo YARA macro rule checks, signature checking, and text extraction."
        )
        render_html("<p style='font-size: 11px; color: #64748b; margin-top: -5px;'>Supported: PDF, DOCX, XLSX. Max size 5MB.</p>")

    render_html("<div style='height: 10px;'></div>")
    submit_button = st.button("🛡️ Execute Gateway Screening Engine", use_container_width=True)

    if submit_button:
        if not prompt.strip() and not uploaded_file:
            st.warning("Please provide a prompt input or upload a sandboxed document.")
            return

        # Modern loading pipeline progress timeline
        with st.status("🛡️ Securing LLM Gateway Proxy...", expanded=True) as status:
            st.write("🔑 Decrypting input payloads & parsing metadata...")
            time.sleep(0.3)
            st.write("🔍 Evaluating exploit signatures & prompt injections...")
            time.sleep(0.4)
            st.write("🔒 Scanning for PII disclosures & sensitive leaks...")
            time.sleep(0.3)
            
            if uploaded_file:
                st.write("📂 Performing sandbox macro rule checks on attachment...")
                time.sleep(0.4)
            st.write("⚖️ Applying active security policy configurations...")
            
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
            
            status.update(label="🛡️ Gateway Screening Complete. Policy outcome processed.", state="complete", expanded=False)

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

        # Verdict Panel Setup
        if policy_action == "ALLOW":
            color_class = "allow"
            icon_verdict = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="#10b981" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:8px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 11 11 13 15 9"></polyline></svg>'
            action_label = "ALLOW — SAFE TRANSIT"
        elif policy_action == "ALLOW_WITH_WARNING":
            color_class = "allow_warning"
            icon_verdict = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="#f59e0b" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:8px;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>'
            action_label = "WARN — ANOMALIES PROXIED"
        elif policy_action == "REDACTED":
            color_class = "redacted"
            icon_verdict = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="#3b82f6" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:8px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>'
            action_label = "REDACTED — DATA MASKED"
        elif policy_action == "HUMAN_REVIEW":
            color_class = "review"
            icon_verdict = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="#f59e0b" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:8px;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>'
            action_label = "REVIEW — HELD FOR APPROVAL"
        else: # BLOCK
            color_class = "block"
            icon_verdict = '<svg viewBox="0 0 24 24" width="24" height="24" stroke="#ef4444" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:8px;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>'
            action_label = "BLOCK — THREAT MITIGATED"

        verdict_html = f"""
        <div class="verdict-banner {color_class}">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px;">
                <div style="flex: 1; min-width: 250px;">
                    <div style="display: flex; align-items: center; margin-bottom: 8px;">
                        {icon_verdict}
                        <span style="font-size: 15px; font-weight: 800; letter-spacing: 0.5px;">{action_label}</span>
                    </div>
                    <p style="font-size: 13.5px; color: #cbd5e1; margin: 0; line-height: 1.5;">{message}</p>
                </div>
                <div style="width: 220px;">
                    {make_risk_gauge(risk_score)}
                </div>
            </div>
        </div>
        """
        render_html(verdict_html)

        # Multi-Agent Screening Timeline Log
        render_html("<div class='playground-section-header'>🔍 Sub-Agent Logging Telemetry</div>")
        col_f1, col_f2, col_f3 = st.columns(3)
        
        has_inject_event = any(e.get("agent_source") == "INJECTION" for e in events)
        has_pii_event = any(e.get("agent_source") == "PII" for e in events)
        has_file_event = any(e.get("agent_source") == "FILE" for e in events)

        # Icons for grids
        svg_bug = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:6px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 9.9-1"></path></svg>'
        svg_shield = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>'
        svg_file_code = '<svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:6px;"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line></svg>'

        with col_f1:
            if has_inject_event:
                inj_evt = [e for e in events if e.get("agent_source") == "INJECTION"][0]
                html_inj = f"""
                <div class="detector-card threat">
                    <span style="font-size: 11px; font-weight: bold; color: #ef4444; display: flex; align-items: center;">
                        {svg_bug} INJECTION ALARM
                    </span>
                    <div style="font-size: 13px; color: #f8fafc; font-weight: 600; margin-top: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{inj_evt.get('trigger_type')}</div>
                    <div style="font-size: 11px; color: #ef4444; margin-top: 4px; font-family: monospace;">Jailbreak / Override detected</div>
                </div>
                """
            else:
                html_inj = f"""
                <div class="detector-card clean">
                    <span style="font-size: 11px; font-weight: bold; color: #10b981; display: flex; align-items: center;">
                        {svg_shield} INJECTION FILTER
                    </span>
                    <div style="font-size: 13px; color: #cbd5e1; font-weight: 500; margin-top: 8px;">CLEAN / SECURE</div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 4px;">No adversarial injections flagged.</div>
                </div>
                """
            render_html(html_inj)

        with col_f2:
            if has_pii_event:
                pii_evt = [e for e in events if e.get("agent_source") == "PII"][0]
                html_pii = f"""
                <div class="detector-card threat" style="border-left-color: #3b82f6 !important;">
                    <span style="font-size: 11px; font-weight: bold; color: #3b82f6; display: flex; align-items: center;">
                        <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle; margin-right:6px;"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg> PII LEAK FILTER
                    </span>
                    <div style="font-size: 13px; color: #f8fafc; font-weight: 600; margin-top: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{pii_evt.get('trigger_type')}</div>
                    <div style="font-size: 11px; color: #3b82f6; margin-top: 4px; font-family: monospace;">Sensitive attributes redacted</div>
                </div>
                """
            else:
                html_pii = f"""
                <div class="detector-card clean">
                    <span style="font-size: 11px; font-weight: bold; color: #10b981; display: flex; align-items: center;">
                        {svg_shield} DATA MASKING (PII)
                    </span>
                    <div style="font-size: 13px; color: #cbd5e1; font-weight: 500; margin-top: 8px;">CLEAN / SECURE</div>
                    <div style="font-size: 11px; color: #64748b; margin-top: 4px;">No private disclosures identified.</div>
                </div>
                """
            render_html(html_pii)

        with col_f3:
            if uploaded_file:
                if has_file_event:
                    file_evt = [e for e in events if e.get("agent_source") == "FILE"][0]
                    html_file = f"""
                    <div class="detector-card threat">
                        <span style="font-size: 11px; font-weight: bold; color: #ef4444; display: flex; align-items: center;">
                            {svg_file_code} FILE SANDBOX ALARM
                        </span>
                        <div style="font-size: 13px; color: #f8fafc; font-weight: 600; margin-top: 8px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{file_evt.get('trigger_type')}</div>
                        <div style="font-size: 11px; color: #ef4444; margin-top: 4px; font-family: monospace;">Unsafe macros or code lines</div>
                    </div>
                    """
                else:
                    html_file = f"""
                    <div class="detector-card clean">
                        <span style="font-size: 11px; font-weight: bold; color: #10b981; display: flex; align-items: center;">
                            {svg_file_code} FILE SANDBOX
                        </span>
                        <div style="font-size: 13px; color: #cbd5e1; font-weight: 500; margin-top: 8px;">SAFE ATTACHMENT</div>
                        <div style="font-size: 11px; color: #64748b; margin-top: 4px;">YARA macro scan clean. Text extracted.</div>
                    </div>
                    """
            else:
                html_file = f"""
                <div class="detector-card bypass">
                    <span style="font-size: 11px; font-weight: bold; color: #64748b; display: flex; align-items: center;">
                        {svg_file_code} FILE SANDBOX
                    </span>
                    <div style="font-size: 13px; color: #475569; font-weight: 500; margin-top: 8px;">SCAN BYPASSED</div>
                    <div style="font-size: 11px; color: #475569; margin-top: 4px;">No document attachment supplied.</div>
                </div>
                """
            render_html(html_file)

        render_html("<br/>")

        # 10 Detector Detailed Findings
        all_detector_details = result.get("all_detector_details", [])
        if all_detector_details:
            render_html("<div class='playground-section-header'>📊 Granular Detector Posture & Telemetry</div>")
            
            table_html = """
            <table class="detector-table">
                <thead>
                    <tr>
                        <th style="padding: 12px 16px;">Detector Name</th>
                        <th style="padding: 12px 16px; text-align: center; width: 120px;">Threat Score</th>
                        <th style="padding: 12px 16px; width: 180px;">Confidence Score</th>
                        <th style="padding: 12px 16px; width: 150px;">Matched Evidence</th>
                        <th style="padding: 12px 16px;">Explanation</th>
                    </tr>
                </thead>
                <tbody>
            """
            for det in all_detector_details:
                score = det.get("score", 0.0)
                conf = det.get("confidence", 0.0)
                name = det.get("detector_name", "Unknown Detector")
                evidence = det.get("matched_evidence", "None")
                explanation = det.get("explanation", "")
                
                icon_svg = get_detector_icon(name)
                
                if score >= 0.75:
                    score_badge = f'<span style="background-color: rgba(239, 68, 68, 0.15); color: #ef4444; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-family: \'JetBrains Mono\', monospace; border: 1px solid rgba(239, 68, 68, 0.2);">{score:.2f}</span>'
                elif score >= 0.30:
                    score_badge = f'<span style="background-color: rgba(245, 158, 11, 0.15); color: #f59e0b; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-family: \'JetBrains Mono\', monospace; border: 1px solid rgba(245, 158, 11, 0.2);">{score:.2f}</span>'
                else:
                    score_badge = f'<span style="background-color: rgba(16, 185, 129, 0.15); color: #10b981; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-family: \'JetBrains Mono\', monospace; border: 1px solid rgba(16, 185, 129, 0.2);">{score:.2f}</span>'
                    
                conf_bar = make_confidence_bar(conf)
                
                if evidence == "None" or not evidence:
                    if score < 0.10:
                        evidence_html = '<span style="color: #475569; font-family: monospace;">None</span>'
                    else:
                        evidence_html = '<span style="color: #475569; font-family: monospace;">—</span>'
                else:
                    evidence_html = f'<span style="color: #f59e0b; font-family: \'JetBrains Mono\', monospace; font-size: 11px; background-color: rgba(245,158,11,0.1); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(245,158,11,0.3); font-weight: bold;">{evidence}</span>'
                
                table_html += f"""
                    <tr>
                        <td style="font-weight: 600; color: #f8fafc; display: flex; align-items: center; gap: 4px; border-bottom: none;">
                            {icon_svg} {name}
                        </td>
                        <td style="text-align: center;">{score_badge}</td>
                        <td>{conf_bar}</td>
                        <td>{evidence_html}</td>
                        <td style="line-height: 1.4; color: #94a3b8; font-size: 12.5px;">{explanation}</td>
                    </tr>
                """
            table_html += """
                </tbody>
            </table>
            """
            render_html(table_html)
            render_html("<br/>")

        # Downstream execution print
        if policy_action in ("ALLOW", "ALLOW_WITH_WARNING", "REDACTED"):
            if policy_action == "ALLOW_WITH_WARNING":
                st.warning("⚠️ Gateway Warning: Proceed with caution. Low-risk anomalies were identified in the payload.")
            if policy_action == "REDACTED" and sanitized_prompt:
                with st.expander("📝 View Redacted Prompt Sent to Downstream LLM"):
                    st.code(sanitized_prompt, language="markdown")
                    
            render_html("<div class='playground-section-header'>💬 Downstream LLM Response Payload</div>")
            st.code(execution_output, language="markdown")
            
        elif policy_action == "HUMAN_REVIEW":
            st.warning("⏳ Manual Verification Hold: This request triggered security anomalies and is held in the verification queue. Admin approval is required.")
            
        elif policy_action == "BLOCK":
            st.error("🚫 Access Forbidden: Transaction blocked by active AgentShield-X safety policies.")
