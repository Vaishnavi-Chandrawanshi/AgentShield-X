import streamlit as st
import pandas as pd
import datetime

try:
    from frontend.utils import fetch_audit_logs
except ModuleNotFoundError:
    from utils import fetch_audit_logs

def render_analytics_dashboard():
    st.markdown("""
        <div style="padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1e293b;">
            <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">📊 Security Threat Analytics</h2>
            <p style="color: #64748b; font-size: 14px; margin: 0;">Real-time threat intelligence feeds, gateway transaction volumes, and agent policy audit trends.</p>
        </div>
    """, unsafe_allow_html=True)

    # Compile registry check
    if "token" not in st.session_state or not st.session_state.token:
        st.warning("Please sign in to view analytics data.")
        return

    with st.spinner("Compiling security gateway logs..."):
        logs = fetch_audit_logs(st.session_state.token)

    if not logs:
        st.markdown("""
            <div style="background-color: #131a26; border: 1px dashed #1e293b; padding: 40px; border-radius: 6px; text-align: center;">
                <h4 style="color: #64748b; margin-bottom: 8px;">No Audit Data Available</h4>
                <p style="color: #475569; margin: 0; font-size: 14px;">Gateway analytics will populate once transaction requests are processed through the security pipeline.</p>
            </div>
        """, unsafe_allow_html=True)
        return

    # Process logs in Pandas
    data = []
    events_list = []
    
    for log in logs:
        try:
            # Safely parse timestamp
            ts = datetime.datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))
        except Exception:
            ts = datetime.datetime.now()
            
        data.append({
            "timestamp": ts,
            "date": ts.date(),
            "hour": ts.hour,
            "policy_action": log["policy_action"],
            "risk_score": log["overall_risk_score"]
        })
        
        # Flatten events
        for evt in log.get("events", []):
            events_list.append({
                "agent_source": evt.get("agent_source", "UNKNOWN"),
                "severity": evt.get("severity_level", "INFO"),
                "trigger_type": evt.get("trigger_type", "")
            })

    df = pd.DataFrame(data)
    df_events = pd.DataFrame(events_list)

    # 1. Calculate cybersecurity enterprise metrics
    total_tx = len(df)
    blocked_count = len(df[df["policy_action"] == "BLOCK"])
    
    # Extract sub-agent details
    injection_count = 0
    pii_count = 0
    file_scans_failed = 0
    
    if not df_events.empty:
        injection_count = len(df_events[df_events["agent_source"] == "INJECTION"])
        pii_count = len(df_events[df_events["agent_source"] == "PII"])
        file_scans_failed = len(df_events[df_events["agent_source"] == "FILE"])
        
    avg_risk = df["risk_score"].mean()

    # 2. Render KPI cards grid
    col1, col2, col3 = st.columns(3)
    col4, col5, col6 = st.columns(3)

    with col1:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Total Requests Proxy</span>
                <div class="metric-val" style="color: #3b82f6; margin-top: 5px;">{total_tx}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col2:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Threats Blocked</span>
                <div class="metric-val" style="color: #ef4444; margin-top: 5px;">{blocked_count}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col3:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Prompt Injections</span>
                <div class="metric-val" style="color: #f59e0b; margin-top: 5px;">{injection_count}</div>
            </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">PII Disclosures Redacted</span>
                <div class="metric-val" style="color: #10b981; margin-top: 5px;">{pii_count}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col5:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Malicious Files Quarantined</span>
                <div class="metric-val" style="color: #a78bfa; margin-top: 5px;">{file_scans_failed}</div>
            </div>
        """, unsafe_allow_html=True)
        
    with col6:
        st.markdown(f"""
            <div class="sec-card">
                <span style="font-size: 12px; color: #64748b; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px;">Average Gateway Risk</span>
                <div class="metric-val" style="color: #cbd5e1; margin-top: 5px;">{avg_risk:.3f}</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # 3. Charts Section
    st.markdown("<h4 style='color: #f8fafc; font-weight: 600; margin-bottom: 12px;'>📊 Performance Auditing Feeds</h4>", unsafe_allow_html=True)
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.markdown("<p style='color: #94a3b8; font-size: 13px; font-weight: 500;'>Policy Actions Enforcement Distribution</p>", unsafe_allow_html=True)
        action_counts = df["policy_action"].value_counts().reset_index()
        action_counts.columns = ["Action Verdict", "Volume"]
        # Custom color mapped bar chart
        st.bar_chart(action_counts.set_index("Action Verdict"), color="#3b82f6")

    with chart_col2:
        st.markdown("<p style='color: #94a3b8; font-size: 13px; font-weight: 500;'>Security Event Severity Counts</p>", unsafe_allow_html=True)
        if df_events.empty:
            st.info("No policy alarms triggered in the current audit logging cycle.")
        else:
            sev_counts = df_events["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity Level", "Events"]
            st.bar_chart(sev_counts.set_index("Severity Level"), color="#ef4444")

    # 4. Trend Line Chart
    st.markdown("<hr style='border-color: #1e293b; margin: 30px 0;'/>", unsafe_allow_html=True)
    st.markdown("<h4 style='color: #f8fafc; font-weight: 600;'>📈 Gateway Risk Index Trend</h4>", unsafe_allow_html=True)
    
    # Calculate daily average risk trend
    trend_df = df.groupby("date")["risk_score"].mean().reset_index(name="Risk Score Index")
    trend_df["date"] = trend_df["date"].astype(str)
    st.line_chart(trend_df.set_index("date"), color="#6366f1")
