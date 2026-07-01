import streamlit as st
import datetime
import textwrap
import httpx

try:
    from frontend.utils import (
        fetch_pending_approvals,
        submit_approval_action,
        BACKEND_URL,
    )
except ModuleNotFoundError:
    from utils import (
        fetch_pending_approvals,
        submit_approval_action,
        BACKEND_URL,
    )

def render_html(html_str):
    """Clean HTML string from leading/trailing whitespaces per line and render it safely."""
    cleaned = "\n".join(line.strip() for line in html_str.split("\n") if line.strip())
    st.markdown(cleaned, unsafe_allow_html=True)

def render_approval_console():
    render_html("""
        <div style="padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1e293b;">
            <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">🔑 Security Review & Approvals</h2>
            <p style="color: #64748b; font-size: 14px; margin: 0;">Audit and resolve transaction requests held in queue by active threat classification rules.</p>
        </div>
    """)

    # Compile registry check
    if "token" not in st.session_state or not st.session_state.token:
        st.warning("Please sign in to access the verification console.")
        return

    # Load Queue from backend API
    with st.spinner("Fetching pending transactions from firewall queue..."):
        tickets = fetch_pending_approvals(st.session_state.token)

    col_title, col_ref = st.columns([5, 1.2])
    with col_ref:
        if st.button("🔄 Refresh Queue", use_container_width=True):
            st.rerun()

    if not tickets:
        empty_check_svg = """
        <svg viewBox="0 0 200 120" width="120" height="70" style="display: block; margin: 0 auto 12px auto;" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <radialGradient id="greenGlow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="rgba(16, 185, 129, 0.2)"/>
              <stop offset="100%" stop-color="rgba(0,0,0,0)"/>
            </radialGradient>
          </defs>
          <circle cx="100" cy="60" r="45" fill="url(#greenGlow)" />
          <path d="M100 82s20-10 20-25V42l-20-8-20 8v15c0 15 20 25 20 25z" fill="none" stroke="#10b981" stroke-width="2.5" />
          <path d="M93 58 l5 5 l10 -10" stroke="#10b981" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round" />
          <circle cx="100" cy="60" r="35" fill="none" stroke="rgba(16, 185, 129, 0.1)" stroke-width="1" stroke-dasharray="4 4"/>
        </svg>
        """
        render_html(f"""
            <div style="background-color: rgba(16, 185, 129, 0.03); border: 1px dashed rgba(16, 185, 129, 0.25); padding: 35px; border-radius: 8px; text-align: center; margin-top: 20px;">
                {empty_check_svg}
                <h4 style="color: #10b981; margin-bottom: 6px; font-weight: 700;">No Pending Verifications</h4>
                <p style="color: #64748b; margin: 0; font-size: 13.5px;">All proxy queries are passing active safety thresholds. Gateway secure & healthy.</p>
            </div>
        """)
        return

    st.write(f"Showing **{len(tickets)}** transaction(s) requiring manual administrator clearance:")

    for idx, ticket in enumerate(tickets):
        ticket_id = str(ticket["approval_id"])
        log_id = str(ticket["log_id"])
        created_at_raw = ticket["created_at"]
        
        # Parse timestamp safely
        try:
            created_at = datetime.datetime.fromisoformat(created_at_raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            created_at = created_at_raw

        # Load parent log details to decrypt raw text and extract event details
        log_detail = None
        try:
            response = httpx.get(
                f"{BACKEND_URL}/api/v1/audit/logs/{log_id}",
                headers={"Authorization": f"Bearer {st.session_state.token}"},
                timeout=5.0
            )
            if response.status_code == 200:
                log_detail = response.json()
        except Exception:
            pass

        # Generate Transaction ID: TX-YYYYMMDD-HHMMSS
        try:
            clean_ts = created_at_raw.replace("Z", "").split(".")[0]
            dt = datetime.datetime.fromisoformat(clean_ts)
        except Exception:
            dt = datetime.datetime.now()
        tx_id = f"TX-{dt.strftime('%Y%m%d')}-{dt.strftime('%H%M%S')}"

        # Resolve details dynamically
        user_display = "Unknown User"
        composite_risk = 0.0
        threat_type = "Verification Hold"
        triggered_detector = "N/A"
        confidence_val = 0.90
        reason_text = "Transaction held by gateway policy for manual review."

        if log_detail:
            user_display = log_detail.get("session_id", "API Session Client")
            composite_risk = log_detail.get("overall_risk_score", 0.0)
            events = log_detail.get("events", [])
            if events:
                primary = events[0]
                for e in events:
                    if e.get("severity_level") in ("CRITICAL", "HIGH"):
                        primary = e
                        break
                threat_type = primary.get("trigger_type", "Violation Triggered")
                triggered_detector = primary.get("agent_source", "Gateway Interceptor")
                details = primary.get("details") or {}
                confidence_val = details.get("confidence", 0.92)
                reason_text = details.get("reason", "Anomalous patterns flagged.")
                # Clean HTML tags from reason text for presentation
                import re
                reason_text = re.sub(r'<[^>]*>', ' ', reason_text)

        render_html(f"""
            <div style="background-color: #131a26; border: 1px solid #1e293b; padding: 18px; border-radius: 6px; margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-bottom: 15px;">
                    <span style="font-weight: bold; color: #cbd5e1; font-size: 13.5px; font-family: 'JetBrains Mono', monospace;">TRANSACTION ID: {tx_id}</span>
                    <span style="font-size: 12px; color: #64748b;">Triggered: {created_at}</span>
                </div>
                <div style="font-size: 13px; color: #94a3b8; line-height: 1.6; display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                    <div>👤 <b>User:</b> {user_display}</div>
                    <div>📊 <b>Composite Risk:</b> <span style="color: #ef4444; font-weight: bold;">{composite_risk:.4f}</span></div>
                    <div>🚨 <b>Threat Type:</b> {threat_type}</div>
                    <div>🛡️ <b>Triggered Detector:</b> {triggered_detector}</div>
                    <div>📈 <b>Confidence:</b> {confidence_val * 100:.0f}%</div>
                    <div style="grid-column: span 2;">📝 <b>Reason:</b> {reason_text}</div>
                </div>
            </div>
        """)

        # View Details state tracker
        details_key = f"show_details_{ticket_id}"
        if details_key not in st.session_state:
            st.session_state[details_key] = False

        if st.session_state[details_key]:
            if log_detail:
                with st.container():
                    st.markdown("**Proposed Query Payload:**")
                    st.code(log_detail.get("raw_input", "[Unavailable]"), language="markdown")
                    if log_detail.get("sanitized_input"):
                        st.markdown("**Sanitized Input Draft:**")
                        st.code(log_detail.get("sanitized_input"), language="markdown")
            else:
                st.info("Loading payload details from secure log vault...")

        # Review comments
        review_notes = st.text_area(
            f"Review Verdict Comments (Ticket {ticket_id[:8]}):",
            placeholder="Add decision reasoning or justification details for audit trail compliance...",
            key=f"notes_{ticket_id}"
        )

        c1, c2, c3 = st.columns([1.2, 1.2, 1.5])
        with c1:
            if st.button("✅ Approve", key=f"app_{ticket_id}", use_container_width=True):
                with st.spinner("Clearing transaction..."):
                    success = submit_approval_action(
                        st.session_state.token,
                        ticket_id,
                        "APPROVED",
                        st.session_state.user.get("username", "admin"),
                        review_notes
                    )
                    if success:
                        st.success("Query cleared successfully!")
                        st.rerun()
                    else:
                        st.error("Failed to commit approval verdict.")
        with c2:
            if st.button("❌ Reject", key=f"rej_{ticket_id}", use_container_width=True):
                with st.spinner("Rejecting transaction..."):
                    success = submit_approval_action(
                        st.session_state.token,
                        ticket_id,
                        "REJECTED",
                        st.session_state.user.get("username", "admin"),
                        review_notes
                    )
                    if success:
                        st.error("Query block verdict committed.")
                        st.rerun()
                    else:
                        st.error("Failed to commit rejection verdict.")
        with c3:
            if st.button("👁️ View Details", key=f"details_btn_{ticket_id}", use_container_width=True):
                st.session_state[details_key] = not st.session_state[details_key]
                st.rerun()
        
        render_html("<hr style='border-color: #1e293b; margin: 20px 0;'/>")
