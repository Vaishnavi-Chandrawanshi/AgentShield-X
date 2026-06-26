import streamlit as st
import datetime
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

def render_approval_console():
    st.markdown("""
        <div style="padding: 10px 0px; margin-bottom: 20px; border-bottom: 1px solid #1e293b;">
            <h2 style="color: #f8fafc; margin-bottom: 4px; font-weight: 700;">🔑 Security Review & Approvals</h2>
            <p style="color: #64748b; font-size: 14px; margin: 0;">Audit and resolve transaction requests held in queue by active threat classification rules.</p>
        </div>
    """, unsafe_allow_html=True)

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
        st.markdown("""
            <div style="background-color: rgba(16, 185, 129, 0.05); border: 1px solid #10b981; padding: 30px; border-radius: 6px; text-align: center; margin-top: 20px;">
                <h4 style="color: #10b981; margin-bottom: 8px;">No Actions Pending</h4>
                <p style="color: #64748b; margin: 0; font-size: 14px;">All proxy queries are passing safety thresholds automatically. Gateway healthy.</p>
            </div>
        """, unsafe_allow_html=True)
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

        st.markdown(f"""
            <div style="background-color: #131a26; border: 1px solid #1e293b; padding: 18px; border-radius: 6px; margin-bottom: 25px;">
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #1e293b; padding-bottom: 10px; margin-bottom: 15px;">
                    <span style="font-weight: bold; color: #cbd5e1; font-size: 13px;">CASE REF: {ticket_id[:18]}...</span>
                    <span style="font-size: 12px; color: #64748b;">Triggered: {created_at}</span>
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown(f"**Parent Audit Transaction ID:** `{log_id}`")

        # Decrypted Prompt Details container
        if log_detail:
            with st.expander("🔍 Inspect Proposed Input Query Payload (Decrypted)", expanded=True):
                st.code(log_detail.get("raw_input", "[Unavailable]"), language="markdown")
            
            # Show alarms triggered
            events = log_detail.get("events", [])
            if events:
                st.markdown("**Violated Policies & Alarms:**")
                for event in events:
                    sev = event.get("severity_level", "INFO")
                    color = "#ef4444" if sev in ("HIGH", "CRITICAL") else "#f59e0b" if sev == "MEDIUM" else "#94a3b8"
                    st.markdown(f"⚠️ **{event.get('agent_source')}** • <span style='color: {color}; font-weight: bold;'>{sev}</span>: {event.get('trigger_type')}", unsafe_allow_html=True)
        else:
            st.info("Loading transaction payload details...")

        # Review verdict controls
        review_notes = st.text_area(
            f"Review Verdict Comments (Ticket {ticket_id[:8]}):",
            placeholder="Add decision reasoning or justification details for audit trail compliance...",
            key=f"notes_{ticket_id}"
        )
        
        c1, c2, c3 = st.columns([1.2, 1.2, 2.5])
        with c1:
            if st.button("✅ Approve Query", key=f"app_{ticket_id}", use_container_width=True):
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
            if st.button("❌ Reject Query", key=f"rej_{ticket_id}", use_container_width=True):
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
        
        st.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'/>", unsafe_allow_html=True)
