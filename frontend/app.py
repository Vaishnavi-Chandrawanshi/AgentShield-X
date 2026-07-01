import streamlit as st
import base64
import textwrap

try:
    from frontend.utils import (
        get_auth_token,
        register_user_api,
        fetch_current_user,
        update_profile_api,
        change_password_api,
        forgot_password_api,
        reset_password_api,
    )
except ModuleNotFoundError:
    from utils import (
        get_auth_token,
        register_user_api,
        fetch_current_user,
        update_profile_api,
        change_password_api,
        forgot_password_api,
        reset_password_api,
    )

def render_html(html_str, sidebar=False):
    """Clean HTML string from leading/trailing whitespaces per line and render it safely."""
    cleaned = "\n".join(line.strip() for line in html_str.split("\n") if line.strip())
    if sidebar:
        st.sidebar.markdown(cleaned, unsafe_allow_html=True)
    else:
        st.markdown(cleaned, unsafe_allow_html=True)

# Base64 SVG Favicon
favicon_svg = """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="32" height="32">
  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="#3b82f6" stroke="#10b981" stroke-width="2"/>
</svg>
"""
favicon_b64 = "data:image/svg+xml;base64," + base64.b64encode(favicon_svg.encode('utf-8')).decode('utf-8')

# Configure page layout and visual parameters
st.set_page_config(
    page_title="AgentShield-X | Enterprise LLM Gateway",
    page_icon=favicon_b64,
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise cybersecurity design overrides (CrowdStrike / Defender style)
render_html("""
    <style>
    /* Google Fonts Inter Integration */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* Base App Container & Background */
    .stApp {
        background-color: #05080e !important;
        color: #f8fafc !important;
    }
    
    /* Global Container Padding Adjustments */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }

    /* Dashboard Header Card */
    .dashboard-header {
        background: linear-gradient(135deg, #0d121f 0%, #060910 100%);
        border: 1px solid #141b2d;
        border-radius: 8px;
        padding: 24px 30px;
        margin-bottom: 28px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.05);
    }
    .dashboard-title {
        color: #f8fafc;
        font-weight: 700;
        font-size: 26px;
        margin: 0 0 6px 0 !important;
        letter-spacing: -0.5px;
        background: linear-gradient(90deg, #f8fafc 0%, #cbd5e1 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .dashboard-subtitle {
        color: #64748b;
        font-size: 13.5px;
        margin: 0 !important;
        line-height: 1.5;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #060910 !important;
        border-right: 1px solid #141b2d !important;
    }
    [data-testid="stSidebar"] .block-container {
        padding-top: 1.5rem !important;
    }
    
    /* Custom Sidebar Logo */
    .sidebar-logo {
        font-weight: 800;
        font-size: 20px;
        background: linear-gradient(90deg, #3b82f6 0%, #10b981 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 4px;
    }

    /* Style sidebar radio panel navigation */
    [data-testid="stSidebar"] div[role="radiogroup"] {
        background-color: transparent !important;
        gap: 8px !important;
        padding-top: 10px;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label {
        background-color: #0b0f19 !important;
        border: 1px solid #141b2d !important;
        padding: 12px 14px !important;
        border-radius: 8px !important;
        margin-bottom: 2px !important;
        width: 100% !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
        cursor: pointer !important;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2) !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background-color: #111a30 !important;
        border-color: #3b82f6 !important;
        transform: translateX(2px) !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] {
        background: linear-gradient(90deg, rgba(59, 130, 246, 0.15) 0%, rgba(59, 130, 246, 0.05) 100%) !important;
        border-color: #3b82f6 !important;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.15) !important;
    }
    /* Hide radio button circle */
    [data-testid="stSidebar"] div[role="radiogroup"] label div[dir="ltr"] {
        display: none !important;
    }
    /* Active typography */
    [data-testid="stSidebar"] div[role="radiogroup"] label[data-checked="true"] span {
        color: #60a5fa !important;
        font-weight: 600 !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label span {
        color: #94a3b8 !important;
        font-size: 13.5px !important;
        transition: color 0.2s ease !important;
    }
    [data-testid="stSidebar"] div[role="radiogroup"] label:hover span {
        color: #f8fafc !important;
    }

    /* Cybersecurity Minimalist Card Elements */
    .sec-card {
        background: linear-gradient(135deg, #0e1422 0%, #090c15 100%);
        border: 1px solid #1a2336;
        padding: 22px 24px;
        border-radius: 8px;
        margin-bottom: 20px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.05);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
    }
    .sec-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.05);
    }
    
    /* Left border highlights for different card types */
    .sec-card.blue { border-left: 4px solid #3b82f6; }
    .sec-card.red { border-left: 4px solid #ef4444; }
    .sec-card.orange { border-left: 4px solid #f59e0b; }
    .sec-card.green { border-left: 4px solid #10b981; }
    .sec-card.violet { border-left: 4px solid #a78bfa; }
    .sec-card.slate { border-left: 4px solid #94a3b8; }
    
    .sec-card.blue:hover { border-color: #3b82f6; }
    .sec-card.red:hover { border-color: #ef4444; }
    .sec-card.orange:hover { border-color: #f59e0b; }
    .sec-card.green:hover { border-color: #10b981; }
    .sec-card.violet:hover { border-color: #a78bfa; }
    .sec-card.slate:hover { border-color: #cbd5e1; }

    /* Forms styling */
    div[data-testid="stForm"] {
        background-color: #0b0f19 !important;
        border: 1px solid #1e293b !important;
        border-radius: 8px !important;
        padding: 24px !important;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5), 0 0 1px 1px rgba(255, 255, 255, 0.05) !important;
    }

    /* Standardized button styles */
    div.stButton > button {
        background: linear-gradient(180deg, #2563eb 0%, #1d4ed8 100%) !important;
        color: white !important;
        border: 1px solid #3b82f6 !important;
        border-radius: 6px !important;
        padding: 10px 20px !important;
        font-weight: 600 !important;
        font-size: 14px !important;
        letter-spacing: 0.2px;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.1) !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
    }
    div.stButton > button:hover {
        background: linear-gradient(180deg, #1d4ed8 0%, #1e40af 100%) !important;
        border-color: #60a5fa !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.3) !important;
    }
    div.stButton > button:active {
        transform: translateY(0px) !important;
    }

    /* Approve button style modifier */
    .btn-approve button {
        background: linear-gradient(180deg, #10b981 0%, #059669 100%) !important;
        border-color: #10b981 !important;
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.2) !important;
    }
    .btn-approve button:hover {
        background: linear-gradient(180deg, #059669 0%, #047857 100%) !important;
        border-color: #34d399 !important;
        box-shadow: 0 6px 16px rgba(16, 185, 129, 0.3) !important;
    }

    /* Reject button style modifier */
    .btn-reject button {
        background: linear-gradient(180deg, #ef4444 0%, #dc2626 100%) !important;
        border-color: #ef4444 !important;
        box-shadow: 0 4px 12px rgba(239, 68, 68, 0.2) !important;
    }
    .btn-reject button:hover {
        background: linear-gradient(180deg, #dc2626 0%, #b91c1c 100%) !important;
        border-color: #f87171 !important;
        box-shadow: 0 6px 16px rgba(239, 68, 68, 0.3) !important;
    }

    /* Input widgets integration */
    div[data-baseweb="base-input"], div[data-baseweb="textarea"], div[data-baseweb="select"] {
        border-radius: 8px !important;
        background-color: #0a0d14 !important;
        border: 1px solid #161f30 !important;
        transition: all 0.2s ease !important;
    }
    div[data-baseweb="base-input"]:focus-within, div[data-baseweb="textarea"]:focus-within, div[data-baseweb="select"]:focus-within {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.15) !important;
    }
    div[data-baseweb="base-input"] input, div[data-baseweb="textarea"] textarea {
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif !important;
    }

    /* Native Tabs override */
    div[role="tablist"] {
        border-bottom: 1px solid #141b2d !important;
        background-color: transparent !important;
        gap: 12px !important;
    }
    button[data-baseweb="tab"] {
        color: #94a3b8 !important;
        background-color: transparent !important;
        font-weight: 600 !important;
        padding: 10px 16px !important;
        border: none !important;
        border-bottom: 2px solid transparent !important;
        font-family: 'Inter', sans-serif !important;
        transition: all 0.2s ease !important;
    }
    button[data-baseweb="tab"]:hover {
        color: #f8fafc !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #3b82f6 !important;
        border-bottom: 2px solid #3b82f6 !important;
    }

    /* Expanders styling */
    [data-testid="stExpander"] {
        background-color: #0b0f19 !important;
        border: 1px solid #141b2d !important;
        border-radius: 8px !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15) !important;
    }

    /* File Uploader styling */
    [data-testid="stFileUploader"] {
        border: 1px dashed #1c263b !important;
        background-color: #080c14 !important;
        border-radius: 8px !important;
        padding: 14px !important;
    }

    /* Metric styles */
    .metric-val {
        font-family: 'JetBrains Mono', monospace;
        font-size: 26px;
        font-weight: 700;
        letter-spacing: -0.5px;
    }

    /* Alert / Security Warning Badges */
    .violation-badge {
        display: inline-block;
        padding: 8px 14px;
        background-color: #0a0d14;
        border: 1px solid #161f30;
        border-radius: 6px;
        margin-bottom: 8px;
        font-size: 13.5px;
        color: #cbd5e1;
        width: 100%;
        box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    /* Threat Action Banner alerts */
    .status-banner {
        padding: 20px 24px;
        border-radius: 8px;
        margin: 24px 0;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.25);
    }
    .status-banner-allow {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(16, 185, 129, 0.02) 100%);
        border: 1px solid rgba(16, 185, 129, 0.25);
        border-left: 4px solid #10b981;
    }
    .status-banner-warning {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(245, 158, 11, 0.02) 100%);
        border: 1px solid rgba(245, 158, 11, 0.25);
        border-left: 4px solid #f59e0b;
    }
    .status-banner-redacted {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.08) 0%, rgba(59, 130, 246, 0.02) 100%);
        border: 1px solid rgba(59, 130, 246, 0.25);
        border-left: 4px solid #3b82f6;
    }
    .status-banner-block {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(239, 68, 68, 0.02) 100%);
        border: 1px solid rgba(239, 68, 68, 0.25);
        border-left: 4px solid #ef4444;
    }

    /* Agent log findings cards */
    .agent-card {
        border: 1px solid #141b2d;
        background: linear-gradient(135deg, #0b0f19 0%, #070a10 100%);
        padding: 16px;
        border-radius: 8px;
        height: 120px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.25);
        overflow-y: auto;
        transition: border-color 0.2s ease;
    }
    .agent-card-clean { border-left: 4px solid #10b981; }
    .agent-card-warning { border-left: 4px solid #f59e0b; }
    .agent-card-danger { border-left: 4px solid #ef4444; }
    .agent-card-info { border-left: 4px solid #3b82f6; }
    .agent-card-bypass { border-left: 4px solid #475569; }

    /* Custom Table Styling */
    table.security-table {
        width: 100%;
        border-collapse: separate;
        border-spacing: 0;
        margin-top: 15px;
        background-color: #0b0f19;
        border: 1px solid #141b2d;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    }
    table.security-table th {
        background-color: #0d1322;
        color: #94a3b8;
        text-align: left;
        font-size: 11px;
        font-weight: 650;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        padding: 14px 16px;
        border-bottom: 1px solid #141b2d;
    }
    table.security-table td {
        padding: 14px 16px;
        border-bottom: 1px solid #0d121c;
        font-size: 13.5px;
        color: #cbd5e1;
        line-height: 1.5;
    }
    table.security-table tr:last-child td {
        border-bottom: none;
    }
    table.security-table tr:hover {
        background-color: #111827;
    }
    </style>
""")

# Session Authentication State Management
if "token" not in st.session_state:
    st.session_state.token = None
if "user" not in st.session_state:
    st.session_state.user = None

# If not authenticated, render login/registration portal
if not st.session_state.token:
    login_svg_illustration = """
    <svg viewBox="0 0 400 400" width="280" height="280" xmlns="http://www.w3.org/2000/svg" style="display: block; margin: 0 auto;">
      <defs>
        <radialGradient id="bgGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="rgba(59, 130, 246, 0.15)"/>
          <stop offset="100%" stop-color="rgba(0,0,0,0)"/>
        </radialGradient>
        <linearGradient id="shieldBody" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#2563eb" />
          <stop offset="100%" stop-color="#1d4ed8" />
        </linearGradient>
      </defs>
      <circle cx="200" cy="200" r="180" fill="url(#bgGlow)" />
      <circle cx="200" cy="200" r="140" fill="none" stroke="#141b2d" stroke-width="2" stroke-dasharray="10 15" />
      <circle cx="200" cy="200" r="110" fill="none" stroke="rgba(59, 130, 246, 0.2)" stroke-width="1.5" stroke-dasharray="40 10 5 10" />
      
      <path d="M200 270s55-25 55-65V120l-55-22-55 22v85c0 40 55 65 55 65z" fill="url(#shieldBody)" />
      <path d="M200 250s38-18 38-48v-65l-38-16-38 16v65c0 30 38 48 38 48z" fill="#05080e" opacity="0.6" />
      
      <path d="M90 120 L145 150 M310 120 L255 150 M200 270 L200 320" stroke="#141b2d" stroke-width="2" />
      
      <circle cx="90" cy="120" r="18" fill="#080c14" stroke="#10b981" stroke-width="2" />
      <path d="M85 120 h10 v6 h-10 z M87 120 v-2 a3 3 0 0 1 6 0 v2" stroke="#10b981" stroke-width="1.5" fill="none" />
      
      <circle cx="310" cy="120" r="18" fill="#080c14" stroke="#ef4444" stroke-width="2" />
      <path d="M310 113 v6 M310 124 h.01" stroke="#ef4444" stroke-width="2" stroke-linecap="round" />
      
      <circle cx="200" cy="320" r="18" fill="#080c14" stroke="#3b82f6" stroke-width="2" />
      <path d="M195 320 l3 3 l6 -6" stroke="#3b82f6" stroke-width="1.8" fill="none" />

      <path d="M188 175 l8 8 l16 -16" stroke="#10b981" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
    """
    
    render_html("<div style='height: 20px;'></div>")
    
    col_form, col_brand = st.columns([1.1, 0.9])
    
    with col_brand:
        render_html(f"""
            <div style="text-align: center; padding: 20px 10px; background-color: #060910; border: 1px solid #141b2d; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); margin-top: 10px;">
                <h2 style="color: #f8fafc; font-weight: 800; font-size: 26px; margin-bottom: 2px; letter-spacing: -0.5px;">🛡️ AgentShield-X</h2>
                <p style="color: #3b82f6; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 15px;">Enterprise LLM Security Gateway</p>
                <div style="margin-bottom: 15px;">
                    {login_svg_illustration}
                </div>
                <p style="color: #64748b; font-size: 13px; line-height: 1.6; max-width: 290px; margin: 0 auto;">
                    Active prompt sanitization, data leak redaction, macro checks, and admin reviews running in high-availability security containers.
                </p>
            </div>
        """)
        
    with col_form:
        auth_tab = st.tabs(["🔒 Secure Login", "📝 Register Tenant", "🔑 Credentials Recovery"])
        
        # 1. Login Tab
        with auth_tab[0]:
            with st.form("login_form"):
                render_html("<h4 style='color: #f8fafc; margin-top: 0;'>Sign In to Security Console</h4>")
                login_user = st.text_input("Username:", placeholder="Enter your username")
                login_pwd = st.text_input("Password:", type="password", placeholder="Enter your password")
                submit_login = st.form_submit_button("Sign In", use_container_width=True)
                
                if submit_login:
                    if not login_user or not login_pwd:
                        st.error("Please enter both username and password.")
                    else:
                        token = get_auth_token(login_user, login_pwd)
                        if token:
                            st.session_state.token = token
                            user_details = fetch_current_user(token)
                            st.session_state.user = user_details
                            st.success("Access Granted. Redirecting to console...")
                            st.rerun()
                        else:
                            st.error("Invalid credentials. Access Denied.")
                            
        # 2. Registration Tab
        with auth_tab[1]:
            with st.form("register_form"):
                render_html("<h4 style='color: #f8fafc; margin-top: 0;'>Provision User Profile</h4>")
                reg_user = st.text_input("Choose Username:", placeholder="e.g. sec_analyst")
                reg_email = st.text_input("Enterprise Email:", placeholder="username@organization.com")
                reg_org = st.text_input("Organization Name:", value="Enterprise Root", placeholder="e.g. Acme Corp")
                reg_pwd = st.text_input("Set Password:", type="password", placeholder="Minimum 6 characters")
                submit_register = st.form_submit_button("Register Account", use_container_width=True)
                
                if submit_register:
                    if not reg_user or not reg_email or not reg_pwd:
                        st.error("Username, email, and password are required fields.")
                    elif len(reg_pwd) < 6:
                        st.error("Password must be at least 6 characters long.")
                    else:
                        res = register_user_api(reg_user, reg_email, reg_pwd, reg_org)
                        if res["success"]:
                            st.success("Account created successfully! Please sign in using the Login tab.")
                        else:
                            st.error(f"Registration failed: {res['error']}")
                            
        # 3. Credentials Recovery Tab
        with auth_tab[2]:
            render_html("<h4 style='color: #f8fafc; margin-top: 0;'>Reset Administrative Credentials</h4>")
            
            # Step A: Request code
            with st.form("forgot_form"):
                render_html("<p style='color: #94a3b8; font-size: 13px;'>1. Enter your registered email to request a reset token.</p>")
                email_forgot = st.text_input("Registered Email:")
                submit_forgot = st.form_submit_button("Request Reset Token")
                
                if submit_forgot:
                    if not email_forgot:
                        st.error("Please enter email.")
                    else:
                        res = forgot_password_api(email_forgot)
                        if res["success"]:
                            st.success("Verification code triggered. (For evaluation, the code is printed in backend logs!)")
                            if "dev_token" in res.get("data", {}):
                                st.info(f"Local Dev reset code: `{res['data']['dev_token']}`")
                        else:
                            st.error(f"Reset request error: {res['error']}")
                            
            # Step B: Reset with code
            with st.form("reset_form"):
                render_html("<p style='color: #94a3b8; font-size: 13px;'>2. Enter email, received token, and configure a new password.</p>")
                email_reset = st.text_input("Reset Email:")
                token_reset = st.text_input("Reset Token:")
                pwd_reset = st.text_input("New Password:", type="password")
                submit_reset = st.form_submit_button("Submit Password Reset")
                
                if submit_reset:
                    if not email_reset or not token_reset or not pwd_reset:
                        st.error("All parameters are required.")
                    elif len(pwd_reset) < 6:
                        st.error("New password must be at least 6 characters.")
                    else:
                        res = reset_password_api(email_reset, token_reset, pwd_reset)
                        if res["success"]:
                            st.success("Password reset successfully. You can now log in.")
                        else:
                            st.error(f"Password reset failed: {res['error']}")
    st.stop()

# Load profile if not present
if not st.session_state.user:
    st.session_state.user = fetch_current_user(st.session_state.token)
    if not st.session_state.user:
        # Clear token if profile fetching fails
        st.session_state.token = None
        st.rerun()

user = st.session_state.user

# Sidebar Dashboard Panel Branding SVG logo
logo_svg = """
<svg viewBox="0 0 240 50" width="100%" height="38" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="shieldGradSidebar" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#3b82f6" />
      <stop offset="100%" stop-color="#10b981" />
    </linearGradient>
  </defs>
  <path d="M18 28s4.5-2.2 4.5-5.6V12.7l-4.5-1.7-4.5 1.7v9.2c0 3.4 4.5 5.6 4.5 5.6z" fill="url(#shieldGradSidebar)" />
  <path d="M18 26.2s3.3-1.6 3.3-4.2V14.5l-3.3-1.2-3.3 1.2v6.9c0 2.6 3.3 4.2 3.3 4.2z" fill="#060910" />
  <text x="35" y="27" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Inter', sans-serif" font-size="16" font-weight="800" fill="#f8fafc" letter-spacing="-0.3">AgentShield</text>
  <rect x="135" y="11" width="16" height="16" rx="3" fill="#ef4444" />
  <text x="140" y="23" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Inter', sans-serif" font-size="10" font-weight="900" fill="#ffffff">X</text>
</svg>
"""

render_html(f"""
    <div style='padding: 10px 0px; border-bottom: 1px solid #141b2d; margin-bottom: 20px;'>
        <div style='margin-bottom: 8px;'>{logo_svg}</div>
        <span style='color: #64748b; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;'>🏢 Tenant: {user.get('org_name', 'Enterprise Root')}</span>
    </div>
""", sidebar=True)

# Router Navigation Options
navigation_tab = st.sidebar.radio(
    "🧭 Navigation Panel",
    [
        "📊 Threat Analytics Dashboard",
        "🛡️ AI Security Playground",
        "🔑 Admin Verification Queue",
        "📋 Historical Audit Registry"
    ]
)

render_html("<hr style='border-color: #1e293b; margin: 20px 0;'/>", sidebar=True)

# User Profile & Org Management
with st.sidebar.expander("👤 User Profile"):
    render_html(f"""
        <div style='font-size: 13px; color: #cbd5e0; margin-bottom: 15px;'>
            <strong>Username:</strong> {user.get('username')}<br/>
            <strong>Email:</strong> {user.get('email')}<br/>
            <strong>Role:</strong> <span style='color: #3b82f6; font-weight: bold;'>{user.get('role').upper()}</span>
        </div>
    """)
    
    profile_choice = st.selectbox("Action:", ["Update Profile", "Change Password"])
    
    if profile_choice == "Update Profile":
        with st.form("up_profile_form"):
            new_email = st.text_input("Email:", value=user.get('email'))
            new_org = st.text_input("Organization:", value=user.get('org_name'))
            submit_profile_up = st.form_submit_button("Update", use_container_width=True)
            if submit_profile_up:
                res = update_profile_api(st.session_state.token, email=new_email, org_name=new_org)
                if res["success"]:
                    st.success("Profile updated!")
                    st.session_state.user = res["data"]
                    st.rerun()
                else:
                    st.error(res["error"])
                    
    elif profile_choice == "Change Password":
        with st.form("ch_pwd_form"):
            old_p = st.text_input("Current Password:", type="password")
            new_p = st.text_input("New Password:", type="password")
            submit_pwd_ch = st.form_submit_button("Update Password", use_container_width=True)
            if submit_pwd_ch:
                if len(new_p) < 6:
                    st.error("New password must be at least 6 characters.")
                else:
                    res = change_password_api(st.session_state.token, old_p, new_p)
                    if res["success"]:
                        st.success("Password changed!")
                    else:
                        st.error(res["error"])

render_html("<div style='height: 20px;'></div>", sidebar=True)

# Terminate session
if st.sidebar.button("🚪 Sign Out", use_container_width=True):
    st.session_state.token = None
    st.session_state.user = None
    st.success("Signed out successfully.")
    st.rerun()

# Import sub-components and render selected screen
try:
    from frontend.components.chat_interface import render_chat_interface
    from frontend.components.approval_console import render_approval_console
    from frontend.components.security_report import render_security_report
    from frontend.components.analytics_dashboard import render_analytics_dashboard
except ModuleNotFoundError:
    from components.chat_interface import render_chat_interface
    from components.approval_console import render_approval_console
    from components.security_report import render_security_report
    from components.analytics_dashboard import render_analytics_dashboard

if navigation_tab == "📊 Threat Analytics Dashboard":
    render_analytics_dashboard()
elif navigation_tab == "🛡️ AI Security Playground":
    render_chat_interface()
elif navigation_tab == "🔑 Admin Verification Queue":
    render_approval_console()
elif navigation_tab == "📋 Historical Audit Registry":
    render_security_report()
