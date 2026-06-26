import streamlit as st

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

# Configure page layout and visual parameters
st.set_page_config(
    page_title="AgentShield-X | Enterprise LLM Gateway",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise cybersecurity design overrides (CrowdStrike / Defender style)
st.markdown("""
    <style>
    /* Google Fonts Inter Integration */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* Strict Dark/Cyber Theme Adjustments */
    .stApp {
        background-color: #0b0f19;
        color: #f8fafc;
    }
    
    /* Clean Enterprise Header */
    .brand-header {
        font-weight: 700;
        font-size: 32px;
        letter-spacing: -0.5px;
        color: #f8fafc;
        margin-bottom: 2px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 8px;
    }
    
    .brand-tagline {
        color: #64748b;
        font-size: 14px;
        margin-top: 4px;
        margin-bottom: 24px;
    }
    
    /* Cybersecurity Minimalist Card Elements */
    .sec-card {
        background-color: #131a26;
        border: 1px solid #1e293b;
        padding: 20px;
        border-radius: 6px;
        margin-bottom: 20px;
    }
    
    /* Standardized button styles */
    div.stButton > button {
        background-color: #2563eb !important;
        color: white !important;
        border: none !important;
        border-radius: 4px !important;
        padding: 8px 16px !important;
        font-weight: 500 !important;
        font-size: 14px !important;
        transition: background-color 0.2s ease !important;
    }
    div.stButton > button:hover {
        background-color: #1d4ed8 !important;
    }
    
    /* Secondary or warning button styles */
    .btn-secondary button {
        background-color: #334155 !important;
    }
    
    /* Badge metrics */
    .metric-val {
        font-family: 'Inter', monospace;
        font-size: 28px;
        font-weight: 700;
        color: #f8fafc;
    }
    </style>
""", unsafe_allow_html=True)

# Session Authentication State Management
if "token" not in st.session_state:
    st.session_state.token = None
if "user" not in st.session_state:
    st.session_state.user = None

# If not authenticated, render login/registration portal
if not st.session_state.token:
    st.markdown("""
        <div style="text-align: center; padding: 40px 0px 20px 0px;">
            <h1 style="color: #f8fafc; font-weight: 800; font-size: 36px; margin-bottom: 8px;">🛡️ AgentShield-X</h1>
            <p style="color: #64748b; font-size: 15px;">Enterprise Multi-Agent LLM Security Gateway & Policy Firewall</p>
        </div>
    """, unsafe_allow_html=True)
    
    col_c1, col_c2, col_c3 = st.columns([1, 1.8, 1])
    with col_c2:
        auth_tab = st.tabs(["🔒 Secure Login", "📝 Register Tenant", "🔑 Credentials Recovery"])
        
        # 1. Login Tab
        with auth_tab[0]:
            with st.form("login_form"):
                st.markdown("<h4 style='color: #f8fafc;'>Sign In to Security console</h4>", unsafe_allow_html=True)
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
                st.markdown("<h4 style='color: #f8fafc;'>Provision User Profile</h4>", unsafe_allow_html=True)
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
            st.markdown("<h4 style='color: #f8fafc;'>Reset Administrative Credentials</h4>", unsafe_allow_html=True)
            
            # Step A: Request code
            with st.form("forgot_form"):
                st.markdown("<p style='color: #94a3b8; font-size: 13px;'>1. Enter your registered email to request a reset token.</p>", unsafe_allow_html=True)
                email_forgot = st.text_input("Registered Email:")
                submit_forgot = st.form_submit_button("Request Reset Token")
                
                if submit_forgot:
                    if not email_forgot:
                        st.error("Please enter email.")
                    else:
                        res = forgot_password_api(email_forgot)
                        if res["success"]:
                            st.success("Verification code triggered. (For evaluation, the code is printed in backend logs!)")
                            # We can also display the token for local testing ease
                            if "dev_token" in res.get("data", {}):
                                st.info(f"Local Dev reset code: `{res['data']['dev_token']}`")
                        else:
                            st.error(f"Reset request error: {res['error']}")
                            
            # Step B: Reset with code
            with st.form("reset_form"):
                st.markdown("<p style='color: #94a3b8; font-size: 13px;'>2. Enter email, received token, and configure a new password.</p>", unsafe_allow_html=True)
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

# Sidebar Dashboard Panel Branding
st.sidebar.markdown(f"""
    <div style='padding: 10px 0px; border-bottom: 1px solid #1e293b; margin-bottom: 20px;'>
        <h3 style='color: #f8fafc; margin: 0; font-weight: 800;'>🛡️ AgentShield-X</h3>
        <span style='color: #64748b; font-size: 12px; font-weight: 500;'>🏢 Tenant: {user.get('org_name', 'Enterprise Root')}</span>
    </div>
""", unsafe_allow_html=True)

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

st.sidebar.markdown("<hr style='border-color: #1e293b; margin: 20px 0;'/>", unsafe_allow_html=True)

# User Profile & Org Management
with st.sidebar.expander("👤 User Profile"):
    st.markdown(f"""
        <div style='font-size: 13px; color: #cbd5e0; margin-bottom: 15px;'>
            <strong>Username:</strong> {user.get('username')}<br/>
            <strong>Email:</strong> {user.get('email')}<br/>
            <strong>Role:</strong> <span style='color: #3b82f6; font-weight: bold;'>{user.get('role').upper()}</span>
        </div>
    """, unsafe_allow_html=True)
    
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

st.sidebar.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

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
