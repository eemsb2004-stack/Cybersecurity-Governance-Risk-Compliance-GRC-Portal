import streamlit as st
import sqlite3
from werkzeug.security import generate_password_hash
from database import get_db, init_db, validate_password_strength, validate_email_domain, log_audit, ORG_INVITE_CODE

st.set_page_config(page_title="Sign Up | Hail Region Municipality", page_icon="📝", layout="centered")
init_db()

st.markdown("""
    <style>
        [data-testid="stSidebarNav"] {display: none;}
    </style>
""", unsafe_allow_html=True)

if st.session_state.get('authenticated'):
    st.switch_page("app.py")

st.markdown("<h1 style='text-align: center;'>🛡️ Hail Region Municipality</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #6c757d; font-size: 16px;'>Personnel Security Registration — NCA ECC Identity Onboarding</p>", unsafe_allow_html=True)
st.divider()

conn = get_db()
depts = conn.execute("SELECT * FROM departments").fetchall()
conn.close()
dept_map = {d['name']: d['id'] for d in depts}

st.subheader("📝 Sign Up for Portal Access")

col1, col2 = st.columns(2)
with col1:
    full_name = st.text_input("Official Full Name", placeholder="e.g., Fahad Al-Shammari", key="reg_name")
    username = st.text_input("Username", placeholder="e.g., f.alshammari", key="reg_user")
with col2:
    email = st.text_input("Official Email", placeholder="name@hail.gov.sa", key="reg_email")
    assigned_dept = st.selectbox("Assigned Department", list(dept_map.keys()), key="reg_dept")

invite_code = st.text_input("Institutional Access Code", type="password", help="Enter: HAIL-SEC-2026", key="reg_code")

col3, col4 = st.columns(2)
with col3:
    password = st.text_input("Strong Password", type="password", key="reg_pass")
with col4:
    confirm_password = st.text_input("Confirm Password", type="password", key="reg_conf")

st.caption("🔒 **NCA Password Standard:** Minimum 12 characters, including uppercase, lowercase, numbers, and special symbols (`@$!%*?&#`).")

if st.button("✅ Verify & Create Account", type="primary", use_container_width=True):
    clean_name = full_name.strip()
    clean_user = username.strip()
    clean_email = email.strip().lower()

    if not clean_name or not clean_user or not clean_email or not password or not invite_code:
        st.error("All fields including the Institutional Access Code are mandatory.")
    elif invite_code != ORG_INVITE_CODE:
        log_audit(clean_user, "REGISTRATION_DENIED", "Invalid Institutional Access Code provided", "CRITICAL")
        st.error("⛔ Unauthorized: Invalid Institutional Access Code. Registration blocked.")
    elif not validate_email_domain(clean_email):
        st.error("Please enter a valid email address format.")
    elif password != confirm_password:
        st.error("Passwords do not match.")
    else:
        pw_error = validate_password_strength(password)
        if pw_error:
            st.error(f"⚠️ Password Policy Violation: {pw_error}")
        else:
            try:
                conn = get_db()
                hashed_pw = generate_password_hash(password)
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, full_name, role, dept_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (clean_user, clean_email, hashed_pw, clean_name, 'dept', dept_map[assigned_dept])
                )
                conn.commit()
                conn.close()

                log_audit(clean_user, "ACCOUNT_CREATED", f"Registered under {assigned_dept}", "SUCCESS")
                st.success("✅ Account verified and registered securely! Click 'Back to Login' below to sign in.")
            except sqlite3.IntegrityError:
                st.error("❌ Username or Email is already registered in the system.")

st.info(f"🔑 **Testing Institutional Code:** `{ORG_INVITE_CODE}`")

st.markdown("---")
col1, col2 = st.columns([2, 1])
with col1:
    st.write("Already have an active account?")
with col2:
    if st.button("← Back to Login", use_container_width=True):
        st.switch_page("pages/1_Login.py")