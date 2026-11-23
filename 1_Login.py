import streamlit as st
from werkzeug.security import check_password_hash
from database import get_db, init_db, log_audit

st.set_page_config(page_title="Login | Hail Region Municipality", page_icon="🔐", layout="centered")
init_db()

st.markdown("""
    <style>
        [data-testid="stSidebarNav"] {display: none;}
    </style>
""", unsafe_allow_html=True)

if st.session_state.get('authenticated'):
    st.switch_page("app.py")

st.markdown("<h1 style='text-align: center;'>🛡️ Hail Region Municipality</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #6c757d; font-size: 16px;'>Cybersecurity Governance, Risk & Compliance (GRC) Portal</p>", unsafe_allow_html=True)
st.divider()

st.subheader("🔐 Personnel Login")
username = st.text_input("Username", placeholder="Enter your official username", key="login_user")
password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pass")

if st.button("Authenticate & Login", type="primary", use_container_width=True):
    clean_user = username.strip()
    if not clean_user or not password:
        st.error("Please provide both username and password.")
    else:
        conn = get_db()
        user = conn.execute(
            "SELECT u.*, d.name as dept_name FROM users u LEFT JOIN departments d ON u.dept_id = d.id WHERE u.username = ?",
            (clean_user,)
        ).fetchone()

        if not user:
            conn.close()
            log_audit(clean_user, "LOGIN_FAILED", "Attempted login with non-existent username", "WARNING")
            st.error("❌ Invalid credentials. Access denied.")
        elif user['is_locked'] == 1:
            conn.close()
            log_audit(clean_user, "LOGIN_BLOCKED", "Attempted login on locked account", "CRITICAL")
            st.error("🔒 Account Locked: Too many failed login attempts. Contact the CISO Administrator to unlock.")
        else:
            if check_password_hash(user['password_hash'], password):
                conn.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user['id'],))
                conn.commit()
                conn.close()

                st.session_state['authenticated'] = True
                st.session_state['user_id'] = user['id']
                st.session_state['username'] = user['username']
                st.session_state['full_name'] = user['full_name']
                st.session_state['email'] = user['email']
                st.session_state['role'] = user['role']
                st.session_state['dept_id'] = user['dept_id']
                st.session_state['dept_name'] = user['dept_name'] if user['dept_name'] else 'All Municipality Departments (CISO)'

                log_audit(clean_user, "LOGIN_SUCCESS", f"User logged in with role {user['role']}", "SUCCESS")
                st.switch_page("app.py")
            else:
                new_attempts = user['failed_attempts'] + 1
                lock_status = 1 if new_attempts >= 5 else 0
                conn.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?", (new_attempts, lock_status, user['id']))
                conn.commit()
                conn.close()

                log_audit(clean_user, "LOGIN_FAILED", f"Invalid password (Attempt {new_attempts}/5)", "WARNING")
                if lock_status == 1:
                    st.error("🔒 Security Alert: Account has been locked after 5 failed attempts.")
                else:
                    st.error(f"❌ Invalid credentials. Remaining attempts before lockout: {5 - new_attempts}")

st.info("💡 **Default CISO Admin Account:**\n* **Username:** `ciso_admin`\n* **Password:** `Admin@2026#Hail`")

st.markdown("---")
col1, col2 = st.columns([2, 1])
with col1:
    st.write("New department security officer? Request access:")
with col2:
    if st.button("Go to Sign Up →", use_container_width=True):
        st.switch_page("pages/2_Sign_Up.py")