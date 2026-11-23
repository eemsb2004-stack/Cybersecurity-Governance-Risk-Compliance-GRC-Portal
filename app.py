import streamlit as st
import sqlite3
from datetime import datetime
from database import get_db, init_db, log_audit, validate_password_strength, validate_email_domain, ORG_INVITE_CODE
from werkzeug.security import generate_password_hash, check_password_hash

st.set_page_config(
    page_title="GRC Portal | Hail Region Municipality",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

init_db()

# Session State Initialization
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

def get_risk_badge(score):
    if score == 0:
        return "🟢 Compliant (0% Risk)"
    elif score <= 25:
        return "🔵 Low Risk"
    elif score <= 55:
        return "🟡 Medium Risk"
    else:
        return "🔴 High Risk"

# ==============================================================================
# AUTHENTICATION & REGISTRATION PORTAL (IF NOT LOGGED IN)
# ==============================================================================
if not st.session_state['authenticated']:
    st.markdown("<h1 style='text-align: center;'>🛡️ Hail Region Municipality</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #6c757d; font-size: 16px;'>Cybersecurity Governance, Risk & Compliance (GRC) Portal</p>", unsafe_allow_html=True)
    st.divider()

    col_1, col_2, col_3 = st.columns([1, 1.5, 1])
    with col_2:
        auth_tab = st.radio("Portal Navigation", ["Secure Sign In", "New Employee Sign Up"], horizontal=True)

        if auth_tab == "Secure Sign In":
            st.subheader("🔐 Personnel Login")
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                submit_login = st.form_submit_button("Authenticate & Login", use_container_width=True)

                if submit_login:
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
                            log_audit(clean_user, "LOGIN_FAILED", "Non-existent username", "WARNING")
                            st.error("❌ Invalid credentials. Access denied.")
                        elif user['is_locked'] == 1:
                            conn.close()
                            log_audit(clean_user, "LOGIN_BLOCKED", "Locked account access attempt", "CRITICAL")
                            st.error("🔒 Account Locked: Too many failed login attempts. Contact CISO.")
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

                                log_audit(clean_user, "LOGIN_SUCCESS", f"Role: {user['role']}", "SUCCESS")
                                st.rerun()
                            else:
                                new_attempts = user['failed_attempts'] + 1
                                lock_status = 1 if new_attempts >= 5 else 0
                                conn.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?", (new_attempts, lock_status, user['id']))
                                conn.commit()
                                conn.close()

                                log_audit(clean_user, "LOGIN_FAILED", f"Invalid password ({new_attempts}/5)", "WARNING")
                                if lock_status == 1:
                                    st.error("🔒 Security Alert: Account locked due to 5 failed attempts.")
                                else:
                                    st.error(f"❌ Invalid credentials. Remaining attempts: {5 - new_attempts}")

        else:
            st.subheader("📝 Sign Up for Portal Access")
            conn = get_db()
            depts = conn.execute("SELECT * FROM departments").fetchall()
            conn.close()
            dept_map = {d['name']: d['id'] for d in depts}

            with st.form("signup_form"):
                full_name = st.text_input("Official Full Name", placeholder="e.g., Fahad Al-Shammari")
                username = st.text_input("Desired Username", placeholder="e.g., f.alshammari")
                email = st.text_input("Official Email", placeholder="name@hail.gov.sa")
                assigned_dept = st.selectbox("Assign to Department", list(dept_map.keys()))
                invite_code = st.text_input("Institutional Access Code", type="password", help="Enter institutional security code")
                
                password = st.text_input("Strong Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")

                st.caption("🔒 **Password Standard:** Min 12 chars, uppercase, lowercase, numbers, and special symbols (`@$!%*?&#`).")
                submit_reg = st.form_submit_button("Verify & Create Account", use_container_width=True)

                if submit_reg:
                    clean_name = full_name.strip()
                    clean_user = username.strip()
                    clean_email = email.strip().lower()

                    if not clean_name or not clean_user or not clean_email or not password or not invite_code:
                        st.error("All fields including the Institutional Access Code are mandatory.")
                    elif invite_code != ORG_INVITE_CODE:
                        log_audit(clean_user, "REGISTRATION_DENIED", "Invalid Institutional Access Code", "CRITICAL")
                        st.error("⛔ Unauthorized: Invalid Institutional Access Code.")
                    elif not validate_email_domain(clean_email):
                        st.error("Please enter a valid email format.")
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
                                st.success("✅ Account created successfully! Switch to the 'Secure Sign In' tab to log in.")
                            except sqlite3.IntegrityError:
                                st.error("❌ Username or Email is already registered.")

            st.info(f"🔑 **Testing Institutional Code:** `{ORG_INVITE_CODE}`")

    st.stop()

# ==============================================================================
# MAIN SYSTEM DASHBOARD & MODULES (AFTER LOGIN)
# ==============================================================================
st.sidebar.markdown("### 🏛️ Hail Region Municipality")
st.sidebar.markdown(f"**Officer:** {st.session_state['full_name']}")
st.sidebar.markdown(f"**Role:** `{st.session_state['role'].upper()}`")
st.sidebar.markdown(f"**Scope:** {st.session_state['dept_name']}")
st.sidebar.markdown("---")

# Separation of Duties (SoD) Navigation:
# Only Department Coordinators perform Self-Assessments; CISO Admin reviews & approves.
if st.session_state['role'] == 'admin':
    nav_options = [
        "Executive Dashboard",
        "1. Remediation & Verification",
        "2. Compliance & Impact Reports",
        "3. NCA ECC Controls Reference",
        "4. IAM & Security Audit Logs"
    ]
else:
    nav_options = [
        "Executive Dashboard",
        "1. NCA ECC Assessment",
        "2. Remediation & Verification",
        "3. Compliance & Impact Reports",
        "4. NCA ECC Controls Reference"
    ]

menu = st.sidebar.radio("System Modules", nav_options, key="main_nav_menu")

st.sidebar.markdown("---")
if st.sidebar.button("🔒 Secure Logout", type="secondary", use_container_width=True):
    log_audit(st.session_state['username'], "LOGOUT", "Session terminated", "INFO")
    st.session_state.clear()
    st.rerun()

# --- MODULE: EXECUTIVE DASHBOARD ---
if menu == "Executive Dashboard":
    st.title("📊 Cybersecurity Risk & Compliance Dashboard")
    st.markdown("Real-time governance overview across Hail Region Municipality departments based on **NCA ECC**.")

    conn = get_db()
    if st.session_state['role'] == 'admin':
        depts = conn.execute("SELECT * FROM departments").fetchall()
        tasks = conn.execute("SELECT * FROM remediations").fetchall()
    else:
        depts = conn.execute("SELECT * FROM departments WHERE id = ?", (st.session_state['dept_id'],)).fetchall()
        tasks = conn.execute("SELECT * FROM remediations WHERE dept_id = ?", (st.session_state['dept_id'],)).fetchall()
    conn.close()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored Departments", len(depts))
    col2.metric("Open Security Gaps", sum(1 for t in tasks if t['status'] not in ['Closed', 'Pending Verification']))
    col3.metric("Awaiting CISO Approval", sum(1 for t in tasks if t['status'] == 'Pending Verification'))
    col4.metric("Verified & Closed", sum(1 for t in tasks if t['status'] == 'Closed'))

    st.markdown("### 🏢 Departmental Risk Posture")
    for d in depts:
        badge = get_risk_badge(d['current_risk'])
        with st.container():
            c1, c2, c3, c4 = st.columns([2.2, 1, 2, 1.3])
            c1.markdown(f"**{d['name']}**")
            c2.markdown(f"State: `{d['status']}`")
            c3.progress(min(d['current_risk'], 100) / 100.0, text=f"Residual Risk: {d['current_risk']}%")
            c4.markdown(f"**{badge}**")
            st.divider()

# --- MODULE: NCA ECC ASSESSMENT (DEPARTMENT USERS ONLY) ---
elif menu == "1. NCA ECC Assessment":
    if st.session_state['role'] == 'admin':
        st.error("⛔ Separation of Duties Policy: CISO Administrators do not perform departmental self-assessments.")
        st.stop()

    st.title("📋 NCA ECC Compliance & Risk Assessment")
    st.markdown("Evaluate departmental adherence to Essential Cybersecurity Controls stored in the core database.")

    conn = get_db()
    dept_id = st.session_state['dept_id']
    dept_rec = conn.execute("SELECT * FROM departments WHERE id = ?", (dept_id,)).fetchone()

    if not dept_rec:
        conn.close()
        st.warning("No department assigned to your account.")
        st.stop()

    # Security Check: Prevent re-assessment if open or pending vulnerabilities exist
    active_gaps = conn.execute(
        "SELECT COUNT(*) as cnt FROM remediations WHERE dept_id = ? AND status != 'Closed'",
        (dept_id,)
    ).fetchone()['cnt']

    if active_gaps > 0:
        conn.close()
        st.warning(f"🔒 **Assessment Locked:** Your department currently has **{active_gaps} unresolved security gap(s)** open or awaiting CISO approval.")
        st.info("👉 Under GRC Governance Policy, you cannot overwrite or reset an active assessment. Please complete all remediation tasks in **'2. Remediation & Verification'** and obtain CISO sign-off first.")
        st.stop()

    controls = conn.execute("SELECT * FROM controls ORDER BY id ASC").fetchall()
    conn.close()

    st.info(f"🏢 **Target Department:** {dept_rec['name']}")
    st.markdown("---")

    answers = {}
    for idx, q in enumerate(controls):
        st.markdown(f"**{idx+1}. [{q['nca_code']}] — {q['domain']}**")
        st.write(q['question'])
        answers[q['id']] = st.radio(
            "Control Implementation Status",
            ["Compliant (Implemented)", "Non-Compliant (Gap Detected)"],
            key=f"ctrl_{dept_id}_{q['id']}",
            horizontal=True
        )
        st.caption(f"Risk Exposure Weight: {q['weight']}%")
        st.divider()

    if st.button("🚀 Calculate Risk Score & Generate Remediation Plan", type="primary", use_container_width=True):
        total_risk = 0
        gap_count = 0
        conn = get_db()

        for q in controls:
            if "Non-Compliant" in answers[q['id']]:
                total_risk += int(q['weight'])
                gap_count += 1
                conn.execute('''INSERT INTO remediations 
                                (dept_id, nca_code, problem_title, action_desc, remediation_type, weight, created_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                             (dept_id, q['nca_code'], q['problem_title'], q['action_desc'], q['remediation_type'], int(q['weight']), datetime.now().strftime('%Y-%m-%d %H:%M')))

        initial_risk = total_risk if dept_rec['status'] == 'Not Assessed' else dept_rec['initial_risk']
        conn.execute("UPDATE departments SET initial_risk = ?, current_risk = ?, status = 'Assessed' WHERE id = ?", (initial_risk, total_risk, dept_id))
        conn.commit()
        conn.close()

        log_audit(st.session_state['username'], "ASSESSMENT_SUBMITTED", f"Assessed {dept_rec['name']} with Risk Score {total_risk}%", "INFO")
        
        st.success(f"✅ Assessment Completed for **{dept_rec['name']}**!")
        res_col1, res_col2, res_col3 = st.columns(3)
        res_col1.metric("Calculated Risk Score", f"{total_risk}%")
        res_col2.metric("Security Gaps Detected", f"{gap_count} Controls")
        res_col3.metric("Classification", get_risk_badge(total_risk))
        if gap_count > 0:
            st.info("👉 Navigate to **'2. Remediation & Verification'** in the sidebar to resolve detected gaps.")

# --- MODULE: REMEDIATION & VERIFICATION ---
elif menu in ["1. Remediation & Verification", "2. Remediation & Verification"]:
    st.title("🛠️ Risk Remediation & Evidence Verification")
    st.markdown("Resolve security gaps and submit auditable evidence under **Separation of Duties (SoD)**.")

    conn = get_db()
    if st.session_state['role'] == 'admin':
        tasks = conn.execute("SELECT r.*, d.name as dept_name FROM remediations r JOIN departments d ON r.dept_id = d.id ORDER BY r.id DESC").fetchall()
    else:
        tasks = conn.execute("SELECT r.*, d.name as dept_name FROM remediations r JOIN departments d ON r.dept_id = d.id WHERE r.dept_id = ? ORDER BY r.id DESC", (st.session_state['dept_id'],)).fetchall()
    conn.close()

    if not tasks:
        st.info("No active remediation tasks pending. Complete an assessment first.")

    for t in tasks:
        with st.container():
            st.markdown(f"### 📌 {t['problem_title']}")
            st.markdown(f"**Department:** {t['dept_name']} | **Control:** `{t['nca_code']}` | **Status:** `{t['status']}` | **Risk Weight:** -{t['weight']}%")
            st.write(f"**Mandatory Remediation Action:** {t['action_desc']}")

            if t['proof_text']:
                st.info(f"**Submitted Evidence Log:** {t['proof_text']}")

            if t['status'] != 'Closed':
                if t['status'] != 'Pending Verification':
                    if st.session_state['role'] == 'admin':
                        st.info("⏳ Awaiting departmental coordinator to submit remediation evidence.")
                    else:
                        if t['remediation_type'] == 'auto_training':
                            with st.expander("🎓 Complete Mandatory Cybersecurity Awareness & Phishing Simulation"):
                                q1 = st.radio(
                                    "Q1: Which of the following is a primary sign of a spear-phishing attack?",
                                    ["Urgent request for credentials via an external link", "Official internal memo posted on the intranet"],
                                    key=f"q1_{t['id']}"
                                )
                                q2 = st.radio(
                                    "Q2: What is the mandatory action upon receiving a suspicious email?",
                                    ["Report immediately to the Information Security Operations Center", "Forward it to colleagues to ask if it is real"],
                                    key=f"q2_{t['id']}"
                                )
                                if st.button("Verify & Submit Training", key=f"sub_quiz_{t['id']}"):
                                    if "Urgent request" in q1 and "Information Security" in q2:
                                        conn = get_db()
                                        proof = f"Completed & Passed Security Awareness Module by {st.session_state['full_name']} ({st.session_state['username']}) at {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                                        conn.execute("UPDATE remediations SET status = 'Pending Verification', proof_text = ? WHERE id = ?", (proof, t['id']))
                                        conn.commit()
                                        conn.close()
                                        log_audit(st.session_state['username'], "EVIDENCE_SUBMITTED", f"Passed awareness training for {t['nca_code']}", "INFO")
                                        st.success("Training verified and locked for CISO approval!")
                                        st.rerun()
                                    else:
                                        st.error("Assessment failed. Review security guidelines and retry.")
                        else:
                            proof_input = st.text_input("Technical Evidence / Ticket Reference (e.g., ITSM Ticket #8841 - MFA Policy Applied)", key=f"txt_proof_{t['id']}")
                            if st.button("Lock & Submit Evidence for CISO Verification", key=f"btn_proof_{t['id']}"):
                                if not proof_input.strip():
                                    st.error("Evidence reference cannot be empty.")
                                else:
                                    conn = get_db()
                                    proof = f"[{st.session_state['full_name']} | {datetime.now().strftime('%Y-%m-%d %H:%M')}]: {proof_input.strip()}"
                                    conn.execute("UPDATE remediations SET status = 'Pending Verification', proof_text = ? WHERE id = ?", (proof, t['id']))
                                    conn.commit()
                                    conn.close()
                                    log_audit(st.session_state['username'], "EVIDENCE_SUBMITTED", f"Submitted proof for {t['nca_code']} ({t['dept_name']})", "INFO")
                                    st.success("Evidence submitted and locked for CISO verification!")
                                    st.rerun()
                else:
                    if st.session_state['role'] == 'admin':
                        c1, c2 = st.columns(2)
                        if c1.button(f"✅ Approve Evidence & Reduce Risk (-{t['weight']}%)", key=f"approve_{t['id']}", use_container_width=True):
                            conn = get_db()
                            conn.execute("UPDATE remediations SET status = 'Closed' WHERE id = ?", (t['id'],))
                            conn.execute("UPDATE departments SET current_risk = MAX(0, current_risk - ?) WHERE id = ?", (t['weight'], t['dept_id']))
                            conn.commit()
                            conn.close()
                            log_audit(st.session_state['username'], "REMEDIATION_APPROVED", f"Closed {t['nca_code']} for {t['dept_name']}", "SUCCESS")
                            st.rerun()
                        if c2.button("❌ Reject & Reopen Task", key=f"reject_{t['id']}", use_container_width=True):
                            conn = get_db()
                            conn.execute("UPDATE remediations SET status = 'Rejected - Revision Required' WHERE id = ?", (t['id'],))
                            conn.commit()
                            conn.close()
                            log_audit(st.session_state['username'], "REMEDIATION_REJECTED", f"Rejected proof for {t['nca_code']} ({t['dept_name']})", "WARNING")
                            st.rerun()
                    else:
                        st.warning("🔒 Separation of Duties Active: Evidence is locked and awaiting independent CISO verification.")
            st.divider()

# --- MODULE: COMPLIANCE & IMPACT REPORTS ---
elif menu in ["2. Compliance & Impact Reports", "3. Compliance & Impact Reports"]:
    st.title("📈 Executive Risk Reduction & Compliance Reports")
    st.markdown("Quantifying cybersecurity maturity improvement before and after control remediation.")

    conn = get_db()
    if st.session_state['role'] == 'admin':
        depts = conn.execute("SELECT * FROM departments").fetchall()
    else:
        depts = conn.execute("SELECT * FROM departments WHERE id = ?", (st.session_state['dept_id'],)).fetchall()
    conn.close()

    for d in depts:
        reduction = d['initial_risk'] - d['current_risk']
        with st.container():
            st.subheader(d['name'])
            c1, c2, c3 = st.columns(3)
            c1.metric("Baseline Initial Risk", f"{d['initial_risk']}%")
            c2.metric("Current Residual Risk", f"{d['current_risk']}%", delta=f"-{reduction}% Risk Reduced" if reduction > 0 else "No Change")
            c3.metric("Compliance Rating", get_risk_badge(d['current_risk']))
            st.divider()

# --- MODULE: BUILT-IN CONTROLS REFERENCE ---
elif menu in ["3. NCA ECC Controls Reference", "4. NCA ECC Controls Reference"]:
    st.title("📚 NCA Essential Cybersecurity Controls (Database Registry)")
    st.markdown("Authoritative controls stored natively within the relational database schema.")

    conn = get_db()
    controls = conn.execute("SELECT nca_code as 'NCA Code', domain as 'Domain', weight as 'Weight (%)', problem_title as 'Risk Vector', action_desc as 'Required Control' FROM controls").fetchall()
    conn.close()
    st.table([dict(row) for row in controls])

# --- MODULE: IAM & SECURITY AUDIT LOGS (ADMIN ONLY) ---
elif menu == "4. IAM & Security Audit Logs":
    if st.session_state['role'] != 'admin':
        st.error("⛔ Access Denied: CISO Administrator clearance required.")
        st.stop()

    st.title("🛡️ Identity Management & Security Audit Trail")
    tab1, tab2, tab3 = st.tabs(["User Accounts & Lockout Control", "Register New Department", "Security Audit Logs"])

    with tab1:
        st.subheader("Registered Personnel")
        conn = get_db()
        users = conn.execute("SELECT u.*, d.name as dept_name FROM users u LEFT JOIN departments d ON u.dept_id = d.id").fetchall()
        for u in users:
            c1, c2, c3, c4 = st.columns([2, 2, 1.5, 1.5])
            c1.write(f"**{u['full_name']}** (`{u['username']}`)")
            c2.write(f"{u['dept_name'] if u['dept_name'] else 'All Departments'}")
            c3.write(f"Role: `{u['role'].upper()}` | Status: {'🔒 Locked' if u['is_locked'] else '🟢 Active'}")
            if u['is_locked']:
                if c4.button("Unlock Account", key=f"unlock_{u['id']}"):
                    conn.execute("UPDATE users SET is_locked = 0, failed_attempts = 0 WHERE id = ?", (u['id'],))
                    conn.commit()
                    log_audit(st.session_state['username'], "ACCOUNT_UNLOCKED", f"Unlocked user {u['username']}", "INFO")
                    st.rerun()
        conn.close()

    with tab2:
        new_dept = st.text_input("New Municipality Department Name", key="new_dept_input")
        if st.button("Add Department", key="btn_add_dept"):
            if new_dept.strip():
                try:
                    conn = get_db()
                    conn.execute("INSERT INTO departments (name) VALUES (?)", (new_dept.strip(),))
                    conn.commit()
                    conn.close()
                    log_audit(st.session_state['username'], "DEPARTMENT_ADDED", f"Added department: {new_dept.strip()}", "INFO")
                    st.success("Department added successfully.")
                    st.rerun()
                except Exception:
                    st.warning("Department already exists.")

    with tab3:
        st.subheader("Immutable System Security Logs")
        conn = get_db()
        logs = conn.execute("SELECT timestamp as 'Timestamp', username as 'User', action as 'Event', details as 'Details', status as 'Severity' FROM audit_logs ORDER BY id DESC LIMIT 50").fetchall()
        conn.close()
        if logs:
            st.table([dict(row) for row in logs])
        else:
            st.info("No audit logs recorded yet.")