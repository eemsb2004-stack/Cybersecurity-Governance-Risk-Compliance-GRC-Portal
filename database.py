import sqlite3
import re
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_NAME = "hail_cyber_enterprise.db"
ORG_INVITE_CODE = "HAIL-SEC-2026"  # Institutional verification code for new registrations

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(username, action, details, status="INFO"):
    """Record security events for NCA ECC compliance auditing"""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (timestamp, username, action, details, status) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, action, details, status)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def init_db():
    conn = get_db()
    c = conn.cursor()

    # 1. Departments Table
    c.execute('''CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        initial_risk INTEGER DEFAULT 0,
        current_risk INTEGER DEFAULT 0,
        status TEXT DEFAULT 'Not Assessed'
    )''')

    # 2. Users Table (with failed login tracking & lockout)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        dept_id INTEGER,
        failed_attempts INTEGER DEFAULT 0,
        is_locked INTEGER DEFAULT 0,
        FOREIGN KEY(dept_id) REFERENCES departments(id)
    )''')

    # 3. Built-in NCA ECC Controls Table (Replaces external CSV dataset)
    c.execute('''CREATE TABLE IF NOT EXISTS controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nca_code TEXT UNIQUE NOT NULL,
        domain TEXT NOT NULL,
        question TEXT NOT NULL,
        weight INTEGER NOT NULL,
        problem_title TEXT NOT NULL,
        remediation_type TEXT NOT NULL,
        action_desc TEXT NOT NULL
    )''')

    # 4. Remediations Table
    c.execute('''CREATE TABLE IF NOT EXISTS remediations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        dept_id INTEGER,
        nca_code TEXT,
        problem_title TEXT,
        action_desc TEXT,
        remediation_type TEXT,
        weight INTEGER,
        status TEXT DEFAULT 'Open',
        proof_text TEXT,
        created_at TEXT,
        FOREIGN KEY(dept_id) REFERENCES departments(id)
    )''')

    # 5. Security Audit Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT NOT NULL,
        status TEXT NOT NULL
    )''')

    # Seed Official Municipality Departments
    depts = [
        'Human Resources Department',
        'Urban Planning & Projects Department',
        'Financial & Administrative Affairs',
        'Licensing & Municipal Control',
        'Digital Transformation & IT Infrastructure'
    ]
    for d in depts:
        c.execute('INSERT OR IGNORE INTO departments (name) VALUES (?)', (d,))

    # Seed Official NCA ECC Controls (Total Weight = 100%)
    nca_controls = [
        ('NCA-ECC-1-1-1', 'Cybersecurity Governance', 'Is there an approved cybersecurity strategy and policy communicated to all department personnel?', 15, 'Missing Approved Departmental Cybersecurity Policy', 'policy_template', 'Adopt, sign, and distribute the official Hail Municipality Cybersecurity Policy.'),
        ('NCA-ECC-2-1-1', 'Identity & Access Management', 'Is Multi-Factor Authentication (MFA) strictly enforced for all employee accounts and remote access?', 25, 'Multi-Factor Authentication (MFA) Not Enforced', 'it_task', 'Enforce MFA across Active Directory, VPN, and corporate email portals.'),
        ('NCA-ECC-2-2-1', 'Access Control & Least Privilege', 'Are user access privileges periodically reviewed and restricted based on least privilege?', 15, 'Unreviewed Excessive User Access Privileges', 'it_task', 'Conduct IAM access review and revoke redundant administrative privileges.'),
        ('NCA-ECC-2-3-1', 'Vulnerability & Patch Management', 'Are critical OS and application security patches deployed within the approved SLA timeframe?', 20, 'Delayed Critical Security Patch Management', 'it_task', 'Deploy latest security updates and vulnerability patches across all endpoints.'),
        ('NCA-ECC-3-1-1', 'Cybersecurity Awareness', 'Have all department staff completed mandatory cybersecurity awareness and phishing simulation training?', 10, 'Insufficient Employee Phishing Awareness', 'auto_training', 'Complete mandatory internal phishing simulation and security awareness module.'),
        ('NCA-ECC-4-1-1', 'Backup & Business Continuity', 'Are automated, encrypted backups regularly performed and tested for critical departmental data?', 15, 'Absence of Tested Encrypted Data Backups', 'it_task', 'Configure automated encrypted backups and attach restoration test logs.')
    ]
    for ctrl in nca_controls:
        c.execute('''INSERT OR IGNORE INTO controls 
                     (nca_code, domain, question, weight, problem_title, remediation_type, action_desc) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)''', ctrl)

    # Seed Default CISO Admin Account
    if not c.execute('SELECT * FROM users WHERE username = ?', ('ciso_admin',)).fetchone():
        c.execute('''INSERT INTO users (username, email, password_hash, full_name, role, dept_id) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  ('ciso_admin', 'ciso@hail.gov.sa', generate_password_hash('Admin@2026#Hail'), 'Chief Information Security Officer', 'admin', None))

    conn.commit()
    conn.close()

def validate_password_strength(password):
    """Strict NCA ECC Password Complexity Enforcement"""
    if len(password) < 12:
        return "Password must be at least 12 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one numeric digit (0-9)."
    if not re.search(r"[@$!%*?&#^_-]", password):
        return "Password must include at least one special character (@$!%*?&#^_-)."
    return None

def validate_email_domain(email):
    """Enforce valid institutional email format"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None