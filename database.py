"""
Database initialization and access layer for SYSAD System.
Implements the two data stores specified in the DFD:
1. User & Roles Database (user_roles.db)
2. Audit & Ticket Logs DB (audit_ticket_logs.db)
With enhanced schemas supporting the 6 Expected Outcomes:
- Automated Account Management
- Enhanced Network Security (Granular RBAC)
- Proactive Threat Prevention (Aging accounts & Credential rotation)
- Accelerated Incident Resolution (Prioritized queues & Permission change audits)
- High Infrastructure Reliability (Telemetry & Rapid Backup Recovery)
- Optimized IT Operations (Server config & Firewall management)
"""

import sqlite3
import os
import hashlib
import uuid
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USER_ROLES_DB_PATH = os.path.join(DATA_DIR, "user_roles.db")
AUDIT_TICKET_DB_PATH = os.path.join(DATA_DIR, "audit_ticket_logs.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")

def get_db_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    """Hash password with sha256 and salt."""
    salt = "SYSAD_SECURITY_SALT_2026"
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def init_databases():
    """Initializes both SQLite databases according to the DFD schema."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    # -------------------------------------------------------------
    # 1. User & Roles Database
    # -------------------------------------------------------------
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Roles and Granular Permissions Table (Outcome 2)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                role_name TEXT PRIMARY KEY,
                description TEXT,
                can_submit_tickets INTEGER DEFAULT 1,
                can_view_own_tickets INTEGER DEFAULT 1,
                can_manage_users INTEGER DEFAULT 0,
                can_triage_tickets INTEGER DEFAULT 0,
                can_view_telemetry INTEGER DEFAULT 0,
                can_manage_backups INTEGER DEFAULT 0,
                can_manage_patches INTEGER DEFAULT 0,
                can_manage_firewall INTEGER DEFAULT 0,
                can_view_audit_logs INTEGER DEFAULT 0
            )
        """)

        # Users Table with Lifecycle & Credential Rotation (Outcome 1 & 3)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Active', -- Active, Aging, Suspended
                department TEXT DEFAULT 'General',
                last_login TEXT,
                created_at TEXT NOT NULL,
                password_changed_at TEXT,
                must_rotate_password INTEGER DEFAULT 0, -- Proactive Threat Prevention
                failed_attempts INTEGER DEFAULT 0, -- Brute-force lockout protection (Outcome 6: max_failed_logins)
                FOREIGN KEY (role) REFERENCES roles (role_name)
            )
        """)

        # Ensure failed_attempts column exists on existing databases
        cursor.execute("PRAGMA table_info(users)")
        user_cols = [c[1] for c in cursor.fetchall()]
        if "failed_attempts" not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")

        # Active Session Tokens for RBAC Policy Engine
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # Column migrations for existing tables
        cursor.execute("PRAGMA table_info(roles)")
        role_cols = [c["name"] for c in cursor.fetchall()]
        if "can_manage_firewall" not in role_cols:
            cursor.execute("ALTER TABLE roles ADD COLUMN can_manage_firewall INTEGER DEFAULT 0")
            cursor.execute("UPDATE roles SET can_manage_firewall = 1 WHERE role_name IN ('IT Staff', 'Administrator')")

        cursor.execute("PRAGMA table_info(users)")
        user_cols = [c["name"] for c in cursor.fetchall()]
        if "must_rotate_password" not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN must_rotate_password INTEGER DEFAULT 0")

        # Seed standard roles if not existing
        cursor.execute("SELECT COUNT(*) FROM roles")
        if cursor.fetchone()[0] == 0:
            roles_data = [
                ('Student', 'Enrolled University Student', 1, 1, 0, 0, 0, 0, 0, 0, 0),
                ('IT Staff', 'IT Operations, Support & Triage Staff', 1, 1, 1, 1, 1, 1, 1, 1, 1),
                ('Administrator', 'System Administrator with full RBAC & Infrastructure control', 1, 1, 1, 1, 1, 1, 1, 1, 1)
            ]
            cursor.executemany("""
                INSERT INTO roles (role_name, description, can_submit_tickets, can_view_own_tickets,
                                   can_manage_users, can_triage_tickets, can_view_telemetry,
                                   can_manage_backups, can_manage_patches, can_manage_firewall, can_view_audit_logs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, roles_data)

        # Seed standard users if not existing
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            now_iso = datetime.now().isoformat()
            ninety_five_days_ago = (datetime.now() - timedelta(days=95)).isoformat()
            one_hundred_twenty_days_ago = (datetime.now() - timedelta(days=120)).isoformat()
            
            sample_users = [
                # Primary Student (Maintained)
                ('alex.student', hash_password('student123'), 'Alex Vance', 'alex.vance@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                # Standard University Students (Departments: Information Technology or Computer Science)
                ('liam.smith', hash_password('student123'), 'Liam Smith', 'liam.smith@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('emma.johnson', hash_password('student123'), 'Emma Johnson', 'emma.johnson@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('noah.williams', hash_password('student123'), 'Noah Williams', 'noah.williams@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('olivia.brown', hash_password('student123'), 'Olivia Brown', 'olivia.brown@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('james.jones', hash_password('student123'), 'James Jones', 'james.jones@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('sophia.garcia', hash_password('student123'), 'Sophia Garcia', 'sophia.garcia@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('lucas.miller', hash_password('student123'), 'Lucas Miller', 'lucas.miller@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('mia.davis', hash_password('student123'), 'Mia Davis', 'mia.davis@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('ethan.rodriguez', hash_password('student123'), 'Ethan Rodriguez', 'ethan.rodriguez@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('isabella.martinez', hash_password('student123'), 'Isabella Martinez', 'isabella.martinez@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('mason.hernandez', hash_password('student123'), 'Mason Hernandez', 'mason.hernandez@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('ava.lopez', hash_password('student123'), 'Ava Lopez', 'ava.lopez@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('logan.gonzalez', hash_password('student123'), 'Logan Gonzalez', 'logan.gonzalez@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('charlotte.wilson', hash_password('student123'), 'Charlotte Wilson', 'charlotte.wilson@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('benjamin.anderson', hash_password('student123'), 'Benjamin Anderson', 'benjamin.anderson@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('amelia.thomas', hash_password('student123'), 'Amelia Thomas', 'amelia.thomas@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('elijah.taylor', hash_password('student123'), 'Elijah Taylor', 'elijah.taylor@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('harper.moore', hash_password('student123'), 'Harper Moore', 'harper.moore@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('daniel.jackson', hash_password('student123'), 'Daniel Jackson', 'daniel.jackson@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('evelyn.white', hash_password('student123'), 'Evelyn White', 'evelyn.white@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('henry.harris', hash_password('student123'), 'Henry Harris', 'henry.harris@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('scarlett.martin', hash_password('student123'), 'Scarlett Martin', 'scarlett.martin@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('jackson.clark', hash_password('student123'), 'Jackson Clark', 'jackson.clark@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('grace.lewis', hash_password('student123'), 'Grace Lewis', 'grace.lewis@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('sebastian.robinson', hash_password('student123'), 'Sebastian Robinson', 'sebastian.robinson@campus.edu', 'Student', 'Active', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('zoey.walker', hash_password('student123'), 'Zoey Walker', 'zoey.walker@campus.edu', 'Student', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                
                # Proactive Threat Aging Profile
                ('kevin.aging', hash_password('student123'), 'Kevin Miller', 'kevin.miller@campus.edu', 'Student', 'Aging', 'Computer Science', ninety_five_days_ago, ninety_five_days_ago, one_hundred_twenty_days_ago, 1),
                
                # Suspended Students for Login Policy Verification (Formatted like alex.student)
                ('sam.student', hash_password('student123'), 'Sam Wilson', 'sam.wilson@campus.edu', 'Student', 'Suspended', 'Computer Science', now_iso, now_iso, now_iso, 0),
                ('chloe.student', hash_password('student123'), 'Chloe Davis', 'chloe.davis@campus.edu', 'Student', 'Suspended', 'Information Technology', now_iso, now_iso, now_iso, 0),
                
                # IT Staff and Administrator
                ('marcus.it', hash_password('itstaff123'), 'Marcus Cole (IT Tech)', 'marcus.cole@campus.edu', 'IT Staff', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0),
                ('elena.admin', hash_password('admin123'), 'Elena Rostova', 'elena.rostova@campus.edu', 'Administrator', 'Active', 'Information Technology', now_iso, now_iso, now_iso, 0)
            ]
            cursor.executemany("""
                INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_users)

        conn.commit()

    # -------------------------------------------------------------
    # 2. Audit & Ticket Logs DB
    # -------------------------------------------------------------
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()

        # Tickets Table (Outcome 4: Accelerated Incident Resolution)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_code TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL, -- Low, Medium, High, Critical
                status TEXT NOT NULL DEFAULT 'Open', -- Open, In Triage, In Progress, Resolved, Closed
                submitted_by_id INTEGER NOT NULL,
                submitted_by_name TEXT NOT NULL,
                assigned_to TEXT DEFAULT 'Unassigned',
                resolution_notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # System Audit & Incident Logs Table (Audited Trail of Permission & State Changes)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL, -- AUTH, PROVISIONING, LIFECYCLE, PERMISSION_CHANGE, TICKET_TRIAGE, PATCH, BACKUP, FIREWALL, ALERT
                actor_username TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                details TEXT NOT NULL,
                ip_address TEXT DEFAULT '127.0.0.1',
                timestamp TEXT NOT NULL
            )
        """)

        # Hardware & Security Telemetry History (Outcome 5: High Infrastructure Reliability)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu_percent REAL NOT NULL,
                ram_percent REAL NOT NULL,
                disk_percent REAL NOT NULL,
                active_connections INTEGER NOT NULL,
                system_status TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)

        # Client-Side Student PC Telemetry (Client-Side Agent Heartbeats)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS student_pc_telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT UNIQUE NOT NULL,
                mac_address TEXT,
                ip_address TEXT,
                student_username TEXT,
                os_platform TEXT,
                cpu_load REAL,
                ram_used_mb REAL,
                ram_total_mb REAL,
                ram_usage_pct REAL,
                disk_used_gb REAL,
                disk_total_gb REAL,
                disk_usage_pct REAL,
                last_heartbeat TEXT NOT NULL,
                status TEXT DEFAULT 'ONLINE'
            )
        """)

        # Forbidden Websites Management (Campus Content Inspection Filter)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS forbidden_websites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_pattern TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'ACTIVE',
                added_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Maintenance, Patches & Backup Schedules Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS maintenance_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL, -- 'PATCH' or 'BACKUP'
                title TEXT NOT NULL,
                status TEXT NOT NULL, -- Scheduled, In Progress, Completed, Failed
                details TEXT,
                created_by TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                executed_at TEXT
            )
        """)

        # Firewall Management Table (Outcome 6: Optimized IT Operations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                direction TEXT NOT NULL, -- Inbound, Outbound
                source_subnet TEXT NOT NULL,
                port TEXT NOT NULL,
                action TEXT NOT NULL, -- ALLOW, DENY
                status TEXT NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, DISABLED
                last_modified TEXT NOT NULL
            )
        """)

        # Server Configuration Table (Outcome 6: Optimized IT Operations)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS server_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # Seed sample tickets if empty
        cursor.execute("SELECT COUNT(*) FROM tickets")
        if cursor.fetchone()[0] == 0:
            now = datetime.now()
            sample_tickets = [
                ('TICK-1001', 'Lab 304 Projector HDMI Signal Loss', 'Projector in STEM 304 flickers and cuts off during lecture slideshows.', 'Hardware', 'High', 'In Triage', 1, 'Alex Vance', 'marcus.it', 'Investigating HDMI splitter in ceiling mount.', (now - timedelta(hours=3)).isoformat(), (now - timedelta(hours=1)).isoformat()),
                ('TICK-1002', 'Canvas LMS 403 Forbidden Access on Math exam portal', 'Receiving access denied when attempting to load midterm assessment page.', 'Software', 'Critical', 'Open', 1, 'Alex Vance', 'Unassigned', '', (now - timedelta(hours=1)).isoformat(), (now - timedelta(hours=1)).isoformat()),
                ('TICK-1003', 'Dormitory Hall C Wi-Fi frequent disconnects', 'Wireless network drops connection every 10 minutes in dorm rooms 201-215.', 'Network', 'Medium', 'In Progress', 1, 'Alex Vance', 'marcus.it', 'Scheduled AP restart and channel re-alignment.', (now - timedelta(days=1)).isoformat(), (now - timedelta(hours=4)).isoformat()),
                ('TICK-1004', 'Student Mailbox storage limit alert', 'Exchange mailbox exceeded 48GB capacity threshold.', 'Account', 'Low', 'Resolved', 1, 'Alex Vance', 'marcus.it', 'Archived older attachments to cold storage. Quota restored to 60%.', (now - timedelta(days=2)).isoformat(), (now - timedelta(days=1)).isoformat())
            ]
            cursor.executemany("""
                INSERT INTO tickets (ticket_code, title, description, category, priority, status,
                                     submitted_by_id, submitted_by_name, assigned_to, resolution_notes,
                                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_tickets)

        # Seed initial audit logs if empty
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        if cursor.fetchone()[0] == 0:
            now_str = datetime.now().isoformat()
            sample_logs = [
                ('AUTH', 'elena.admin', 'Administrator', 'Successful privileged login and RBAC token issuance', '127.0.0.1', now_str),
                ('PERMISSION_CHANGE', 'elena.admin', 'Administrator', 'Configured granular RBAC access for Student role (Enforce ticket isolation)', '127.0.0.1', now_str),
                ('PROVISIONING', 'marcus.it', 'IT Staff', 'Account verified: alex.student (Student, IT Dept)', '127.0.0.1', now_str),
                ('ALERT', 'SYSTEM_MONITOR', 'System Daemon', 'Routine telemetry heartbeat recorded: All subsystems nominal', '127.0.0.1', now_str),
                ('BACKUP', 'elena.admin', 'Administrator', 'Automated Daily Snapshot backup executed successfully', '127.0.0.1', now_str)
            ]
            cursor.executemany("""
                INSERT INTO audit_logs (event_type, actor_username, actor_role, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, sample_logs)

        # Seed maintenance tasks if empty
        cursor.execute("SELECT COUNT(*) FROM maintenance_tasks")
        if cursor.fetchone()[0] == 0:
            now = datetime.now()
            sample_tasks = [
                ('PATCH', 'SYSAD-KB-2026-08: OpenSSH Vulnerability Mitigation', 'Completed', 'Upgraded OpenSSH server packages and closed obsolete cipher suites.', 'elena.admin', (now - timedelta(days=1)).isoformat(), (now - timedelta(days=1)).isoformat()),
                ('BACKUP', 'Automated Weekly Full DB Snapshot', 'Completed', 'Snapshot archive db_snapshot_20261101.bak verified integrity.', 'SYSTEM', (now - timedelta(days=4)).isoformat(), (now - timedelta(days=4)).isoformat()),
                ('PATCH', 'Campus Firewall SSL Certificate Renewal 2026', 'Scheduled', 'Deploy renewed Wildcard TLS/SSL certificate across gateway proxies.', 'elena.admin', (now + timedelta(days=2)).isoformat(), None)
            ]
            cursor.executemany("""
                INSERT INTO maintenance_tasks (task_type, title, status, details, created_by, scheduled_at, executed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, sample_tasks)

        # Seed firewall rules (Outcome 6: Firewall Management)
        cursor.execute("SELECT COUNT(*) FROM firewall_rules WHERE rule_name LIKE '%P2P%'")
        if cursor.fetchone()[0] == 0:
            now_str = datetime.now().isoformat()
            more_fw = [
                ('FW-RULE-06: Block P2P Torrenting & Copyright Sites', 'Outbound', '10.0.0.0/16', '6881-6889, 80, 443', 'DENY', 'ACTIVE', now_str),
                ('FW-RULE-07: Block Proxy & VPN Evasion Gateways', 'Outbound', '10.0.0.0/16', '1194, 500, 8080', 'DENY', 'ACTIVE', now_str)
            ]
            cursor.executemany("""
                INSERT INTO firewall_rules (rule_name, direction, source_subnet, port, action, status, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, more_fw)

        # Seed server configuration (Outcome 6: Server Configuration)
        cursor.execute("SELECT COUNT(*) FROM server_config")
        if cursor.fetchone()[0] == 0:
            now_str = datetime.now().isoformat()
            sample_cfg = [
                ('session_timeout_minutes', '60', 'Security', 'User inactivity timeout before token invalidation', now_str),
                ('credential_rotation_days', '90', 'Security', 'Maximum days before password rotation is strictly enforced', now_str),
                ('max_failed_logins', '5', 'Access Control', 'Failed attempts before temporary account lockout', now_str),
                ('tls_min_version', 'TLSv1.3', 'Network', 'Minimum encryption protocol enforced for portal access', now_str),
                ('automated_backup_interval_hours', '24', 'Reliability', 'Frequency of automated SQLite snapshot archives', now_str)
            ]
            cursor.executemany("""
                INSERT INTO server_config (key, value, category, description, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, sample_cfg)

        # Seed sample student workstation telemetry if empty
        cursor.execute("SELECT COUNT(*) FROM student_pc_telemetry")
        if cursor.fetchone()[0] == 0:
            now_str = datetime.now().isoformat()
            sample_workstations = [
                ('DESKTOP-ALEX-CS', '00:1A:2B:3C:4D:5E', '192.168.1.104', 'alex.student', 'Windows 11 Pro', 14.2, 7840.0, 16384.0, 47.8, 185.4, 512.0, 36.2, now_str, 'ONLINE'),
                ('LAB-WORKSTATION-08', '00:14:22:01:23:45', '192.168.1.155', 'alex.student', 'Ubuntu 24.04 LTS', 28.5, 4120.0, 8192.0, 50.3, 112.0, 256.0, 43.8, now_str, 'ONLINE')
            ]
            cursor.executemany("""
                INSERT INTO student_pc_telemetry (hostname, mac_address, ip_address, student_username, os_platform, cpu_load, ram_used_mb, ram_total_mb, ram_usage_pct, disk_used_gb, disk_total_gb, disk_usage_pct, last_heartbeat, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, sample_workstations)

        # Seed initial forbidden websites list if empty
        cursor.execute("SELECT COUNT(*) FROM forbidden_websites")
        if cursor.fetchone()[0] == 0:
            now_str = datetime.now().isoformat()
            default_forbidden = [
                ('torrent', 'P2P / Unauthorized File Sharing', 'Copyright violation & excessive bandwidth consumption', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('pirate', 'Copyright Infringement / P2P', 'Unlicensed intellectual property distribution', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('proxy', 'Network Proxy / VPN Evasion', 'Bypassing perimeter network security controls', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('vpn-bypass', 'Network Tunneling Bypass', 'Unauthorized external tunnel creation', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('gambling', 'Gambling / High-Risk Content', 'Unregulated betting and financial risk', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('bet365', 'Online Betting Services', 'Commercial gambling platform', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('crypto', 'Unauthorized Cryptomining', 'Hardware wear & unauthorized server resource abuse', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('mining', 'Unauthorized Cryptomining', 'Cryptocurrency hash calculation traffic', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('phish', 'Phishing & Credential Theft', 'Malicious credential harvesting pages', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('malware', 'Malicious Software / C2', 'Botnet command & control and payload drops', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('darknet', 'Anonymizing Darknet Gateway', 'Tor/I2P routing nodes and illicit marketplaces', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('tiktok.com', 'Social Media / Distraction', 'Policy restricting video streaming during lab hours', 'ACTIVE', 'elena.admin', now_str, now_str),
                ('roblox.com', 'Online Gaming', 'Non-academic gaming platform bandwidth restriction', 'ACTIVE', 'elena.admin', now_str, now_str)
            ]
            cursor.executemany("""
                INSERT INTO forbidden_websites (domain_pattern, category, reason, status, added_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, default_forbidden)

        conn.commit()

def log_audit_event(event_type: str, actor_username: str, actor_role: str, details: str, ip_address: str = "127.0.0.1"):
    """Logs an incident or change to the Audit & Ticket Logs DB (as specified in DFD)."""
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs (event_type, actor_username, actor_role, details, ip_address, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_type, actor_username, actor_role, details, ip_address, datetime.now().isoformat()))
        conn.commit()

if __name__ == "__main__":
    init_databases()
    print("Databases successfully updated with all 6 Expected Outcomes schemas:")
    print("1. User & Roles Database ->", USER_ROLES_DB_PATH)
    print("2. Audit & Ticket Logs DB ->", AUDIT_TICKET_DB_PATH)
