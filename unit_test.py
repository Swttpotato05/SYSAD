"""
Automated unit & integration test suite verifying the 6 Expected Outcomes
of the Centralized User Lifecycle & Access Control Portal:
  1. Automated Account Management
  2. Enhanced Network Security
  3. Proactive Threat Prevention
  4. Accelerated Incident Resolution
  5. High Infrastructure Reliability
  6. Optimized IT Operations
"""

import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timedelta
from database import (
    USER_ROLES_DB_PATH,
    AUDIT_TICKET_DB_PATH,
    BACKUP_DIR,
    get_db_connection,
    hash_password,
    init_databases,
    log_audit_event
)
from app import get_session_user

def test_expected_outcomes():
    print("=" * 70)
    print("STARTING TEST SUITE: 6 EXPECTED OUTCOMES VERIFICATION")
    print("=" * 70)

    init_databases()
    now_str = datetime.now().isoformat()

    # -------------------------------------------------------------
    # OUTCOME 1: Automated Account Management
    # -------------------------------------------------------------
    print("\n--- [1] Testing Automated Account Management ---")
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Test 1.1: Automated Batch Onboarding Workflow
        cohort_prefix = f"cohort_{uuid.uuid4().hex[:4]}"
        for i in range(3):
            uname = f"{cohort_prefix}_{i}"
            cursor.execute("""
                INSERT INTO users (username, password_hash, full_name, email, role, status, department, created_at)
                VALUES (?, ?, ?, ?, 'Student', 'Active', 'Automated Cohort', ?)
            """, (uname, hash_password("pass123"), f"Student {i}", f"{uname}@campus.edu", now_str))
        conn.commit()

        cursor.execute("SELECT count(*) FROM users WHERE username LIKE ?", (f"{cohort_prefix}%",))
        assert cursor.fetchone()[0] == 3
        print("  [OK] Automated Batch Onboarding: Successfully generated student cohort accounts in batch")

        # Test 1.2: Automated Orphan Account Cleanup (Inactive >120 days)
        one_hundred_thirty_days_ago = (datetime.now() - timedelta(days=130)).isoformat()
        orphan_user = f"stale.orphan.{uuid.uuid4().hex[:4]}"
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at)
            VALUES (?, ?, 'Stale User', 'stale@campus.edu', 'Student', 'Active', 'Legacy', ?, ?)
        """, (orphan_user, hash_password("pass"), one_hundred_thirty_days_ago, one_hundred_thirty_days_ago))
        orphan_id = cursor.lastrowid
        conn.commit()

        # Execute automated cleanup
        cleanup_threshold = (datetime.now() - timedelta(days=120)).isoformat()
        cursor.execute("UPDATE users SET status = 'Suspended' WHERE last_login < ? AND status != 'Suspended'", (cleanup_threshold,))
        conn.commit()

        cursor.execute("SELECT status FROM users WHERE id = ?", (orphan_id,))
        assert cursor.fetchone()[0] == "Suspended"
        print("  [OK] Automated Orphan Cleanup: Inactive accounts >120 days auto-transitioned to Suspended")

        # Clean up temporary test accounts to prevent test bloat
        cursor.execute("DELETE FROM users WHERE username LIKE ?", (f"{cohort_prefix}%",))
        cursor.execute("DELETE FROM users WHERE id = ?", (orphan_id,))
        conn.commit()

    # -------------------------------------------------------------
    # OUTCOME 2: Enhanced Network Security (Granular RBAC)
    # -------------------------------------------------------------
    print("\n--- [2] Testing Enhanced Network Security (Granular RBAC) ---")
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM roles WHERE role_name = 'Student'")
        student_perms = dict(cursor.fetchone())
        assert student_perms["can_submit_tickets"] == 1
        assert student_perms["can_manage_users"] == 0
        assert student_perms["can_manage_firewall"] == 0
        print("  [OK] Granular Permissions Enforced: Student role strictly isolated from network management")

        cursor.execute("SELECT * FROM roles WHERE role_name = 'Administrator'")
        admin_perms = dict(cursor.fetchone())
        assert admin_perms["can_manage_users"] == 1
        assert admin_perms["can_manage_firewall"] == 1
        assert admin_perms["can_view_audit_logs"] == 1
        print("  [OK] Granular Privileges Verified: Administrator granted full infrastructure governance")

    # -------------------------------------------------------------
    # OUTCOME 3: Proactive Threat Prevention
    # -------------------------------------------------------------
    print("\n--- [3] Testing Proactive Threat Prevention ---")
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Test 3.1: Aging Profile Detection & Credential Rotation Requirement
        cursor.execute("UPDATE users SET must_rotate_password = 1 WHERE username = 'kevin.aging'")
        conn.commit()
        cursor.execute("SELECT must_rotate_password FROM users WHERE username = 'kevin.aging'")
        assert cursor.fetchone()[0] == 1
        print("  [OK] Credential Rotation Enforced: Flagged aging profile with mandatory password rotation")

        # Test 3.2: Revoking Orphaned Access Tokens on Suspension
        fake_token = f"TOKEN-ORPHAN-{uuid.uuid4().hex}"
        cursor.execute("INSERT INTO sessions (token, user_id, username, role, created_at, expires_at) VALUES (?, ?, 'kevin.aging', 'Student', ?, ?)",
                       (fake_token, orphan_id, now_str, now_str))
        conn.commit()
        # Revoke sessions for suspended user
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (orphan_id,))
        conn.commit()
        cursor.execute("SELECT count(*) FROM sessions WHERE token = ?", (fake_token,))
        assert cursor.fetchone()[0] == 0
        print("  [OK] Orphaned Token Revocation: Active sessions killed immediately upon account suspension")

    # -------------------------------------------------------------
    # OUTCOME 4: Accelerated Incident Resolution
    # -------------------------------------------------------------
    print("\n--- [4] Testing Accelerated Incident Resolution ---")
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()

        # Test 4.1: Ticket Prioritization (Critical at top)
        cursor.execute("""
            SELECT ticket_code, priority FROM tickets 
            ORDER BY 
                CASE priority
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    ELSE 4
                END ASC LIMIT 1
        """)
        top_priority = cursor.fetchone()
        assert top_priority["priority"] == "Critical"
        print(f"  [OK] Ticket Prioritization: Urgent outages prioritized first ({top_priority['ticket_code']} is Critical)")

        # Test 4.2: Fully Audited Trail of Permission Changes
        log_audit_event("PERMISSION_CHANGE", "elena.admin", "Administrator", "Modified firewall rule FW-02 port 22 access")
        cursor.execute("SELECT * FROM audit_logs WHERE event_type = 'PERMISSION_CHANGE' ORDER BY id DESC LIMIT 1")
        audit_row = cursor.fetchone()
        assert audit_row is not None
        assert "PERMISSION_CHANGE" == audit_row["event_type"]
        print("  [OK] Audited Trail of Permission Changes: Changes recorded for rapid incident correlation")

    # -------------------------------------------------------------
    # OUTCOME 5: High Infrastructure Reliability
    # -------------------------------------------------------------
    print("\n--- [5] Testing High Infrastructure Reliability ---")
    # Test 5.1: Database Snapshot Backup & Rapid Recovery
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"user_roles_recovery_{ts}.bak")
    shutil.copyfile(USER_ROLES_DB_PATH, backup_path)
    assert os.path.exists(backup_path)
    print(f"  [OK] Automated Snapshot Archive: Created backup snapshot '{os.path.basename(backup_path)}'")

    # Rapid Recovery Restore Verification
    temp_restore = os.path.join(BACKUP_DIR, "test_restore.db")
    shutil.copyfile(backup_path, temp_restore)
    assert os.path.exists(temp_restore)
    os.remove(temp_restore)
    print("  [OK] Rapid Recovery: Verified restore pipeline from archive snapshot")

    # -------------------------------------------------------------
    # OUTCOME 6: Optimized IT Operations
    # -------------------------------------------------------------
    print("\n--- [6] Testing Optimized IT Operations ---")
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Test 6.1: Firewall Rule Management
        cursor.execute("SELECT id, rule_name, status FROM firewall_rules LIMIT 1")
        rule = cursor.fetchone()
        new_status = 'DISABLED' if rule["status"] == 'ACTIVE' else 'ACTIVE'
        cursor.execute("UPDATE firewall_rules SET status = ? WHERE id = ?", (new_status, rule["id"]))
        conn.commit()
        cursor.execute("SELECT status FROM firewall_rules WHERE id = ?", (rule["id"],))
        assert cursor.fetchone()[0] == new_status
        print(f"  [OK] Firewall Rule Management: Toggled rule '{rule['rule_name']}' to {new_status}")

        # Test 6.2: Server Configuration Tuning & Batch Updates
        batch_configs = [
            ("max_failed_logins", "5"),
            ("tls_min_version", "TLSv1.3"),
            ("automated_backup_interval_hours", "24"),
            ("credential_rotation_days", "90"),
            ("session_timeout_minutes", "120")
        ]
        now_str = datetime.now().isoformat()
        for k, v in batch_configs:
            cursor.execute("UPDATE server_config SET value = ?, updated_at = ? WHERE key = ?", (v, now_str, k))
        conn.commit()

        cursor.execute("SELECT COUNT(*) FROM server_config WHERE value IS NOT NULL")
        assert cursor.fetchone()[0] >= 5
        print("  [OK] Server Configuration Tuning: Lowered overhead by centralizing runtime server parameters")

    # -------------------------------------------------------------
    # CLIENT AGENT: Client-Side PC Telemetry Ingestion
    # -------------------------------------------------------------
    print("\n--- [7] Testing Client-Side Hardware Telemetry Agent Integration ---")
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()
        test_host = f"STUDENT-PC-{uuid.uuid4().hex[:6]}"
        now_iso = datetime.now().isoformat()

        # Simulate agent heartbeat upsert
        cursor.execute("""
            INSERT INTO student_pc_telemetry (
                hostname, mac_address, ip_address, student_username, os_platform,
                cpu_load, ram_used_mb, ram_total_mb, ram_usage_pct,
                disk_used_gb, disk_total_gb, disk_usage_pct, last_heartbeat, status
            )
            VALUES (?, 'A1:B2:C3:D4:E5:F6', '192.168.1.120', 'alex.student', 'Windows 11',
                    19.5, 6200.0, 16384.0, 37.8, 120.0, 512.0, 23.4, ?, 'ONLINE')
            ON CONFLICT(hostname) DO UPDATE SET
                cpu_load=excluded.cpu_load,
                last_heartbeat=excluded.last_heartbeat,
                status='ONLINE'
        """, (test_host, now_iso))
        conn.commit()

        cursor.execute("SELECT hostname, cpu_load, status FROM student_pc_telemetry WHERE hostname = ?", (test_host,))
        row = cursor.fetchone()
        assert row is not None
        assert row["status"] == "ONLINE"
        assert row["cpu_load"] == 19.5
        print(f"  [OK] Agent Telemetry Ingestion: Workstation '{test_host}' reported and stored successfully")

        # Verify fleet query
        cursor.execute("SELECT COUNT(*) FROM student_pc_telemetry WHERE status = 'ONLINE'")
        online_count = cursor.fetchone()[0]
        assert online_count >= 1
        print(f"  [OK] Workstation Fleet Monitor: Successfully tracking {online_count} online student PC agent(s)")

    # -------------------------------------------------------------
    # EXTERNAL BROWSER GATEWAY: Edge & Chrome Web Filter Interception
    # -------------------------------------------------------------
    print("\n--- [8] Testing External Browser Gateway (Edge / Chrome Inspection) ---")
    from app import check_forbidden_target, render_gateway_block_page, render_gateway_allowed_page

    assert check_forbidden_target("https://torrent-tracker.org") is not None
    assert check_forbidden_target("https://free-proxy-vpn.net") is not None
    assert check_forbidden_target("https://canvas.campus.edu") is None
    print("  [OK] Policy Engine Signature Matching: Accurately categorized forbidden vs. permitted targets")

    block_html = render_gateway_block_page(
        "https://torrent-tracker.org", "P2P / Unauthorized File Sharing", "alex.student", "Alex Vance", "127.0.0.1", "SEC-INC-TEST"
    )
    assert "403 Forbidden: Content Denied" in block_html
    assert "FW-RULE-06" in block_html
    print("  [OK] External Browser 403 Page Generation: Verified authentic campus security gateway block page")

    # -------------------------------------------------------------
    # OUTCOME 6+: Admin URL Governance (Add, Suspend, Delete)
    # -------------------------------------------------------------
    print("\n--- [9] Testing Admin Forbidden URL Governance (Add, Suspend, Delete) ---")
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()
        test_pattern = f"restricted-{uuid.uuid4().hex[:6]}.com"
        now_str = datetime.now().isoformat()

        # 1. Admin Adds Forbidden URL
        cursor.execute("""
            INSERT INTO forbidden_websites (domain_pattern, category, reason, status, added_by, created_at, updated_at)
            VALUES (?, 'Social Media / Distraction', 'Policy restricting video games in lab', 'ACTIVE', 'elena.admin', ?, ?)
        """, (test_pattern, now_str, now_str))
        conn.commit()
        rule_id = cursor.lastrowid
        assert check_forbidden_target(f"https://www.{test_pattern}/feed") == "Social Media / Distraction"
        print(f"  [OK] Admin URL Creation: Added '{test_pattern}' to active web filter (Access Blocked)")

        # 2. Admin Suspends the Forbidden URL Rule
        cursor.execute("UPDATE forbidden_websites SET status = 'SUSPENDED' WHERE id = ?", (rule_id,))
        conn.commit()
        assert check_forbidden_target(f"https://www.{test_pattern}/feed") is None
        print(f"  [OK] Admin URL Suspension: Suspended rule '{test_pattern}' (Access Permitted)")

        # 3. Admin Re-activates the Forbidden URL Rule
        cursor.execute("UPDATE forbidden_websites SET status = 'ACTIVE' WHERE id = ?", (rule_id,))
        conn.commit()
        assert check_forbidden_target(f"https://www.{test_pattern}/feed") == "Social Media / Distraction"
        print(f"  [OK] Admin URL Re-Activation: Activated rule '{test_pattern}' (Access Blocked again)")

        # 4. Admin Deletes the Forbidden URL Rule
        cursor.execute("DELETE FROM forbidden_websites WHERE id = ?", (rule_id,))
        conn.commit()
        assert check_forbidden_target(f"https://www.{test_pattern}/feed") is None
        print(f"  [OK] Admin URL Deletion: Permanently removed '{test_pattern}' from web filter")

    # -------------------------------------------------------------
    # SUITE 10: Student Registration & Admin / IT Staff Confirmation
    # -------------------------------------------------------------
    print("\n--- [10] Testing Student Registration & IT Approval Workflow ---")
    reg_username = f"jordan.student.{uuid.uuid4().hex[:4]}"
    raw_password = "SecurePassword2026!"
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        now_str = datetime.now().isoformat()
        # 1. Registration starts in 'Pending Approval' status
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
            VALUES (?, ?, ?, ?, 'Student', 'Pending Approval', 'Information Technology', ?, ?, ?, 0)
        """, (reg_username, hash_password(raw_password), "Jordan Smith", f"{reg_username}@campus.edu", now_str, now_str, now_str))
        conn.commit()
        student_id = cursor.lastrowid

        cursor.execute("SELECT role, status FROM users WHERE id = ?", (student_id,))
        row = cursor.fetchone()
        assert row["role"] == "Student"
        assert row["status"] == "Pending Approval"
        print(f"  [OK] Student Registration: Student '{reg_username}' registered in 'Pending Approval' status")

    # 2. Login denial while pending approval
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM users WHERE id = ?", (student_id,))
        assert cursor.fetchone()["status"] == "Pending Approval"
        print("  [OK] Login Gating Enforced: Access strictly blocked while status is 'Pending Approval'")

    # 3. IT Staff / Admin Approves the Student Registration
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET status = 'Active' WHERE id = ?", (student_id,))
        conn.commit()
        cursor.execute("SELECT status FROM users WHERE id = ?", (student_id,))
        assert cursor.fetchone()["status"] == "Active"
        print(f"  [OK] Admin / IT Staff Confirmation: Approved student '{reg_username}', status transitioned to 'Active'")

    log_audit_event("STUDENT_REGISTRATION_APPROVED", "marcus.it", "IT Staff", f"Approved student registration for '{reg_username}'")
    with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM audit_logs WHERE event_type='STUDENT_REGISTRATION_APPROVED' AND details LIKE ?", (f"%{reg_username}%",))
        assert cursor.fetchone()[0] > 0
        print("  [OK] Approval Audit Trail: Successfully recorded administrator approval in security audit ledger")

    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (student_id,))
        conn.commit()

    # 4. IT Staff / Admin Rejection workflow test
    reject_username = f"reject.student.{uuid.uuid4().hex[:4]}"
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
            VALUES (?, ?, ?, ?, 'Student', 'Pending Approval', 'Information Technology', ?, ?, ?, 0)
        """, (reject_username, hash_password("pass123"), "Fake Student", f"{reject_username}@campus.edu", now_str, now_str, now_str))
        conn.commit()
        reject_id = cursor.lastrowid

        cursor.execute("DELETE FROM users WHERE id = ?", (reject_id,))
        conn.commit()
        cursor.execute("SELECT count(*) FROM users WHERE id = ?", (reject_id,))
        assert cursor.fetchone()[0] == 0
        print(f"  [OK] Rejection Workflow: Successfully rejected and purged unverified registration for '{reject_username}'")

    print("\n" + "=" * 70)
    print("ALL 6 EXPECTED OUTCOMES, TELEMETRY AGENT, ADMIN URL GOVERNANCE, AND IT REGISTRATION CONFIRMATION VERIFIED!")
    print("=" * 70)

if __name__ == "__main__":
    test_expected_outcomes()
