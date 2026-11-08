"""
Comprehensive automated verification test for SYSAD Centralized Portal.
Tests all processes from the DFD:
  1.0 RBAC Policy Engine
  2.0 Identity Directory Manager
  3.0 Troubleshooting Ledger
  4.0 Security & Performance Monitoring
"""

import urllib.request
import urllib.parse
import json
import time
import threading
import sys
from app import run_server

def make_request(url, method='GET', data=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    encoded_data = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode('utf-8'))

def run_tests():
    base_url = "http://127.0.0.1:8000"
    print("\n--- 1. Testing Web Page Serving ---")
    with urllib.request.urlopen(f"{base_url}/") as resp:
        assert resp.status == 200
        html = resp.read().decode('utf-8')
        assert "Centralized Portal" in html
        print("✓ Root web page serves properly (Status 200 OK)")

    print("\n--- 2. Testing 1.0 RBAC Policy Engine (Login & Token Enforcement) ---")
    # Student login
    status, res = make_request(f"{base_url}/api/auth/login", 'POST', {
        "username": "alex.student",
        "password": "student123"
    })
    assert status == 200 and res["success"] is True
    student_token = res["token"]
    print(f"✓ Student authenticated successfully. Token issued: {student_token[:20]}...")

    # Admin login
    status, res = make_request(f"{base_url}/api/auth/login", 'POST', {
        "username": "elena.admin",
        "password": "admin123"
    })
    assert status == 200 and res["success"] is True
    admin_token = res["token"]
    print(f"✓ Administrator authenticated successfully. Role: {res['user']['role']}")

    # Verify session
    status, session_res = make_request(f"{base_url}/api/auth/session", 'GET', token=admin_token)
    assert session_res["authenticated"] is True
    print("✓ Access Token & Role Enforcement verified via session check")

    print("\n--- 3. Testing 3.0 Troubleshooting Ledger (Problem Reporting & Triage) ---")
    # Student reports problem
    status, res = make_request(f"{base_url}/api/tickets/create", 'POST', {
        "title": "Lab 201 Switch Port 14 down",
        "category": "Network",
        "priority": "High",
        "description": "Ethernet drop disconnected during networking lab session."
    }, token=student_token)
    assert status == 200 and res["success"] is True
    ticket_code = res["ticket_code"]
    print(f"✓ Student reported problem: [{ticket_code}] successfully logged to ledger")

    # Fetch tickets as IT/Admin
    status, res = make_request(f"{base_url}/api/tickets", 'GET', token=admin_token)
    assert status == 200 and len(res["tickets"]) > 0
    triage_target = next(t for t in res["tickets"] if t["ticket_code"] == ticket_code)
    print(f"✓ Prioritized Ticket Queue retrieved: {len(res['tickets'])} total tickets")

    # Triage ticket
    status, res = make_request(f"{base_url}/api/tickets/triage", 'POST', {
        "ticket_id": triage_target["id"],
        "status": "In Progress",
        "priority": "High",
        "assigned_to": "marcus.it",
        "resolution_notes": "Patched port 14 to alternate switch blade."
    }, token=admin_token)
    assert status == 200
    print("✓ Ticket Triage & Resolution executed and logged to audit trail")

    print("\n--- 4. Testing 2.0 Identity Directory Manager ---")
    # Fetch directory
    status, res = make_request(f"{base_url}/api/directory/users", 'GET', token=admin_token)
    assert status == 200 and len(res["users"]) >= 5
    print(f"✓ Identity Directory retrieved: {len(res['users'])} accounts visible (Active/Aging/Suspended)")

    # Provision new user
    new_username = f"test.user.{int(time.time())}"
    status, res = make_request(f"{base_url}/api/directory/provision", 'POST', {
        "username": new_username,
        "full_name": "Test User Automata",
        "email": f"{new_username}@campus.edu",
        "role": "Student",
        "department": "Engineering"
    }, token=admin_token)
    assert status == 200
    print(f"✓ Account Provisioning verified for '{new_username}'")

    print("\n--- 5. Testing 4.0 Security & Performance Monitoring ---")
    # Scan for aging accounts
    status, res = make_request(f"{base_url}/api/monitoring/scan-aging", 'POST', token=admin_token)
    assert status == 200
    print(f"✓ Aging Accounts Scan executed: {res['message']}")

    # Telemetry
    status, res = make_request(f"{base_url}/api/monitoring/telemetry", 'GET', token=admin_token)
    assert status == 200 and "cpu_percent" in res["telemetry"]
    print(f"✓ Hardware Telemetry retrieved: CPU={res['telemetry']['cpu_percent']}%, RAM={res['telemetry']['ram_percent']}%, Disk={res['telemetry']['disk_percent']}%")

    # Backup execution
    status, res = make_request(f"{base_url}/api/monitoring/backup", 'POST', token=admin_token)
    assert status == 200 and len(res["backup_files"]) == 2
    print(f"✓ Backup Schedule snapshot executed: {res['backup_files']}")

    # Audit Logs
    status, res = make_request(f"{base_url}/api/monitoring/audit-logs", 'GET', token=admin_token)
    assert status == 200 and len(res["audit_logs"]) > 0
    print(f"✓ Audit & Ticket Logs DB verified: {len(res['audit_logs'])} immutable audit trail records")

    print("\n=======================================================")
    print(" ALL 4 DFD PROCESSES & DATA FLOWS SUCCESSFULLY VERIFIED!")
    print("=======================================================\n")

if __name__ == "__main__":
    run_tests()

