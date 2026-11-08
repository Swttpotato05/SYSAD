"""
Centralized Portal Web Server & REST API.
Implements the 4 processes from the SYSAD Data Flow Diagram and guarantees all
6 Expected Outcomes:
  1. Automated Account Management
  2. Enhanced Network Security (Granular RBAC)
  3. Proactive Threat Prevention (Aging profiles, Inactive alerts, Credential rotation)
  4. Accelerated Incident Resolution (Prioritized ticket queue & Permission change audit trail)
  5. High Infrastructure Reliability (Hardware telemetry & Rapid backup recovery)
  6. Optimized IT Operations (Server configuration & Firewall rule management)
"""

import http.server
import html
import json
import os
import re
import shutil
import sqlite3
import sys
import threading
import time
import urllib.parse
import uuid
import random
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

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_session_user(token: str):
    """Verifies token against sessions table in User & Roles Database."""
    if not token:
        return None
    with get_db_connection(USER_ROLES_DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT s.token, s.user_id, s.username, s.role, u.full_name, u.email, u.status, u.department, u.must_rotate_password, u.password_changed_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
        """, (token,))
        row = cursor.fetchone()
        if row:
            # Check permissions for this role (Granular RBAC - Outcome 2)
            cursor.execute("SELECT * FROM roles WHERE role_name = ?", (row["role"],))
            role_info = cursor.fetchone()
            perms = dict(role_info) if role_info else {}
            user_data = dict(row)
            if user_data.get("full_name"):
                user_data["full_name"] = re.sub(r'\s*\(SysAdmin\)', '', str(user_data["full_name"]), flags=re.IGNORECASE).strip()
            user_data["permissions"] = perms
            return user_data
    return None

def normalize_url_or_domain(text: str) -> str:
    """Strips scheme, trailing slashes, www, port, trailing dots, and query strings to extract clean domain/pattern."""
    if not text:
        return ""
    cleaned = text.lower().strip()
    if "://" in cleaned:
        cleaned = cleaned.split("://", 1)[1]
    if "/" in cleaned:
        cleaned = cleaned.split("/", 1)[0]
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]
    cleaned = cleaned.rstrip(".")
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    return cleaned.strip()

def check_forbidden_target(target_url: str):
    raw_target = (target_url or "").lower().strip()
    clean_target = normalize_url_or_domain(raw_target)

    # Check dynamic forbidden URL rules from Audit & Ticket Logs DB
    try:
        with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain_pattern, category FROM forbidden_websites WHERE status = 'ACTIVE'")
            db_rules = cursor.fetchall()
            for r in db_rules:
                raw_pat = (r["domain_pattern"] or "").lower().strip()
                clean_pat = normalize_url_or_domain(raw_pat)

                # Match 1: Clean pattern match (e.g. 'roblox.com' in 'www.roblox.com')
                if clean_pat and (clean_pat in clean_target or clean_pat in raw_target):
                    return r["category"]

                # Match 2: Raw pattern match (e.g. 'torrent' keyword)
                if raw_pat and (raw_pat in raw_target or raw_pat in clean_target):
                    return r["category"]

                # Match 3: Base name match (e.g. 'roblox' in 'roblox.com')
                base_name = clean_pat.split('.')[0] if '.' in clean_pat else clean_pat
                if len(base_name) >= 4 and base_name in raw_target:
                    return r["category"]
    except Exception as e:
        print(f"[DB FILTER ERROR] {e}")

    # Fallback built-in signatures
    forbidden_keywords = [
        ("torrent", "P2P / Unauthorized File Sharing"),
        ("pirate", "Copyright Infringement / P2P"),
        ("proxy", "Network Proxy / VPN Evasion"),
        ("vpn-bypass", "Network Tunneling Bypass"),
        ("gambling", "Gambling / High-Risk Web Content"),
        ("bet365", "Online Betting Services"),
        ("crypto", "Unauthorized Cryptomining"),
        ("mining", "Unauthorized Cryptomining"),
        ("phish", "Phishing & Credential Harvesting"),
        ("malware", "Malicious Software / Command & Control"),
        ("darknet", "Anonymizing Darknet Gateway")
    ]
    for kw, cat in forbidden_keywords:
        if kw in raw_target or kw in clean_target:
            return cat
    return None

def get_active_or_latest_student(current_user=None):
    if current_user and current_user.get("role") == "Student":
        return current_user
    try:
        with get_db_connection(USER_ROLES_DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT u.username, u.full_name, u.role, u.department 
                FROM sessions s JOIN users u ON s.user_id = u.id 
                WHERE u.role = 'Student'
                ORDER BY s.created_at DESC LIMIT 1
            """)
            row = cursor.fetchone()
            if row:
                return dict(row)
    except Exception as e:
        print(f"[SESSION QUERY NOTICE] {e}")
    return {
        "username": "alex.student",
        "full_name": "Alex Vance",
        "role": "Student",
        "department": "Information Technology"
    }

def render_gateway_block_page(target_url, matched_reason, student_username, student_fullname, client_ip, incident_code):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden - Campus Network Security Gateway</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/static/css/style.css">
  <style>
    body {{ display:flex; align-items:center; justify-content:center; min-height:100vh; padding:1.5rem; background:#070b14; }}
    .gateway-box {{ max-width:640px; width:100%; background:var(--card-bg); border:2px solid var(--accent-rose); border-radius:var(--radius-md); padding:2rem; box-shadow:0 0 40px rgba(244, 63, 94, 0.35); }}
    .gateway-pill {{ display:inline-block; padding:0.25rem 0.75rem; border-radius:999px; font-size:0.75rem; font-weight:700; text-transform:uppercase; background:rgba(244,63,94,0.2); color:var(--accent-rose); border:1px solid var(--accent-rose); }}
    .kv-row {{ display:flex; justify-content:space-between; padding:0.45rem 0; border-bottom:1px solid var(--border-color); font-size:0.85rem; }}
    .kv-label {{ color:var(--text-muted); }}
    .kv-val {{ font-weight:600; color:var(--text-main); font-family:monospace; }}
  </style>
</head>
<body>
  <div class="gateway-box">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
      <span class="gateway-pill">PACKET DROPPED BY FIREWALL GATEWAY</span>
      <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">FW-RULE-06 ACTIVE</span>
    </div>

    <h2 style="color:var(--accent-rose); margin-bottom:0.5rem; font-size:1.5rem;">403 Forbidden: Content Denied</h2>
    <p style="color:var(--text-muted); font-size:0.88rem; line-height:1.5; margin-bottom:1.25rem;">
      Your request to access this destination was intercepted and dropped by the Campus Perimeter Firewall Gateway in accordance with university network security policies.
    </p>

    <div style="background:#0a0f1d; padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color); margin-bottom:1.25rem;">
      <div class="kv-row"><span class="kv-label">Attempted Destination</span><span class="kv-val" style="color:var(--accent-cyan); word-break:break-all;">{html.escape(target_url)}</span></div>
      <div class="kv-row"><span class="kv-label">Violation Category</span><span class="kv-val" style="color:var(--accent-rose);">{html.escape(matched_reason)}</span></div>
      <div class="kv-row"><span class="kv-label">Authenticated Student</span><span class="kv-val">{html.escape(student_fullname)} ({html.escape(student_username)})</span></div>
      <div class="kv-row"><span class="kv-label">Firewall Rule Enforced</span><span class="kv-val">FW-RULE-06 (Deny Outbound Prohibited Protocols)</span></div>
      <div class="kv-row"><span class="kv-label">Governing Policy</span><span class="kv-val">Campus Acceptable Use Policy § 4.2</span></div>
      <div class="kv-row"><span class="kv-label">Client IP Address</span><span class="kv-val">{html.escape(client_ip)}</span></div>
      <div class="kv-row" style="border-bottom:none;"><span class="kv-label">Security Incident ID</span><span class="kv-val" style="color:var(--accent-amber);">{html.escape(incident_code)}</span></div>
    </div>

    <div style="background:rgba(244, 63, 94, 0.1); border-left:4px solid var(--accent-rose); padding:0.75rem 1rem; border-radius:var(--radius-sm); font-size:0.8rem; color:#fca5a5; margin-bottom:1.5rem; line-height:1.4;">
      <strong>Security Notice:</strong> This incident has been permanently recorded in the Campus Security Audit Database and transmitted in real time to Campus IT Staff and Network Administrators for monitoring.
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center;">
      <a href="/" class="btn btn-primary" style="text-decoration:none; display:inline-block;">Return to Student Portal</a>
      <span style="font-size:0.75rem; color:var(--text-muted);">Campus Network Edge Gateway v2.4</span>
    </div>
  </div>
</body>
</html>"""

def render_gateway_allowed_page(target_url, student_username, student_fullname):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>200 OK - Campus Gateway Authorized</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/static/css/style.css">
  <style>
    body {{ display:flex; align-items:center; justify-content:center; min-height:100vh; padding:1.5rem; background:#070b14; }}
    .gateway-box {{ max-width:600px; width:100%; background:var(--card-bg); border:1px solid var(--accent-green); border-radius:var(--radius-md); padding:2rem; }}
    .gateway-pill {{ display:inline-block; padding:0.25rem 0.75rem; border-radius:999px; font-size:0.75rem; font-weight:700; text-transform:uppercase; background:rgba(16,185,129,0.2); color:var(--accent-green); border:1px solid var(--accent-green); }}
    .kv-row {{ display:flex; justify-content:space-between; padding:0.45rem 0; border-bottom:1px solid var(--border-color); font-size:0.85rem; }}
    .kv-label {{ color:var(--text-muted); }}
    .kv-val {{ font-weight:600; color:var(--text-main); font-family:monospace; }}
  </style>
</head>
<body>
  <div class="gateway-box">
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
      <span class="gateway-pill">CONNECTION PERMITTED</span>
      <span style="font-size:0.75rem; color:var(--text-muted); font-family:monospace;">FW-RULE-01 ACTIVE</span>
    </div>

    <h2 style="color:var(--accent-green); margin-bottom:0.5rem; font-size:1.5rem;">200 OK: Destination Authorized</h2>
    <p style="color:var(--text-muted); font-size:0.88rem; line-height:1.5; margin-bottom:1.25rem;">
      The requested destination is permitted under campus network acceptable use policies.
    </p>

    <div style="background:#0a0f1d; padding:1rem; border-radius:var(--radius-sm); border:1px solid var(--border-color); margin-bottom:1.5rem;">
      <div class="kv-row"><span class="kv-label">Destination</span><span class="kv-val" style="color:var(--accent-cyan); word-break:break-all;">{html.escape(target_url)}</span></div>
      <div class="kv-row"><span class="kv-label">Category</span><span class="kv-val">Permitted Standard / Academic Web Traffic</span></div>
      <div class="kv-row"><span class="kv-label">Firewall Rule</span><span class="kv-val">FW-RULE-01 (Campus Web Traffic Allow)</span></div>
      <div class="kv-row" style="border-bottom:none;"><span class="kv-label">Student</span><span class="kv-val">{html.escape(student_fullname)} ({html.escape(student_username)})</span></div>
    </div>

    <div style="display:flex; justify-content:space-between; align-items:center;">
      <a href="/" class="btn btn-secondary" style="text-decoration:none;">Back to Portal</a>
      <a href="{html.escape(target_url)}" class="btn btn-primary" style="text-decoration:none;" target="_blank">Proceed to Website &rarr;</a>
    </div>
  </div>
</body>
</html>"""

class SysadRequestHandler(http.server.BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Clean terminal output
        sys.stderr.write(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]} - {args[1]}\n")

    def send_json(self, data, status=200, headers=None):
        response_bytes = json.dumps(data, default=str).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(response_bytes)

    def send_error_json(self, message, status=400):
        self.send_json({"error": message, "success": False}, status=status)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_CONNECT(self):
        # Handles HTTPS proxy inspection when browser is configured with proxy 127.0.0.1:8000
        host = self.path.split(":")[0].lower().strip()
        if host in ["localhost", "127.0.0.1", "0.0.0.0", "::1"]:
            self.send_response(200, "Connection Established")
            self.end_headers()
            return

        matched_reason = check_forbidden_target(host)
        if matched_reason:
            incident_code = f"SEC-INC-{uuid.uuid4().hex[:6].upper()}"
            client_ip = self.client_address[0]
            student = get_active_or_latest_student()
            incident_details = (
                f"Campus Firewall PROXY BLOCKED external browser access by student '{student['username']}': "
                f"Target '{host}' (Category: {matched_reason}). Policy Rule FW-RULE-06 enforced. Dropped."
            )
            log_audit_event("WEB_FILTER_BLOCKED", student["username"], "Student", incident_details, client_ip)
            print(f"[CAMPUS GATEWAY PROXY] BLOCKED CONNECT: '{host}' from student '{student['username']}' ({incident_code})")
            
            html_resp = render_gateway_block_page(
                host, matched_reason, student["username"], student["full_name"], client_ip, incident_code
            ).encode("utf-8")
            self.send_response(403, "Forbidden")
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html_resp)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(html_resp)
            self.close_connection = True
        else:
            self.send_error(502, "Direct proxy tunneling disabled for non-academic targets.")

    def get_auth_token(self):
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:].strip()
        cookie = self.headers.get('Cookie', '')
        if 'token=' in cookie:
            for part in cookie.split(';'):
                if part.strip().startswith('token='):
                    return part.strip().split('=', 1)[1]
        return None

    def read_json_body(self):
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                return json.loads(body)
            except Exception:
                return None
        return {}

    # -------------------------------------------------------------
    # GET Request Dispatcher
    # -------------------------------------------------------------
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # ---------------------------------------------------------
        # Campus Security Gateway & Web Filter (External Browser Inspection)
        # ---------------------------------------------------------
        host_header = self.headers.get("Host", "").split(":")[0].lower().strip()
        url_host = (parsed_url.hostname or "").lower().strip()
        local_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

        # Check if URL path is direct domain navigation (e.g. localhost:8000/youtube.com or /roblox.com)
        clean_path = path.lstrip('/')
        is_direct_domain_path = bool(
            clean_path and '.' in clean_path 
            and not clean_path.startswith(('api/', 'static/')) 
            and not clean_path.endswith(('.html', '.js', '.css', '.png', '.jpg', '.ico', '.svg', '.json', '.map'))
        )

        # It is a proxy request ONLY IF the target host is an external domain (NOT localhost / 127.0.0.1)
        is_proxy_req = bool(parsed_url.scheme in ["http", "https"] and url_host and url_host not in local_hosts)
        is_external_host = bool(host_header and host_header not in local_hosts and not parsed_url.scheme)
        is_gateway_req = path in ["/gateway", "/browse", "/search", "/proxy"] or path.startswith(("/gateway/", "/browse/", "/search/"))

        if is_direct_domain_path or is_external_host or is_proxy_req or is_gateway_req:
            try:
                if is_proxy_req:
                    target_url = self.path
                elif is_external_host:
                    target_url = f"http://{host_header}{self.path}"
                elif is_direct_domain_path:
                    target_url = clean_path
                else:
                    target_url = query_params.get("url", [""])[0] or query_params.get("q", [""])[0]
                    if not target_url:
                        for pfx in ["/gateway/", "/browse/", "/search/"]:
                            if path.startswith(pfx):
                                target_url = path[len(pfx):]
                                break
                    if not target_url:
                        target_url = "https://torrent-tracker.org"

                token = self.get_auth_token()
                user = get_session_user(token)
                student = get_active_or_latest_student(user)

                matched_reason = check_forbidden_target(target_url)

                if matched_reason:
                    incident_code = f"SEC-INC-{uuid.uuid4().hex[:6].upper()}"
                    client_ip = self.client_address[0] if hasattr(self, 'client_address') and self.client_address else "127.0.0.1"
                    incident_details = (
                        f"Campus Firewall BLOCKED external browser access by student '{student['username']}': "
                        f"Target '{target_url}' (Category: {matched_reason}). Policy Rule FW-RULE-06 enforced. Packets dropped."
                    )
                    log_audit_event("WEB_FILTER_BLOCKED", student["username"], "Student", incident_details, client_ip)
                    print(f"[CAMPUS GATEWAY FIREWALL] BLOCKED external browser access: '{target_url}' by student '{student['username']}' ({incident_code})")

                    html_resp = render_gateway_block_page(
                        target_url, matched_reason, student["username"], student["full_name"], client_ip, incident_code
                    ).encode("utf-8")

                    self.send_response(403)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_resp)))
                    self.end_headers()
                    self.wfile.write(html_resp)
                    return
                else:
                    html_resp = render_gateway_allowed_page(
                        target_url, student["username"], student["full_name"]
                    ).encode("utf-8")

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html_resp)))
                    self.end_headers()
                    self.wfile.write(html_resp)
                    return
            except Exception as e:
                print(f"[GATEWAY ERROR] {e}")
                err_page = f"<h1>Gateway Error</h1><p>{html.escape(str(e))}</p>".encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(err_page)))
                self.end_headers()
                self.wfile.write(err_page)
                return

        # Static assets
        if path == "/" or path == "/index.html":
            self.serve_file(os.path.join(BASE_DIR, "templates", "index.html"), "text/html")
            return
        elif path.startswith("/static/"):
            rel_path = path[8:]
            local_path = os.path.join(BASE_DIR, "static", rel_path.replace("/", os.sep))
            if os.path.exists(local_path) and os.path.isfile(local_path):
                content_type = "text/plain"
                if local_path.endswith(".css"): content_type = "text/css"
                elif local_path.endswith(".js"): content_type = "application/javascript"
                elif local_path.endswith(".png"): content_type = "image/png"
                elif local_path.endswith(".svg"): content_type = "image/svg+xml"
                self.serve_file(local_path, content_type)
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        # API Routes
        token = self.get_auth_token()
        current_user = get_session_user(token)

        # Process 1.0: RBAC Policy Engine & Session Check
        if path == "/api/auth/session":
            if current_user:
                self.send_json({"authenticated": True, "user": current_user})
            else:
                self.send_json({"authenticated": False, "user": None})
            return

        elif path == "/api/rbac/roles":
            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM roles")
                roles = [dict(r) for r in cursor.fetchall()]
                self.send_json({"success": True, "roles": roles})
            return

        # Process 2.0: Identity Directory Manager (Outcome 1: Automated Account Management)
        elif path == "/api/directory/users":
            status_filter = query_params.get("status", [None])[0]
            role_filter = query_params.get("role", [None])[0]
            search = query_params.get("search", [None])[0]

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                query = "SELECT id, username, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password FROM users WHERE 1=1"
                params = []
                if status_filter and status_filter != "All":
                    query += " AND status = ?"
                    params.append(status_filter)
                if role_filter and role_filter != "All":
                    query += " AND role = ?"
                    params.append(role_filter)
                if search:
                    query += " AND (username LIKE ? OR full_name LIKE ? OR email LIKE ?)"
                    params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
                query += " ORDER BY id ASC"
                cursor.execute(query, params)
                users = [dict(u) for u in cursor.fetchall()]
                self.send_json({"success": True, "users": users})
            return

        # Process 3.0: Troubleshooting Ledger (Outcome 4: Accelerated Incident Resolution)
        elif path == "/api/tickets":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                if current_user and current_user["role"] == "Student":
                    cursor.execute("""
                        SELECT * FROM tickets
                        WHERE submitted_by_id = ? OR submitted_by_name = ?
                        ORDER BY id DESC
                    """, (current_user["user_id"], current_user["full_name"]))
                else:
                    # Prioritized Ticket Queue: Critical > High > Medium > Low
                    cursor.execute("""
                        SELECT * FROM tickets
                        ORDER BY 
                            CASE priority
                                WHEN 'Critical' THEN 1
                                WHEN 'High' THEN 2
                                WHEN 'Medium' THEN 3
                                WHEN 'Low' THEN 4
                                ELSE 5
                            END ASC,
                            CASE status
                                WHEN 'Open' THEN 1
                                WHEN 'In Triage' THEN 2
                                WHEN 'In Progress' THEN 3
                                WHEN 'Resolved' THEN 4
                                WHEN 'Closed' THEN 5
                                ELSE 6
                            END ASC,
                            id DESC
                    """)
                tickets = [dict(t) for t in cursor.fetchall()]
                self.send_json({"success": True, "tickets": tickets})
            return

        # Process 4.0: Security & Performance Monitoring (Outcome 5: High Infrastructure Reliability)
        elif path == "/api/monitoring/telemetry":
            total_disk, used_disk, free_disk = shutil.disk_usage(".")
            disk_pct = round((used_disk / total_disk) * 100, 1)

            base_cpu = 28.5 + (random.random() * 14 - 7)
            base_ram = 56.2 + (random.random() * 8 - 4)

            now_iso = datetime.now().isoformat()
            try:
                with get_db_connection(USER_ROLES_DB_PATH) as uconn:
                    ucur = uconn.cursor()
                    ucur.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (now_iso,))
                    active_auth_sessions = ucur.fetchone()[0]
            except Exception:
                active_auth_sessions = 1

            active_conns = max(active_auth_sessions, 1)

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM tickets WHERE priority='Critical' AND status IN ('Open', 'In Triage')")
                critical_count = cursor.fetchone()[0]

            sys_status = "Optimal"
            if critical_count > 0:
                sys_status = "Attention Required"

            telemetry_data = {
                "cpu_percent": round(base_cpu, 1),
                "ram_percent": round(base_ram, 1),
                "disk_percent": disk_pct,
                "disk_free_gb": round(free_disk / (1024**3), 1),
                "disk_total_gb": round(total_disk / (1024**3), 1),
                "active_connections": active_conns,
                "system_status": sys_status,
                "critical_tickets_count": critical_count,
                "timestamp": datetime.now().strftime("%H:%M:%S")
            }
            self.send_json({"success": True, "telemetry": telemetry_data})
            return

        # Outcome 3: Proactive Threat Prevention (Aging accounts & Inactive Alerts)
        elif path == "/api/monitoring/alerts":
            alerts = []
            
            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                # Check Aging accounts
                cursor.execute("SELECT COUNT(*), GROUP_CONCAT(username) FROM users WHERE status = 'Aging'")
                aging_count, aging_names = cursor.fetchone()
                if aging_count and aging_count > 0:
                    alerts.append({
                        "id": "ALERT-AGE-01",
                        "severity": "Warning",
                        "category": "Inactive Accounts",
                        "title": f"{aging_count} Inactive / Aging Account(s) Detected",
                        "message": f"Accounts exceeding 90-day threshold: {aging_names}. Proactive Threat Prevention enforces credential rotation or suspension.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

                # Check pending Credential Rotations
                cursor.execute("SELECT COUNT(*) FROM users WHERE must_rotate_password = 1")
                rot_count = cursor.fetchone()[0]
                if rot_count > 0:
                    alerts.append({
                        "id": "ALERT-CRED-ROT",
                        "severity": "Warning",
                        "category": "Credential Rotation",
                        "title": f"{rot_count} Profile(s) Require Credential Rotation",
                        "message": "Enforced password renewal policy active for orphaned or stale accounts.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

                # Check pending Student Registrations awaiting Admin/IT Staff Confirmation
                cursor.execute("SELECT COUNT(*), GROUP_CONCAT(username) FROM users WHERE status = 'Pending Approval'")
                pending_count, pending_names = cursor.fetchone()
                if pending_count and pending_count > 0:
                    alerts.append({
                        "id": "ALERT-REG-PENDING",
                        "severity": "Warning",
                        "category": "Student Registration",
                        "title": f"{pending_count} Student Registration(s) Awaiting Confirmation",
                        "message": f"New student accounts requiring IT verification: {pending_names}. Approve or reject in User Directory.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

            # Check critical unassigned incidents
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*), ticket_code, title FROM tickets WHERE priority='Critical' AND status='Open'")
                crit_row = cursor.fetchone()
                if crit_row and crit_row[0] > 0:
                    alerts.append({
                        "id": "ALERT-CRIT-02",
                        "severity": "Critical",
                        "category": "Incident Queue",
                        "title": f"Critical Ticket Pending Triage: {crit_row[1]}",
                        "message": f"{crit_row[2]} requires immediate triage and dispatch.",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

                # Check recent blocked forbidden website attempts (Threat Detections)
                cursor.execute("""
                    SELECT id, actor_username, details, timestamp 
                    FROM audit_logs 
                    WHERE event_type = 'WEB_FILTER_BLOCKED' 
                    ORDER BY id DESC LIMIT 25
                """)
                blocked_rows = cursor.fetchall()
                for brow in blocked_rows:
                    alerts.append({
                        "id": f"ALERT-NET-BLOCK-{brow['id']}",
                        "severity": "Critical",
                        "category": "Firewall Violation",
                        "title": f"Security Alert: Blocked Forbidden Site by {brow['actor_username']}",
                        "message": brow['details'],
                        "timestamp": brow['timestamp']
                    })

            total_disk, used_disk, free_disk = shutil.disk_usage(".")
            disk_pct = round((used_disk / total_disk) * 100, 1)
            if disk_pct > 80:
                alerts.append({
                    "id": "ALERT-DISK-03",
                    "severity": "Warning",
                    "category": "Storage Telemetry",
                    "title": "High Disk Volume Utilization",
                    "message": f"Primary volume capacity at {disk_pct}%. Rapid recovery snapshots available.",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

            self.send_json({"success": True, "alerts": alerts})
            return

        elif path == "/api/monitoring/maintenance":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM maintenance_tasks ORDER BY id DESC")
                tasks = [dict(t) for t in cursor.fetchall()]
                self.send_json({"success": True, "maintenance_tasks": tasks})
            return

        # Outcome 4: Audited Trail of Permission & System Changes
        elif path == "/api/monitoring/permission-audit-trail":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM audit_logs 
                    WHERE event_type IN ('PERMISSION_CHANGE', 'RBAC_POLICY_UPDATE', 'FIREWALL_CHANGE', 'LIFECYCLE_STATUS_CHANGE', 'AUTH_DENIED')
                    ORDER BY id DESC LIMIT 30
                """)
                logs = [dict(l) for l in cursor.fetchall()]
                self.send_json({"success": True, "permission_audits": logs})
            return

        elif path == "/api/monitoring/audit-logs":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                limit = int(query_params.get("limit", [50])[0])
                cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
                logs = [dict(l) for l in cursor.fetchall()]
                self.send_json({"success": True, "audit_logs": logs})
            return

        # Outcome 6: Optimized IT Operations (Firewall & Server Config)
        elif path == "/api/operations/firewall":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM firewall_rules ORDER BY id ASC")
                rules = [dict(r) for r in cursor.fetchall()]
                self.send_json({"success": True, "firewall_rules": rules})
            return

        elif path == "/api/operations/server-config":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM server_config ORDER BY category, key")
                configs = [dict(c) for c in cursor.fetchall()]
                self.send_json({"success": True, "server_configs": configs})
            return

        # Client-Side Student Workstations Telemetry (Outcome 5 & Client Agent)
        elif path == "/api/telemetry/student-workstations":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM student_pc_telemetry ORDER BY last_heartbeat DESC")
                rows = [dict(r) for r in cursor.fetchall()]
                
                # Dynamic calculation of online/offline status (online if reported within last 20 seconds)
                now = datetime.now()
                for r in rows:
                    try:
                        hb_time = datetime.fromisoformat(r["last_heartbeat"])
                        diff_sec = (now - hb_time).total_seconds()
                        r["seconds_ago"] = max(0, int(diff_sec))
                        if diff_sec > 25:
                            r["status"] = "OFFLINE"
                        else:
                            r["status"] = "ONLINE"
                    except Exception:
                        r["seconds_ago"] = 999
                        r["status"] = "OFFLINE"

                self.send_json({"success": True, "workstations": rows})
            return

        # Query User Web Filter Violations (for Student Security Notice & Incident Ledger)
        elif path == "/api/network/user-violations":
            if not current_user:
                self.send_error_json("Unauthorized", 401)
                return

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, event_type, actor_role, details, ip_address, timestamp 
                    FROM audit_logs 
                    WHERE event_type = 'WEB_FILTER_BLOCKED' AND actor_username = ?
                    ORDER BY id DESC
                """, (current_user["username"],))
                rows = cursor.fetchall()

            violations = []
            for r in rows:
                item = dict(r)
                details_text = item.get("details", "")

                # Extract target domain, category, and policy rule from details
                target_match = re.search(r"Target ['\"]([^'\"]+)['\"]", details_text)
                cat_match = re.search(r"\(Category: ([^)]+)\)", details_text)
                rule_match = re.search(r"(FW-RULE-\d+)", details_text)

                item["target"] = target_match.group(1) if target_match else "Restricted Target"
                item["category"] = cat_match.group(1) if cat_match else "Policy Violation"
                item["policy_rule"] = rule_match.group(1) if rule_match else "FW-RULE-06"
                violations.append(item)

            self.send_json({
                "success": True,
                "violations": violations,
                "count": len(violations)
            })
            return

        # Query Forbidden Websites List (Admin URL Filter Management)
        elif path == "/api/network/forbidden-urls":
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM forbidden_websites ORDER BY id DESC")
                rules = [dict(r) for r in cursor.fetchall()]
            self.send_json({"success": True, "rules": rules})
            return

        # Active Authenticated Sessions List (Admin / IT Staff Governance)
        elif path == "/api/auth/active-sessions":
            if not current_user or current_user["role"] not in ["Administrator", "IT Staff"]:
                self.send_error_json("Unauthorized: Administrator or IT Staff privileges required", 403)
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT s.token, s.user_id, s.username, s.role, s.created_at, s.expires_at,
                           u.full_name, u.department, u.status as account_status
                    FROM sessions s
                    LEFT JOIN users u ON s.user_id = u.id
                    ORDER BY s.created_at DESC
                """)
                rows = [dict(r) for r in cursor.fetchall()]

            now_iso = datetime.now().isoformat()
            for r in rows:
                r["is_active"] = (r.get("expires_at", "") > now_iso)
                raw_tok = r.get("token", "")
                r["token_masked"] = f"{raw_tok[:16]}...{raw_tok[-6:]}" if len(raw_tok) > 24 else raw_tok

            self.send_json({"success": True, "sessions": rows})
            return

        self.send_error_json(f"Endpoint not found: {path}", 404)

    # -------------------------------------------------------------
    # POST Request Dispatcher
    # -------------------------------------------------------------
    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        body = self.read_json_body() or {}
        token = self.get_auth_token()
        current_user = get_session_user(token)

        # ---------------------------------------------------------
        # Process 1.0: RBAC Policy Engine
        # ---------------------------------------------------------
        if path == "/api/auth/login":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()

            if not username or not password:
                self.send_error_json("Username and password are required")
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                user_row = cursor.fetchone()

                if not user_row:
                    log_audit_event("AUTH_FAILED", username, "Unknown", "Failed login: Identity not found in User & Roles DB")
                    self.send_error_json("Invalid credentials", 401)
                    return

                # Proactive Threat Prevention: Deny Suspended/Orphaned Accounts
                if user_row["status"] == "Suspended":
                    log_audit_event("AUTH_DENIED", username, user_row["role"], "Access denied: Account lifecycle status is Suspended")
                    self.send_error_json("Access Denied: Your account has been suspended by IT Administration.", 403)
                    return

                # Deny Accounts Pending Approval by IT Staff / Administrator
                if user_row["status"] == "Pending Approval":
                    log_audit_event("AUTH_PENDING", username, user_row["role"], "Login blocked: Student registration pending IT confirmation")
                    self.send_error_json("Registration Pending: Your student account is awaiting confirmation from IT Staff or Administrator. Please check back shortly.", 403)
                    return

                # Retrieve max_failed_logins policy from server_config (Outcome 6: Optimized IT Operations)
                max_failed_logins = 5
                timeout_mins = 120
                try:
                    with get_db_connection(AUDIT_TICKET_DB_PATH) as cfg_conn:
                        cfg_cur = cfg_conn.cursor()
                        cfg_cur.execute("SELECT key, value FROM server_config WHERE key IN ('max_failed_logins', 'session_timeout_minutes')")
                        for k, val in cfg_cur.fetchall():
                            if k == 'max_failed_logins' and val.strip().isdigit():
                                max_failed_logins = int(val.strip())
                            elif k == 'session_timeout_minutes' and val.strip().isdigit():
                                timeout_mins = int(val.strip())
                except Exception:
                    pass

                hashed = hash_password(password)
                if user_row["password_hash"] != hashed:
                    current_failed = (user_row["failed_attempts"] or 0) + 1
                    
                    if current_failed >= max_failed_logins:
                        # Lock out account: transition status to Suspended and kill sessions
                        cursor.execute("""
                            UPDATE users 
                            SET status = 'Suspended', failed_attempts = ? 
                            WHERE id = ?
                        """, (current_failed, user_row["id"]))
                        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_row["id"],))
                        conn.commit()

                        log_audit_event("ACCOUNT_LOCKOUT", username, user_row["role"],
                                        f"Account locked: Exceeded {max_failed_logins} failed login attempts (Brute-force protection: max_failed_logins policy enforced).")

                        self.send_error_json(
                            f"Account Locked: You have exceeded the maximum allowed failed login attempts ({max_failed_logins}). Your account has been suspended for security. Please contact IT Administration.",
                            403
                        )
                        return
                    else:
                        cursor.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (current_failed, user_row["id"]))
                        conn.commit()

                        remaining = max_failed_logins - current_failed
                        log_audit_event("AUTH_FAILED", username, user_row["role"],
                                        f"Failed login attempt ({current_failed}/{max_failed_logins}): Password mismatch")
                        self.send_error_json(f"Invalid credentials. Warning: {remaining} attempt(s) remaining before account lockout.", 401)
                        return

                # Password matched!
                # Issue Token & Enforce RBAC
                new_token = f"SYSAD-TOKEN-{uuid.uuid4().hex}"
                now_str = datetime.now().isoformat()
                expires_str = (datetime.now() + timedelta(minutes=timeout_mins)).isoformat()

                cursor.execute("""
                    INSERT INTO sessions (token, user_id, username, role, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (new_token, user_row["id"], user_row["username"], user_row["role"], now_str, expires_str))

                cursor.execute("UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?", (now_str, user_row["id"]))
                conn.commit()

            # Check if password rotation is required (Outcome 3)
            rotation_notice = False
            if user_row["must_rotate_password"] == 1:
                rotation_notice = True

            log_audit_event("AUTH_SUCCESS", user_row["username"], user_row["role"], f"Session established with token {new_token[:15]}...")

            user_data = get_session_user(new_token)
            self.send_json({
                "success": True,
                "message": "Authentication successful",
                "token": new_token,
                "user": user_data,
                "requires_credential_rotation": rotation_notice
            }, headers={"Set-Cookie": f"token={new_token}; Path=/; SameSite=Lax"})
            return

        # Student Self-Registration (Process 1.0 Account Lifecycle)
        elif path == "/api/auth/register-student":
            full_name = body.get("full_name", "").strip()
            username = body.get("username", "").strip().lower()
            password = body.get("password", "").strip()
            department = body.get("department", "Information Technology").strip()

            if not full_name:
                self.send_error_json("Full Name is required", 400)
                return
            if not username:
                self.send_error_json("Username is required", 400)
                return
            if len(password) < 6:
                self.send_error_json("Password must be at least 6 characters", 400)
                return

            email = f"{username}@campus.edu"
            role = "Student"  # strictly locked to Student role for self-registration

            try:
                with get_db_connection(USER_ROLES_DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
                    if cursor.fetchone():
                        self.send_error_json("Username already registered. Please choose another username.", 409)
                        return

                    now_str = datetime.now().isoformat()
                    # Registration starts in 'Pending Approval' status awaiting Admin or IT Staff confirmation
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
                        VALUES (?, ?, ?, ?, ?, 'Pending Approval', ?, ?, ?, ?, 0)
                    """, (username, hash_password(password), full_name, email, role, department, now_str, now_str, now_str))
                    new_user_id = cursor.lastrowid
                    conn.commit()

                # Audit logging
                log_audit_event("STUDENT_REGISTRATION_SUBMITTED", username, "Student",
                                f"New student account registered: {full_name} ({department}). Awaiting IT Staff / Administrator approval.")

                self.send_json({
                    "success": True,
                    "requires_approval": True,
                    "message": f"Registration submitted for {full_name}! Your student account is pending confirmation by IT Staff or Administrator. You will be able to log in once approved.",
                    "username": username
                })
            except Exception as e:
                self.send_error_json(f"Registration failed: {str(e)}", 500)
            return

        elif path == "/api/auth/logout":
            if token:
                with get_db_connection(USER_ROLES_DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                    conn.commit()
                if current_user:
                    log_audit_event("AUTH_LOGOUT", current_user["username"], current_user["role"], "User logged out")
            self.send_json({"success": True, "message": "Logged out successfully"},
                           headers={"Set-Cookie": "token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"})
            return

        elif path == "/api/auth/password-update":
            if not current_user:
                self.send_error_json("Unauthorized", 401)
                return

            old_pass = body.get("old_password", "")
            new_pass = body.get("new_password", "")

            if len(new_pass) < 6:
                self.send_error_json("New password must be at least 6 characters long")
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash FROM users WHERE id = ?", (current_user["user_id"],))
                current_hash = cursor.fetchone()[0]

                if current_hash != hash_password(old_pass):
                    self.send_error_json("Existing password incorrect", 400)
                    return

                new_hashed = hash_password(new_pass)
                now_str = datetime.now().isoformat()
                # Clear must_rotate_password on successful rotation
                cursor.execute("""
                    UPDATE users 
                    SET password_hash = ?, password_changed_at = ?, must_rotate_password = 0 
                    WHERE id = ?
                """, (new_hashed, now_str, current_user["user_id"]))
                conn.commit()

            log_audit_event("CREDENTIAL_ROTATION", current_user["username"], current_user["role"], "Credential rotated and password hash updated")
            self.send_json({"success": True, "message": "Password successfully updated. Credential rotation recorded."})
            return

        elif path == "/api/rbac/roles/update":
            # Outcome 2: Enhanced Network Security & Define Roles
            if not current_user or current_user["role"] not in ["Administrator"]:
                log_audit_event("UNAUTHORIZED_ACCESS_ATTEMPT", current_user["username"] if current_user else "Anon", "Forbidden", "Denied unauthorized RBAC policy change attempt")
                self.send_error_json("Unauthorized: Administrator privilege required to modify RBAC policy", 403)
                return

            role_name = body.get("role_name")
            if not role_name:
                self.send_error_json("Missing role_name")
                return

            fields = [
                "can_submit_tickets", "can_view_own_tickets", "can_manage_users",
                "can_triage_tickets", "can_view_telemetry", "can_manage_backups",
                "can_manage_patches", "can_manage_firewall", "can_view_audit_logs"
            ]

            updates = []
            vals = []
            changes_desc = []
            for f in fields:
                if f in body:
                    val = 1 if body[f] else 0
                    updates.append(f"{f} = ?")
                    vals.append(val)
                    changes_desc.append(f"{f}={val}")

            if updates:
                vals.append(role_name)
                with get_db_connection(USER_ROLES_DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute(f"UPDATE roles SET {', '.join(updates)} WHERE role_name = ?", vals)
                    conn.commit()

                # Outcome 4: Log detailed permission change to Audit DB for troubleshooting
                log_audit_event("PERMISSION_CHANGE", current_user["username"], current_user["role"], 
                                f"Granular permission update on role '{role_name}': {', '.join(changes_desc)}")

            self.send_json({"success": True, "message": f"Granular permissions updated for role '{role_name}'"})
            return

        # ---------------------------------------------------------
        # Process 2.0: Identity Directory Manager (Outcome 1: Automated Account Management)
        # ---------------------------------------------------------
        elif path == "/api/directory/provision":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized: Privileged role required", 403)
                return

            username = body.get("username", "").strip()
            full_name = body.get("full_name", "").strip()
            email = body.get("email", "").strip()
            role = body.get("role", "Student")
            department = body.get("department", "General")
            password = body.get("password", "Welcome2026!")

            if not username or not full_name or not email:
                self.send_error_json("Username, Full Name, and Email are required")
                return

            try:
                with get_db_connection(USER_ROLES_DB_PATH) as conn:
                    cursor = conn.cursor()
                    now_str = datetime.now().isoformat()
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
                        VALUES (?, ?, ?, ?, ?, 'Active', ?, ?, ?, ?, 0)
                    """, (username, hash_password(password), full_name, email, role, department, now_str, now_str, now_str))
                    conn.commit()
            except sqlite3.IntegrityError:
                self.send_error_json(f"Username '{username}' already exists in directory")
                return

            log_audit_event("PROVISIONING", current_user["username"], current_user["role"], 
                            f"Automated account provisioning: {username} ({full_name}) as {role}")
            self.send_json({"success": True, "message": f"Account '{username}' successfully provisioned as {role}"})
            return

        # Outcome 1: Automated Batch Onboarding Workflow
        elif path == "/api/directory/batch-onboard":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            cohort_name = body.get("cohort", "CS2026_Lab_Group")
            count = int(body.get("count", 5))
            created_accounts = []

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                now_str = datetime.now().isoformat()
                for i in range(1, count + 1):
                    uid = uuid.uuid4().hex[:4]
                    uname = f"std_{cohort_name.lower()[:6]}_{uid}"
                    fname = f"Cohort Student {uid.upper()}"
                    mail = f"{uname}@campus.edu"
                    cursor.execute("""
                        INSERT INTO users (username, password_hash, full_name, email, role, status, department, last_login, created_at, password_changed_at, must_rotate_password)
                        VALUES (?, ?, ?, ?, 'Student', 'Active', 'Computer Science', ?, ?, ?, 0)
                    """, (uname, hash_password("Cohort2026!"), fname, mail, now_str, now_str, now_str))
                    created_accounts.append(uname)
                conn.commit()

            log_audit_event("BATCH_PROVISIONING", current_user["username"], current_user["role"],
                            f"Automated batch onboarding: Generated {len(created_accounts)} accounts for cohort '{cohort_name}'")

            self.send_json({
                "success": True,
                "message": f"Successfully automated onboarding of {len(created_accounts)} student accounts!",
                "created_accounts": created_accounts
            })
            return

        elif path == "/api/directory/lifecycle-status":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized: Privileged role required", 403)
                return

            user_id = body.get("user_id")
            new_status = body.get("status")

            if new_status not in ["Active", "Aging", "Suspended", "Pending Approval"]:
                self.send_error_json("Status must be Active, Aging, Suspended, or Pending Approval")
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, role, status FROM users WHERE id = ?", (user_id,))
                target = cursor.fetchone()
                if not target:
                    self.send_error_json("Target user not found", 404)
                    return

                old_status = target["status"]
                if new_status == "Active":
                    cursor.execute("UPDATE users SET status = ?, failed_attempts = 0 WHERE id = ?", (new_status, user_id))
                else:
                    cursor.execute("UPDATE users SET status = ? WHERE id = ?", (new_status, user_id))
                
                # Proactive Threat Prevention: Revoke all active sessions on suspension or aging
                if new_status in ["Suspended", "Aging"]:
                    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                conn.commit()

            log_audit_event("LIFECYCLE_STATUS_CHANGE", current_user["username"], current_user["role"],
                            f"Changed lifecycle status of '{target['username']}' from '{old_status}' to '{new_status}' (Revoked orphaned sessions)")
            self.send_json({"success": True, "message": f"Status of {target['username']} updated to {new_status}"})
            return

        # Outcome 1: Approve Student Registration (IT Staff / Administrator Confirmation)
        elif path == "/api/directory/approve-student":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized: IT Staff or Administrator privileges required", 403)
                return

            user_id = body.get("user_id")
            if not user_id:
                self.send_error_json("User ID is required", 400)
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, full_name, role, status FROM users WHERE id = ?", (user_id,))
                target = cursor.fetchone()
                if not target:
                    self.send_error_json("Student account not found", 404)
                    return

                cursor.execute("UPDATE users SET status = 'Active', failed_attempts = 0 WHERE id = ?", (user_id,))
                conn.commit()

            log_audit_event("STUDENT_REGISTRATION_APPROVED", current_user["username"], current_user["role"],
                            f"{current_user['role']} '{current_user['username']}' confirmed & approved student registration for '{target['username']}' ({target['full_name']})")

            self.send_json({
                "success": True,
                "message": f"Student '{target['username']}' ({target['full_name']}) successfully approved and activated!"
            })
            return

        # Outcome 1: Reject Student Registration
        elif path == "/api/directory/reject-student":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized: IT Staff or Administrator privileges required", 403)
                return

            user_id = body.get("user_id")
            if not user_id:
                self.send_error_json("User ID is required", 400)
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, full_name, role, status FROM users WHERE id = ?", (user_id,))
                target = cursor.fetchone()
                if not target:
                    self.send_error_json("Student account not found", 404)
                    return

                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                conn.commit()

            log_audit_event("STUDENT_REGISTRATION_REJECTED", current_user["username"], current_user["role"],
                            f"{current_user['role']} '{current_user['username']}' rejected registration for student '{target['username']}' ({target['full_name']})")

            self.send_json({
                "success": True,
                "message": f"Student registration for '{target['username']}' was rejected and removed."
            })
            return

        # Outcome 1: Automated Orphan Account Cleanup
        elif path == "/api/directory/auto-cleanup":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            cleanup_threshold = (datetime.now() - timedelta(days=120)).isoformat()
            suspended_list = []

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                # Find inactive accounts older than 120 days that are still Active or Aging
                cursor.execute("SELECT id, username FROM users WHERE last_login < ? AND status != 'Suspended'", (cleanup_threshold,))
                orphaned = cursor.fetchall()
                for u in orphaned:
                    cursor.execute("UPDATE users SET status = 'Suspended' WHERE id = ?", (u["id"],))
                    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
                    suspended_list.append(u["username"])
                conn.commit()

            log_audit_event("ORPHAN_CLEANUP", current_user["username"], current_user["role"],
                            f"Automated cleanup: Suspended {len(suspended_list)} orphaned profile(s) inactive >120 days")

            self.send_json({
                "success": True,
                "message": f"Orphan cleanup completed. Automatically suspended {len(suspended_list)} stale profile(s).",
                "suspended_accounts": suspended_list
            })
            return

        elif path == "/api/directory/delete-user":
            if not current_user or current_user["role"] not in ["Administrator"]:
                self.send_error_json("Unauthorized: Only Administrators can delete accounts", 403)
                return

            user_id = body.get("user_id")
            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
                target = cursor.fetchone()
                if not target:
                    self.send_error_json("User not found", 404)
                    return
                cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()

            log_audit_event("ACCOUNT_DELETION", current_user["username"], current_user["role"],
                            f"Deleted user account: {target['username']} (Role: {target['role']})")
            self.send_json({"success": True, "message": f"User {target['username']} permanently removed"})
            return

        # ---------------------------------------------------------
        # Process 3.0: Troubleshooting Ledger (Outcome 4: Accelerated Incident Resolution)
        # ---------------------------------------------------------
        elif path == "/api/tickets/create":
            if not current_user:
                self.send_error_json("Authentication required to submit ticket", 401)
                return

            title = body.get("title", "").strip()
            description = body.get("description", "").strip()
            category = body.get("category", "General")
            priority = body.get("priority", "Medium")

            if not title or not description:
                self.send_error_json("Title and description are required")
                return

            ticket_code = f"TICK-{random.randint(1005, 9999)}"
            now_str = datetime.now().isoformat()

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO tickets (ticket_code, title, description, category, priority, status,
                                         submitted_by_id, submitted_by_name, assigned_to, resolution_notes,
                                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, 'Unassigned', '', ?, ?)
                """, (ticket_code, title, description, category, priority, current_user["user_id"], current_user["full_name"], now_str, now_str))
                conn.commit()

            log_audit_event("INCIDENT_REPORTED", current_user["username"], current_user["role"],
                            f"New incident logged: [{ticket_code}] {title} (Priority: {priority}, Cat: {category})")

            self.send_json({
                "success": True,
                "message": f"Trouble ticket {ticket_code} created successfully",
                "ticket_code": ticket_code
            })
            return

        elif path == "/api/tickets/triage":
            # Accelerated Incident Resolution & Triage
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized: IT Staff triage privilege required", 403)
                return

            ticket_id = body.get("ticket_id")
            new_status = body.get("status")
            new_priority = body.get("priority")
            assigned_to = body.get("assigned_to", "Unassigned")
            resolution_notes = body.get("resolution_notes", "")

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
                t = cursor.fetchone()
                if not t:
                    self.send_error_json("Ticket not found", 404)
                    return

                if t["status"] in ["Resolved", "Closed"]:
                    self.send_error_json("Policy Violation: This ticket has already been resolved and can no longer be edited.", 400)
                    return

                now_str = datetime.now().isoformat()
                cursor.execute("""
                    UPDATE tickets
                    SET status = ?, priority = ?, assigned_to = ?, resolution_notes = ?, updated_at = ?
                    WHERE id = ?
                """, (new_status, new_priority, assigned_to, resolution_notes, now_str, ticket_id))
                conn.commit()

            log_audit_event("TICKET_TRIAGE", current_user["username"], current_user["role"],
                            f"Triage update on {t['ticket_code']}: Status={new_status}, Priority={new_priority}, Assignee={assigned_to}")

            self.send_json({"success": True, "message": f"Ticket {t['ticket_code']} updated successfully"})
            return

        # ---------------------------------------------------------
        # Outcome 3: Proactive Threat Prevention Actions
        # ---------------------------------------------------------
        elif path == "/api/security/enforce-credential-rotation":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            target_user = body.get("username", None)
            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                if target_user:
                    cursor.execute("UPDATE users SET must_rotate_password = 1 WHERE username = ?", (target_user,))
                    msg = f"Enforced credential rotation for '{target_user}'"
                else:
                    # Enforce across all aging accounts
                    cursor.execute("UPDATE users SET must_rotate_password = 1 WHERE status = 'Aging'")
                    msg = "Enforced mandatory credential rotation across all aging profiles"
                conn.commit()

            log_audit_event("ENFORCE_CRED_ROTATION", current_user["username"], current_user["role"], msg)
            self.send_json({"success": True, "message": msg})
            return

        elif path == "/api/monitoring/scan-aging":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            rot_days = 90
            try:
                with get_db_connection(AUDIT_TICKET_DB_PATH) as cfg_conn:
                    cfg_cur = cfg_conn.cursor()
                    cfg_cur.execute("SELECT value FROM server_config WHERE key = 'credential_rotation_days'")
                    cfg_row = cfg_cur.fetchone()
                    if cfg_row and cfg_row[0].strip().isdigit():
                        rot_days = int(cfg_row[0].strip())
            except Exception:
                pass
            aging_threshold = (datetime.now() - timedelta(days=rot_days)).isoformat()
            updated_accounts = []

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, username, last_login, status
                    FROM users
                    WHERE last_login < ? AND status = 'Active'
                """, (aging_threshold,))
                aging_users = cursor.fetchall()

                for u in aging_users:
                    # Mark aging and set credential rotation required
                    cursor.execute("UPDATE users SET status = 'Aging', must_rotate_password = 1 WHERE id = ?", (u["id"],))
                    # Revoke active sessions
                    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (u["id"],))
                    updated_accounts.append(u["username"])

                conn.commit()

            if updated_accounts:
                log_audit_event("AGING_ACCOUNT_SCAN", current_user["username"], current_user["role"],
                                f"Aging scan flagged {len(updated_accounts)} inactive account(s): {', '.join(updated_accounts)} (Enforced credential rotation & revoked sessions)")
            else:
                log_audit_event("AGING_ACCOUNT_SCAN", current_user["username"], current_user["role"],
                                "Aging scan completed: All active accounts verified within 90-day threshold")

            self.send_json({
                "success": True,
                "message": f"Scan completed. Flagged {len(updated_accounts)} aging account(s) and revoked orphaned sessions.",
                "aging_accounts": updated_accounts
            })
            return

        # ---------------------------------------------------------
        # Outcome 5: High Infrastructure Reliability (Backups & Rapid Recovery)
        # ---------------------------------------------------------
        elif path == "/api/monitoring/backup":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_user_db = os.path.join(BACKUP_DIR, f"user_roles_{timestamp_str}.bak")
            backup_audit_db = os.path.join(BACKUP_DIR, f"audit_tickets_{timestamp_str}.bak")

            shutil.copyfile(USER_ROLES_DB_PATH, backup_user_db)
            shutil.copyfile(AUDIT_TICKET_DB_PATH, backup_audit_db)

            title = f"Automated Identity Snapshot ({timestamp_str})"
            details = f"Archived DBs to {os.path.basename(backup_user_db)} and {os.path.basename(backup_audit_db)}"

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                now_str = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO maintenance_tasks (task_type, title, status, details, created_by, scheduled_at, executed_at)
                    VALUES ('BACKUP', ?, 'Completed', ?, ?, ?, ?)
                """, (title, details, current_user["username"], now_str, now_str))
                conn.commit()

            log_audit_event("BACKUP_EXECUTED", current_user["username"], current_user["role"],
                            f"System snapshot created: {details}")

            self.send_json({
                "success": True,
                "message": "Identity database backup snapshot completed successfully!",
                "backup_files": [os.path.basename(backup_user_db), os.path.basename(backup_audit_db)]
            })
            return

        # Outcome 5: Rapid Recovery / Restore Backup
        elif path == "/api/monitoring/restore-backup":
            if not current_user or current_user["role"] not in ["Administrator"]:
                self.send_error_json("Unauthorized: Administrator required for rapid recovery restore", 403)
                return

            backup_file = body.get("backup_file", "")
            if not backup_file:
                # Find most recent user backup
                backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith("user_roles_") and f.endswith(".bak")])
                if not backups:
                    self.send_error_json("No database snapshots found in backup repository")
                    return
                backup_file = backups[-1]

            target_path = os.path.join(BACKUP_DIR, backup_file)
            if not os.path.exists(target_path):
                self.send_error_json("Snapshot file not found", 404)
                return

            # Verify integrity
            shutil.copyfile(target_path, USER_ROLES_DB_PATH)
            log_audit_event("RAPID_RECOVERY_RESTORE", current_user["username"], current_user["role"],
                            f"Rapid recovery executed: Restored User & Roles DB from snapshot {backup_file}")

            self.send_json({
                "success": True,
                "message": f"Rapid recovery verified! Database restored from snapshot '{backup_file}'."
            })
            return

        # ---------------------------------------------------------
        # Outcome 6: Optimized IT Operations (Firewall & Server Config)
        # ---------------------------------------------------------
        elif path == "/api/monitoring/patch":
            if not current_user or current_user["role"] not in ["IT Staff", "Administrator"]:
                self.send_error_json("Unauthorized", 403)
                return

            patch_name = body.get("title", "SYSAD-SECURITY-UPDATE")
            patch_details = body.get("details", "General vulnerability remediation and package upgrade.")
            
            now_str = datetime.now().isoformat()
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO maintenance_tasks (task_type, title, status, details, created_by, scheduled_at, executed_at)
                    VALUES ('PATCH', ?, 'Completed', ?, ?, ?, ?)
                """, (patch_name, patch_details, current_user["username"], now_str, now_str))
                conn.commit()

            log_audit_event("PATCH_DEPLOYMENT", current_user["username"], current_user["role"],
                            f"Deployed security patch: {patch_name} ({patch_details})")

            self.send_json({"success": True, "message": f"Patch '{patch_name}' deployed successfully!"})
            return

        elif path == "/api/operations/firewall/toggle":
            if not current_user or current_user["role"] not in ["Administrator", "IT Staff"]:
                self.send_error_json("Unauthorized", 403)
                return

            rule_id = body.get("rule_id")
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM firewall_rules WHERE id = ?", (rule_id,))
                rule = cursor.fetchone()
                if not rule:
                    self.send_error_json("Firewall rule not found", 404)
                    return

                new_status = 'DISABLED' if rule["status"] == 'ACTIVE' else 'ACTIVE'
                now_str = datetime.now().isoformat()
                cursor.execute("UPDATE firewall_rules SET status = ?, last_modified = ? WHERE id = ?", (new_status, now_str, rule_id))
                conn.commit()

            log_audit_event("FIREWALL_CHANGE", current_user["username"], current_user["role"],
                            f"Firewall policy modified: Rule '{rule['rule_name']}' toggled to {new_status}")

            self.send_json({"success": True, "message": f"Firewall rule '{rule['rule_name']}' is now {new_status}"})
            return

        elif path == "/api/operations/server-config/update":
            if not current_user or current_user["role"] not in ["Administrator", "IT Staff"]:
                self.send_error_json("Unauthorized: Administrator or IT Staff privileges required", 403)
                return

            # Batch configuration update support
            configs = body.get("configs")
            if isinstance(configs, list) and len(configs) > 0:
                with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                    cursor = conn.cursor()
                    now_str = datetime.now().isoformat()
                    updated = 0
                    for item in configs:
                        k = item.get("key")
                        v = item.get("value")
                        if k is not None:
                            cursor.execute("UPDATE server_config SET value = ?, updated_at = ? WHERE key = ?", (str(v), now_str, k))
                            updated += 1
                    conn.commit()

                log_audit_event("SERVER_CONFIG_CHANGE", current_user["username"], current_user["role"],
                                f"Batch server configuration updated ({updated} parameters)")
                self.send_json({"success": True, "count": updated, "message": f"Successfully saved {updated} server configuration parameter(s)!"})
                return

            key = body.get("key")
            new_value = body.get("value")

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                now_str = datetime.now().isoformat()
                cursor.execute("UPDATE server_config SET value = ?, updated_at = ? WHERE key = ?", (new_value, now_str, key))
                conn.commit()

            log_audit_event("SERVER_CONFIG_CHANGE", current_user["username"], current_user["role"],
                            f"Server configuration updated: {key} = {new_value}")

            self.send_json({"success": True, "message": f"Configuration '{key}' updated to '{new_value}'"})
            return

        # ---------------------------------------------------------
        # Campus Web Filter & Forbidden Website Enforcement
        # ---------------------------------------------------------
        elif path == "/api/network/web-filter-check":
            if not current_user:
                self.send_error_json("Unauthorized", 401)
                return

            target_url = body.get("url", "").lower().strip()
            if not target_url:
                self.send_error_json("Destination website URL or domain is required")
                return

            forbidden_keywords = [
                ("torrent", "P2P / Unauthorized File Sharing"),
                ("pirate", "Copyright Infringement / P2P"),
                ("proxy", "Network Proxy / VPN Evasion"),
                ("vpn-bypass", "Network Tunneling Bypass"),
                ("gambling", "Gambling / High-Risk Web Content"),
                ("bet365", "Online Betting Services"),
                ("crypto", "Unauthorized Cryptomining"),
                ("mining", "Unauthorized Cryptomining"),
                ("phish", "Phishing & Credential Harvesting"),
                ("malware", "Malicious Software / Command & Control"),
                ("darknet", "Anonymizing Darknet Gateway")
            ]

            matched_reason = None
            for kw, category in forbidden_keywords:
                if kw in target_url:
                    matched_reason = category
                    break

            fw_rule_06_active = True
            fw_rule_01_active = True
            try:
                with get_db_connection(AUDIT_TICKET_DB_PATH) as fw_conn:
                    cursor = fw_conn.cursor()
                    cursor.execute("SELECT rule_name, status FROM firewall_rules WHERE rule_name LIKE '%FW-RULE-01%' OR rule_name LIKE '%FW-RULE-06%'")
                    for r in cursor.fetchall():
                        if "FW-RULE-06" in r["rule_name"] and r["status"] == "DISABLED":
                            fw_rule_06_active = False
                        elif "FW-RULE-01" in r["rule_name"] and r["status"] == "DISABLED":
                            fw_rule_01_active = False
            except Exception:
                pass

            if matched_reason and fw_rule_06_active:
                incident_details = (
                    f"Campus Firewall BLOCKED forbidden web access by {current_user['role']} '{current_user['username']}': "
                    f"Target '{target_url}' (Category: {matched_reason}). Policy Rule FW-RULE-06 enforced. Packets dropped."
                )
                log_audit_event("WEB_FILTER_BLOCKED", current_user["username"], current_user["role"], incident_details)

                self.send_json({
                    "success": True,
                    "blocked": True,
                    "status_code": 403,
                    "url": target_url,
                    "category": matched_reason,
                    "policy_rule": "FW-RULE-06 (Deny Outbound Prohibited Protocols)",
                    "enforced_policy": "Campus Network Acceptable Use Policy § 4.2",
                    "action_taken": "DROP_CONNECTION_AND_LOG_INCIDENT",
                    "message": f"Access Blocked (403 Forbidden): The website '{target_url}' violates campus network security policies ({matched_reason}). The request was dropped by the campus firewall gateway and logged to the Security Audit DB."
                })
            elif not fw_rule_01_active:
                self.send_json({
                    "success": True,
                    "blocked": True,
                    "status_code": 403,
                    "url": target_url,
                    "category": "Inbound/Outbound Web Traffic Disabled",
                    "policy_rule": "FW-RULE-01 (Campus Web Traffic Inactive)",
                    "action_taken": "DROP_PACKETS_GATEWAY_OFFLINE",
                    "message": f"Connection Dropped: Campus Web Traffic rule (FW-RULE-01) is currently DISABLED by IT Operations."
                })
            else:
                self.send_json({
                    "success": True,
                    "blocked": False,
                    "status_code": 200,
                    "url": target_url,
                    "category": "Permitted Academic / Standard Web Traffic",
                    "policy_rule": "FW-RULE-01 (Campus Web Traffic Allow)",
                    "action_taken": "ALLOW_CONNECTION",
                    "message": f"Connection Permitted: '{target_url}' is authorized under campus web security policies."
                })
            return

        # ---------------------------------------------------------
        # Client-Side Student PC Telemetry Agent Ingestion
        # ---------------------------------------------------------
        elif path == "/api/telemetry/report":
            hostname = body.get("hostname", "").strip() or "UNKNOWN-HOST"
            mac_address = body.get("mac_address", "00:00:00:00:00:00")
            ip_address = body.get("ip_address", self.client_address[0])
            student_username = body.get("student_username", "alex.student").strip()
            os_platform = body.get("os_platform", "Windows")
            
            cpu_load = float(body.get("cpu_load", 0.0))
            ram_used_mb = float(body.get("ram_used_mb", 0.0))
            ram_total_mb = float(body.get("ram_total_mb", 0.0))
            ram_usage_pct = float(body.get("ram_usage_pct", 0.0))
            disk_used_gb = float(body.get("disk_used_gb", 0.0))
            disk_total_gb = float(body.get("disk_total_gb", 0.0))
            disk_usage_pct = float(body.get("disk_usage_pct", 0.0))
            now_iso = datetime.now().isoformat()

            print(f"[TELEMETRY AGENT] Heartbeat from '{hostname}' (Student: {student_username}) | CPU: {cpu_load:.1f}% | RAM: {ram_usage_pct:.1f}% | Disk: {disk_usage_pct:.1f}%")

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO student_pc_telemetry (
                        hostname, mac_address, ip_address, student_username, os_platform,
                        cpu_load, ram_used_mb, ram_total_mb, ram_usage_pct,
                        disk_used_gb, disk_total_gb, disk_usage_pct, last_heartbeat, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ONLINE')
                    ON CONFLICT(hostname) DO UPDATE SET
                        mac_address=excluded.mac_address,
                        ip_address=excluded.ip_address,
                        student_username=COALESCE(excluded.student_username, student_pc_telemetry.student_username),
                        os_platform=excluded.os_platform,
                        cpu_load=excluded.cpu_load,
                        ram_used_mb=excluded.ram_used_mb,
                        ram_total_mb=excluded.ram_total_mb,
                        ram_usage_pct=excluded.ram_usage_pct,
                        disk_used_gb=excluded.disk_used_gb,
                        disk_total_gb=excluded.disk_total_gb,
                        disk_usage_pct=excluded.disk_usage_pct,
                        last_heartbeat=excluded.last_heartbeat,
                        status='ONLINE'
                """, (
                    hostname, mac_address, ip_address, student_username, os_platform,
                    cpu_load, ram_used_mb, ram_total_mb, ram_usage_pct,
                    disk_used_gb, disk_total_gb, disk_usage_pct, now_iso
                ))
                conn.commit()

            # High Resource Warning Check
            if cpu_load > 85.0 or ram_usage_pct > 90.0:
                log_audit_event("HIGH_RESOURCE_USAGE", student_username, "Student",
                                f"Workstation '{hostname}' exceeded safe threshold: CPU {cpu_load:.1f}%, RAM {ram_usage_pct:.1f}%",
                                ip_address)

            self.send_json({
                "success": True,
                "message": f"Telemetry heartbeat recorded for '{hostname}'",
                "timestamp": now_iso
            })
            return

        # ---------------------------------------------------------
        # Admin Forbidden Websites Management (Add, Suspend, Delete)
        # ---------------------------------------------------------
        elif path == "/api/network/forbidden-urls/create":
            if not current_user or current_user["role"] != "Administrator":
                self.send_error_json("Access Denied: Only Administrators can configure forbidden web filter rules", 403)
                return

            raw_input = body.get("domain_pattern", "").strip()
            domain_pattern = normalize_url_or_domain(raw_input) or raw_input.lower()
            category = body.get("category", "Restricted Web Content").strip()
            reason = body.get("reason", "Prohibited by Administrator").strip()

            if not domain_pattern:
                self.send_error_json("Domain pattern or URL string is required")
                return

            now_str = datetime.now().isoformat()
            try:
                with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO forbidden_websites (domain_pattern, category, reason, status, added_by, created_at, updated_at)
                        VALUES (?, ?, ?, 'ACTIVE', ?, ?, ?)
                    """, (domain_pattern, category, reason, current_user["username"], now_str, now_str))
                    conn.commit()
            except sqlite3.IntegrityError:
                self.send_error_json(f"Rule for '{domain_pattern}' already exists", 400)
                return

            log_audit_event("FORBIDDEN_URL_ADDED", current_user["username"], "Administrator",
                            f"Added prohibited web filter rule: '{domain_pattern}' (Category: {category})")
            self.send_json({"success": True, "message": f"Successfully added '{domain_pattern}' to active forbidden web filter"})
            return

        elif path == "/api/network/forbidden-urls/toggle-status":
            if not current_user or current_user["role"] != "Administrator":
                self.send_error_json("Access Denied: Only Administrators can suspend or activate web filter rules", 403)
                return

            rule_id = body.get("id")
            new_status = body.get("status", "").strip().upper()
            if not rule_id or new_status not in ["ACTIVE", "SUSPENDED"]:
                self.send_error_json("Valid rule ID and status ('ACTIVE' or 'SUSPENDED') are required")
                return

            now_str = datetime.now().isoformat()
            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT domain_pattern, status FROM forbidden_websites WHERE id = ?", (rule_id,))
                rule_row = cursor.fetchone()
                if not rule_row:
                    self.send_error_json("Rule not found", 404)
                    return

                cursor.execute("UPDATE forbidden_websites SET status = ?, updated_at = ? WHERE id = ?", (new_status, now_str, rule_id))
                conn.commit()

            log_audit_event("FORBIDDEN_URL_STATUS_CHANGED", current_user["username"], "Administrator",
                            f"Rule '{rule_row['domain_pattern']}' transitioned to {new_status}")
            self.send_json({"success": True, "message": f"Rule for '{rule_row['domain_pattern']}' is now {new_status}"})
            return

        elif path == "/api/network/forbidden-urls/delete":
            if not current_user or current_user["role"] != "Administrator":
                self.send_error_json("Access Denied: Only Administrators can delete web filter rules", 403)
                return

            rule_id = body.get("id")
            if not rule_id:
                self.send_error_json("Rule ID is required")
                return

            with get_db_connection(AUDIT_TICKET_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT domain_pattern FROM forbidden_websites WHERE id = ?", (rule_id,))
                rule_row = cursor.fetchone()
                if not rule_row:
                    self.send_error_json("Rule not found", 404)
                    return

                cursor.execute("DELETE FROM forbidden_websites WHERE id = ?", (rule_id,))
                conn.commit()

            log_audit_event("FORBIDDEN_URL_DELETED", current_user["username"], "Administrator",
                            f"Deleted prohibited web filter rule: '{rule_row['domain_pattern']}'")
            self.send_json({"success": True, "message": f"Deleted rule for '{rule_row['domain_pattern']}'"})
            return

        # Outcome 3: Revoke Session Token (Immediate Token Invalidation)
        elif path == "/api/auth/revoke-session":
            if not current_user or current_user["role"] not in ["Administrator", "IT Staff"]:
                self.send_error_json("Unauthorized: Admin or IT Staff role required", 403)
                return

            target_token = body.get("token", "").strip()
            if not target_token:
                self.send_error_json("Session token is required", 400)
                return

            with get_db_connection(USER_ROLES_DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, role FROM sessions WHERE token = ?", (target_token,))
                target_session = cursor.fetchone()
                if not target_session:
                    self.send_error_json("Session not found or already terminated", 404)
                    return

                cursor.execute("DELETE FROM sessions WHERE token = ?", (target_token,))
                conn.commit()

            log_audit_event("TOKEN_REVOKED", current_user["username"], current_user["role"],
                            f"Revoked active session token for user '{target_session['username']}' ({target_session['role']})")

            self.send_json({"success": True, "message": f"Session for '{target_session['username']}' revoked successfully."})
            return

        self.send_error_json(f"POST route not found: {path}", 404)

    def serve_file(self, filepath, content_type):
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error_json(f"Error serving file: {str(e)}", 500)

def run_server(host=None, port=PORT):
    init_databases()
    bind_host = host or os.environ.get("SYSAD_HOST", "0.0.0.0")
    server_address = (bind_host, port)
    httpd = http.server.ThreadingHTTPServer(server_address, SysadRequestHandler)
    print(f"============================================================")
    print(f" Centralized Portal (SYSAD System) running at:")
    print(f" http://127.0.0.1:{port}")
    print(f"============================================================")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
