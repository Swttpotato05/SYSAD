# SYSAD Centralized User Lifecycle & Access Control Portal

A full-stack Systems Administration (SYSAD) and IT Service Management portal implemented in strict accordance with the provided **Data Flow Diagram (DFD)** and achieving all **6 Expected Outcomes**.

---

## Verification of the 6 Expected Outcomes

The system has been specifically architected and verified to achieve the expected outcomes:

### 1.  Automated Account Management
* **Automated Batch Onboarding**: Generates entire student or faculty cohorts in a single click (`POST /api/directory/batch-onboard`), eliminating manual repetitive entry.
* **Automated Orphan Account Cleanup**: Scans for accounts inactive for >120 days and automatically transitions them to `Suspended` (`POST /api/directory/auto-cleanup`), reducing administrative burden.
* **Full CRUD Operations**: Immediate automated provisioning, modification, and deletion.

### 2.  Enhanced Network Security (Granular RBAC)
* **RBAC Policy Engine**: Granular permissions (Ticket Submission, Triage, User Management, Firewall Rules, Telemetry, Snapshot Recovery, Audit Logs) dynamically enforced per role.
* **Network & Endpoint Isolation**: Student and Faculty roles are strictly prevented from viewing administrative infrastructure or managing users; unauthorized attempts trigger HTTP 403 Forbidden and log security alerts.

### 3.  Proactive Threat Prevention
* **Aging Profile Tracking**: Scans for accounts inactive >90 days, flagging them with warning alerts before they become security liabilities.
* **Mandatory Credential Rotation**: Automatically flags aging or stale profiles with `must_rotate_password = 1`, enforcing password updates upon login.
* **Orphan Session Invalidation**: Instantly revokes all active session tokens whenever an account status transitions to `Suspended` or `Aging`, preventing orphaned accounts from retaining access to critical infrastructure.

### 4.  Accelerated Incident Resolution
* **Ticket Prioritization**: Troubleshooting Ledger organizes tickets by urgency (`Critical > High > Medium > Low`), ensuring system outages and classroom blocks are triaged first.
* **Audited Trail of Permission Changes**: Technicians can directly review a specialized audit trail of recent permission, RBAC, and firewall modifications (`GET /api/monitoring/permission-audit-trail`) to instantly correlate outages with configuration drift.

### 5. High Infrastructure Reliability
* **Continuous Hardware Telemetry**: Live performance monitoring of CPU load, RAM memory usage, Disk storage capacity, and active sessions with threshold alerts.
* **Automated Database Snapshots**: IT Staff & Admins can create timestamped identity database snapshots in [`data/backups/`](file:///c:/Users/ivan/Desktop/SYSAD%20System/data/backups).
* **Rapid Recovery**: Instant database restore pipeline (`POST /api/monitoring/restore-backup`) allowing recovery of corrupted or lost records from snapshot archives.

### 6.  Optimized IT Operations
* **Campus Firewall Management**: Live control panel for network firewall rules (Campus Web Traffic, SSH Access, Telnet Port 23 Blocking, External DB Blocking, Student Lab Subnet Isolation) with instant Enable/Disable toggles.
* **Prohibited URL & Domain Governance**: Administrator control panel to dynamically **Add**, **Suspend**, or **Delete** forbidden website patterns (e.g. `tiktok.com`, `roblox.com`, `torrent`). Changes take effect immediately in student browsers without server restart.
* **Centralized Server Configuration**: Runtime configuration manager for session timeout, credential rotation cycle (90 days), minimum TLS protocol (TLSv1.3), and max failed logins.
* **Security Patch Deployment**: Rollout manager for system-wide patches and vulnerability mitigation with verified change tracking.

---

##  Default Test Accounts

| Actor | Username | Password | Role | Primary Operational Capabilities |
| :--- | :--- | :--- | :--- | :--- |
| **Student** | `alex.student` | `student123` | **Student** | Reports user-driven problems, monitors live ticket status, updates credentials |
| **Faculty** | `dr.carter` | `faculty123` | **Faculty** | Reports classroom AV & lab equipment issues, fast-track lecture hall dispatch |
| **IT Staff** | `marcus.it` | `itstaff123` | **IT Staff** | Prioritized triage queue, automated batch onboarding, firewall toggling, telemetry |
| **Administrator** | `elena.admin` | `admin123` | **Administrator** | Root RBAC matrix, rapid recovery restore, server config tuning, immutable audit logs |
| *Aging Account* | `kevin.aging` | `student123` | **Aging Student** | Inactive >90 days, flagged for mandatory credential rotation |

---

##  Running the System

### 1. Start the Server
* **Option A**: Double-click [`start_system.bat`](file:///c:/Users/ivan/Desktop/SYSAD%20System/start_system.bat).
* **Option B**: Run via PowerShell/terminal:
  ```powershell
  python app.py
  ```
Navigate to **`http://127.0.0.1:8000`** in your browser.

### 2. Run the Verification Test Suite
To run the automated verification test validating all 6 Expected Outcomes:
```powershell
python unit_test.py
```

---

##  Client-Side Telemetry Agent (Student PC Monitoring)

Due to browser security sandboxing, web browsers cannot directly query physical CPU, RAM, or Disk metrics from the operating system. To satisfy this requirement, a standalone **Client-Side Telemetry Agent** is deployed in the [`student_agent/`](file:///c:/Users/ivan/Desktop/SYSAD%20System/student_agent) folder:

### 1. Structure
* `student_agent/package.json`: Configures the agent project and dependencies (`systeminformation`).
* `student_agent/agent.js`: Node.js background program that gathers:
  - **CPU Load**: via `si.currentLoad()` / `os.cpus()`
  - **RAM Consumption**: via `si.mem()` / `os.totalmem()` & `os.freemem()`
  - **Storage Volume**: via `si.fsSize()` / `fs.statfsSync()`
  - **Unique Identifier**: Machine Hostname and MAC address
* `student_agent/run_agent.bat`: Double-click batch launcher for students.
* `student_agent/agent.py`: Optional lightweight Python equivalent.

### 2. How to Run the Agent
1. Open a terminal in the `student_agent` directory:
   ```cmd
   cd student_agent
   npm install
   node agent.js
   ```
   *(Or simply double-click `run_agent.bat`)*
2. The agent prints harvested metrics to the console for local verification and transmits the payload every 5 seconds to `http://127.0.0.1:8000/api/telemetry/report`.
3. Log in as **`marcus.it`** (IT Staff) or **`elena.admin`** (Administrator) to monitor the live-updating fleet under **Connected Student Workstations**.
