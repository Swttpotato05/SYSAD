# Student Workstation Telemetry Agent — PM2 Background Daemon Deployment Guide

To install and run the telemetry agent as a **silent background daemon** on a student PC, the most reliable approach is to use **PM2**, an industry-standard process manager.

### Why PM2?
- **Invisibility:** Hides the execution terminal from the student (runs as a Windows background task).
- **Self-Healing:** Automatically restarts the script within milliseconds if it crashes or is terminated.
- **Persistence:** Forces the script to launch automatically whenever the student computer boots up or reboots.

---

## Deployment Procedure (Step-by-Step)

You can use this method for either the **Node.js** or the **Python** agent.

```
+------------------------------------------------------------------------------------------------+
|  Step 1: Copy to Secure Directory -> Step 2: Install Dependencies -> Step 3: Manual Test Run  |
|                                                                                                |
|  Step 4: Install PM2 Globally     -> Step 5: Start & Save Daemon   -> Silent Background State  |
+------------------------------------------------------------------------------------------------+
```

---

### Step 1: Prepare the Student PC (Prerequisites)
1. Ensure the required runtime (**Node.js** v18+ or **Python** 3.10+) is installed on the student computer.
2. Copy the `student_agent` folder to a secure local directory that students do not easily access, such as:
   ```text
   C:\ProgramData\SysAdmin\student_agent\
   ```
   *(Students on restricted campus accounts do not have write access to `C:\ProgramData`)*.

> **Automated Script:** You can run `1_prepare_and_copy.bat` as Administrator to perform this step automatically.

---

### Step 2: Install Agent Dependencies (Command Line)
1. Open Command Prompt or PowerShell as an **Administrator**.
2. Navigate to the folder:
   ```cmd
   cd C:\ProgramData\SysAdmin\student_agent\
   ```
3. Install the required hardware polling libraries:
   - **For Node.js:**
     ```cmd
     npm install systeminformation
     ```
   - **For Python:**
     ```cmd
     pip install psutil requests
     ```
4. **Verification:** The terminal displays a successful installation message with no critical red error text.

> **Automated Script:** You can run `2_install_dependencies.bat` to perform this step.

---

### Step 3: Test the Agent Connection (Manual Run)
Run the script manually to ensure it correctly polls the hardware and resolves the central server's IP address:
- **For Node.js:**
  ```cmd
  node agent.js
  ```
- **For Python:**
  ```cmd
  python agent.py
  ```

**Verification:**
- Log into your central IT Admin / IT Staff dashboard on the server (`http://localhost:8000`).
- The live hardware metrics (**CPU Load %**, **RAM Consumption**, **Storage Volume**) for this specific student PC should appear on the workstation fleet monitor.
- Once verified, press <kbd>Ctrl</kbd> + <kbd>C</kbd> in the student PC's terminal to stop the manual test.

> **Automated Script:** You can run `3_test_agent.bat` to perform this test.

---

### Step 4: Install the PM2 Process Manager (Global Daemon)
Install PM2 globally on the student PC:
```cmd
npm install -g pm2
```
PM2 acts as the background service wrapper that keeps your agent running invisibly.

**Verification:**
Run:
```cmd
pm2 --version
```
Confirm the installation returns a version number (e.g. `5.3.x` or higher).

> **Automated Script:** You can run `4_install_pm2.bat` to install PM2.

---

### Step 5: Start and Save the Background Service (Automation)

1. Start your agent silently:
   - **For Node.js:**
     ```cmd
     pm2 start agent.js --name "StudentTelemetry"
     ```
   - **For Python:**
     ```cmd
     pm2 start agent.py --interpreter python --name "StudentTelemetry"
     ```
   *(Or launch via ecosystem config: `pm2 start ecosystem.config.js`)*.

2. Ensure the agent starts automatically every time the student PC boots up:
   ```cmd
   pm2 startup
   ```
   PM2 will output a specific command—copy and paste that exact command into the terminal and press <kbd>Enter</kbd>.

3. Lock in the configuration so it persists across reboots:
   ```cmd
   pm2 save
   ```

**Verification:**
Run:
```cmd
pm2 list
```
Your **"StudentTelemetry"** agent will be listed with an **"online"** status. You can now close the terminal entirely, and the agent will continue beaming metrics to your central server in the background.

> **Automated Script:** You can run `5_start_pm2_daemon.bat` to start, register, and verify the service.

---

## ⚡ Turnkey 1-Click Deployment

If you want to perform all 5 steps in a single automated command:
1. Right-click **`deploy_all_in_one.bat`**.
2. Select **Run as administrator**.
3. The script will copy the files, install dependencies, run a connection test, install PM2, and register `StudentTelemetry` as an auto-boot background service.

---

## Daily Management & Diagnostics

Use **`manage_service.bat`** or the following standard PM2 commands:

| Task | Command |
| :--- | :--- |
| **Check Live Status** | `pm2 status` or `pm2 list` |
| **View Real-Time Heartbeats** | `pm2 logs StudentTelemetry --lines 30` |
| **Restart Service** | `pm2 restart StudentTelemetry` |
| **Stop Service** | `pm2 stop StudentTelemetry` |
| **Remove / Uninstall** | `pm2 delete StudentTelemetry && pm2 save` *(or run `uninstall_pm2_daemon.bat`)* |

---

## Environment Variables (Optional Customization)

To point the agent to a remote campus server, set these variables before starting PM2:

```cmd
set SYSAD_SERVER_HOST=192.168.1.100
set SYSAD_SERVER_PORT=8000
set STUDENT_USER=alex.student
pm2 restart StudentTelemetry --update-env
```
*(Or edit `ecosystem.config.js` directly).*

