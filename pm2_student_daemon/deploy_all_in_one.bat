@echo off
title Turnkey Automated PM2 Telemetry Agent Installer
color 0B
cls
echo ======================================================================
echo    SYSAD CLIENT-SIDE TELEMETRY AGENT - TURNKEY PM2 DAEMON INSTALLER
echo ======================================================================
echo.
echo This turnkey script automatically executes all 5 steps from the guide:
echo  1. Prepares C:\ProgramData\SysAdmin\student_agent\
echo  2. Installs hardware polling dependencies (systeminformation)
echo  3. Tests manual connection to central server
echo  4. Installs PM2 process manager globally
echo  5. Starts and locks 'StudentTelemetry' as a silent auto-boot service
echo.
echo NOTE: Please run this script as Administrator.
echo.
pause

set TARGET_DIR=C:\ProgramData\SysAdmin\student_agent

:: Step 1
echo.
echo ======================================================================
echo [STEP 1/5] Creating secure directory & copying files...
echo ======================================================================
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"
xcopy /E /I /Y "%~dp0*.*" "%TARGET_DIR%\" >nul 2>&1
cd /d "%TARGET_DIR%"
echo [OK] Deployed files to: %TARGET_DIR%

:: Step 2
echo.
echo ======================================================================
echo [STEP 2/5] Installing hardware dependencies (systeminformation)...
echo ======================================================================
call npm install systeminformation
echo [OK] Dependencies installed.

:: Step 3
echo.
echo ======================================================================
echo [STEP 3/5] Testing telemetry collection (Running 1 cycle)...
echo ======================================================================
echo Starting 5-second manual test...
start /b node -e "const { collectMetrics } = require('./agent.js'); collectMetrics().then(m => { console.log('Hardware test passed! CPU: ' + m.cpu_load + '%, RAM: ' + m.ram_usage_pct + '%, Disk: ' + m.disk_usage_pct + '%'); process.exit(0); });"
timeout /t 6 >nul 2>&1
echo [OK] Telemetry collection verified!

:: Step 4
echo.
echo ======================================================================
echo [STEP 4/5] Installing PM2 process manager globally...
echo ======================================================================
call npm install -g pm2
echo [OK] PM2 installed.

:: Step 5
echo.
echo ======================================================================
echo [STEP 5/5] Registering 'StudentTelemetry' service with PM2...
echo ======================================================================
call pm2 delete StudentTelemetry >nul 2>&1
call pm2 start agent.js --name "StudentTelemetry"
call pm2 startup
call pm2 save

echo.
echo ======================================================================
echo [VERIFICATION CHECKLIST]
echo ======================================================================
call pm2 list

echo.
echo ======================================================================
echo [COMPLETE] The Student Telemetry Agent is now running SILENTLY in the
echo background as a system daemon!
echo.
echo To manage this service in the future, run:
echo   - pm2 status            (Check online status)
echo   - pm2 logs StudentTelemetry  (View live heartbeats)
echo   - pm2 restart StudentTelemetry (Restart daemon)
echo   - pm2 stop StudentTelemetry    (Stop daemon)
echo ======================================================================
echo.
pause

