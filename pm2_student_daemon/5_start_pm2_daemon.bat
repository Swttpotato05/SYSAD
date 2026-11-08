@echo off
title Step 5: Start & Save Background Telemetry Daemon
color 0A
cls
echo ======================================================================
echo   STEP 5: START & PERSIST BACKGROUND SERVICE VIA PM2
echo ======================================================================
echo.

set TARGET_DIR=C:\ProgramData\SysAdmin\student_agent
if exist "%TARGET_DIR%\agent.js" (
    cd /d "%TARGET_DIR%"
) else (
    cd /d "%~dp0"
)

echo Working Directory: %CD%
echo.
echo Select agent type:
echo  [1] Node.js Agent: pm2 start agent.js --name "StudentTelemetry" (Default)
echo  [2] Python Agent : pm2 start agent.py --interpreter python --name "StudentTelemetry"
echo.
set /p runtime_choice="Enter choice (1 or 2) [Default 1]: "
if "%runtime_choice%"=="" set runtime_choice=1

echo.
echo [1/4] Starting daemon silently under PM2...
if "%runtime_choice%"=="1" (
    call pm2 start agent.js --name "StudentTelemetry"
) else (
    call pm2 start agent.py --interpreter python --name "StudentTelemetry"
)

echo.
echo [2/4] Configuring auto-startup on boot (pm2 startup)...
echo NOTE: If PM2 outputs a command below, copy and run it as Administrator!
call pm2 startup

echo.
echo [3/4] Saving process snapshot (pm2 save)...
call pm2 save

echo.
echo ======================================================================
echo [4/4] VERIFICATION: Active PM2 Process List
echo ======================================================================
call pm2 list

echo.
echo ======================================================================
echo [SUCCESS] Your 'StudentTelemetry' agent is now running as a silent background daemon!
echo - It will automatically restart if crashed.
echo - It launches automatically on system boot.
echo - You can now CLOSE THIS WINDOW completely; telemetry will keep streaming.
echo ======================================================================
echo.
pause

