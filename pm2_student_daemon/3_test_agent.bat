@echo off
title Step 3: Test Agent Connection Manually
color 0E
cls
echo ======================================================================
echo   STEP 3: TEST AGENT CONNECTION & HARDWARE POLLING (MANUAL RUN)
echo ======================================================================
echo.

set TARGET_DIR=C:\ProgramData\SysAdmin\student_agent
if exist "%TARGET_DIR%\agent.js" (
    cd /d "%TARGET_DIR%"
) else (
    cd /d "%~dp0"
)

echo Current Directory: %CD%
echo.
echo Select runtime to test:
echo  [1] Node.js Agent: node agent.js (Default)
echo  [2] Python Agent : python agent.py
echo.
set /p test_choice="Enter choice (1 or 2) [Default 1]: "
if "%test_choice%"=="" set test_choice=1

echo.
echo ======================================================================
echo INSTRUCTIONS FOR VERIFICATION:
echo 1. The script will harvest your CPU load, RAM usage, and Disk space.
echo 2. It sends real-time payloads every 5s to http://127.0.0.1:8000/api/telemetry/report
echo 3. Check your central IT Admin / IT Staff dashboard to confirm the PC appears.
echo 4. Once verified, press Ctrl + C in this window to stop the manual test.
echo ======================================================================
echo.

if "%test_choice%"=="1" (
    node agent.js
) else (
    python agent.py
)

pause

