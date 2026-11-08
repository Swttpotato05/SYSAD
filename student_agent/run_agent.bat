@echo off
title SYSAD Student PC Telemetry Agent
echo ========================================================
echo   SYSAD Client-Side Background Telemetry Agent
echo   Reporting real-time host hardware to Central Server
echo ========================================================
echo.

cd /d "%~dp0"

echo [1/2] Checking dependencies...
if not exist "node_modules" (
    echo Installing systeminformation library...
    call npm install
)

echo.
echo [2/2] Starting Telemetry Agent...
node agent.js

pause

