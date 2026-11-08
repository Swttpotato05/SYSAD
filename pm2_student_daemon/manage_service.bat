@echo off
title Student Telemetry Daemon Control Panel
color 0B
:menu
cls
echo ======================================================================
echo    SYSAD STUDENT TELEMETRY DAEMON - MANAGEMENT CONTROL PANEL
echo ======================================================================
echo.
echo Choose an action:
echo  [1] View Service Status (pm2 status / pm2 list)
echo  [2] View Real-Time Telemetry Logs (pm2 logs StudentTelemetry)
echo  [3] Restart Telemetry Daemon (pm2 restart StudentTelemetry)
echo  [4] Stop Telemetry Daemon (pm2 stop StudentTelemetry)
echo  [5] Start / Resume Daemon (pm2 start StudentTelemetry)
echo  [6] Uninstall / Remove Daemon from PM2
echo  [7] Exit
echo.
set /p opt="Enter option (1-7): "

if "%opt%"=="1" (
    cls
    echo Active PM2 Daemons:
    echo ----------------------------------------------------
    call pm2 list
    echo ----------------------------------------------------
    pause
    goto menu
) else if "%opt%"=="2" (
    cls
    echo Showing recent logs (Press Ctrl+C to stop following logs):
    echo ----------------------------------------------------
    call pm2 logs StudentTelemetry --lines 30
    pause
    goto menu
) else if "%opt%"=="3" (
    cls
    echo Restarting StudentTelemetry daemon...
    call pm2 restart StudentTelemetry
    call pm2 save
    pause
    goto menu
) else if "%opt%"=="4" (
    cls
    echo Stopping StudentTelemetry daemon...
    call pm2 stop StudentTelemetry
    call pm2 save
    pause
    goto menu
) else if "%opt%"=="5" (
    cls
    echo Starting StudentTelemetry daemon...
    call pm2 start StudentTelemetry
    call pm2 save
    pause
    goto menu
) else if "%opt%"=="6" (
    cls
    echo Removing StudentTelemetry from PM2...
    call pm2 stop StudentTelemetry
    call pm2 delete StudentTelemetry
    call pm2 save
    echo [OK] Removed from PM2.
    pause
    goto menu
) else if "%opt%"=="7" (
    exit /b 0
) else (
    goto menu
)

