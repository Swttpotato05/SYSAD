@echo off
title Uninstall Student Telemetry Background Daemon
color 0C
cls
echo ======================================================================
echo    UNINSTALL STUDENT TELEMETRY DAEMON
echo ======================================================================
echo.
echo This script removes the 'StudentTelemetry' daemon from PM2 autostart.
echo.
pause

echo Stopping daemon...
call pm2 stop StudentTelemetry

echo Deleting daemon registration...
call pm2 delete StudentTelemetry

echo Saving PM2 state...
call pm2 save

echo.
echo ======================================================================
echo [SUCCESS] 'StudentTelemetry' has been completely removed from PM2!
echo ======================================================================
echo.
pause

