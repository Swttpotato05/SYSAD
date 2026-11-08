@echo off
title SYSAD Centralized Portal System
color 0B
echo ========================================================
echo       SYSAD CENTRALIZED PORTAL & DFD SYSTEM
echo ========================================================
echo.
echo Initializing Data Stores:
echo  1. User & Roles Database (data/user_roles.db)
echo  2. Audit & Ticket Logs DB (data/audit_ticket_logs.db)
echo.
echo Opening portal in your default browser...
start "" "http://127.0.0.1:8000"
echo Starting Web Server on http://127.0.0.1:8000 ...
echo Press Ctrl+C in this window to stop the server.
echo.

python app.py
pause
