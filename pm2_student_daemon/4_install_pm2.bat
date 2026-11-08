@echo off
title Step 4: Install PM2 Global Process Manager
color 0B
cls
echo ======================================================================
echo   STEP 4: INSTALL PM2 PROCESS MANAGER (GLOBAL DAEMON WRAPPER)
echo ======================================================================
echo.
echo Installing PM2 globally via npm...
echo Running: npm install -g pm2
echo.

call npm install -g pm2

echo.
echo Verifying PM2 installation...
call pm2 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo.
    echo ======================================================================
    echo [SUCCESS] Step 4 Complete: PM2 is successfully installed globally!
    echo PM2 Version:
    call pm2 --version
    echo ======================================================================
) else (
    echo.
    echo [WARNING] 'pm2' command not found in current session PATH.
    echo If npm installed successfully, you may need to reopen Command Prompt
    echo or ensure '%APPDATA%\npm' is in your system PATH.
)

echo.
pause

