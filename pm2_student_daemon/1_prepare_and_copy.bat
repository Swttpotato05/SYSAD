@echo off
title Step 1: Prepare Student PC & Copy Agent
color 0B
cls
echo ======================================================================
echo   STEP 1: PREPARE STUDENT PC AND SECURE FOLDER DEPLOYMENT
echo ======================================================================
echo.

set TARGET_DIR=C:\ProgramData\SysAdmin\student_agent

echo Target Directory: %TARGET_DIR%
echo.
echo Checking runtime prerequisites...
node -v >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [OK] Node.js is installed. Version:
    node -v
) else (
    echo [!] Node.js not detected on PATH. Checking Python...
    python --version >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        echo [OK] Python is installed.
    ) else (
        echo [ERROR] Neither Node.js nor Python was found on this system!
        echo Please install Node.js (https://nodejs.org) or Python before continuing.
        pause
        exit /b 1
    )
)

echo.
echo Creating secure directory: %TARGET_DIR%...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"

echo.
echo Copying agent files to %TARGET_DIR%...
xcopy /E /I /Y "%~dp0*.*" "%TARGET_DIR%\"

if %ERRORLEVEL% equ 0 (
    echo.
    echo ======================================================================
    echo [SUCCESS] Step 1 Complete!
    echo Files successfully deployed to: %TARGET_DIR%
    echo Students do not have write access to ProgramData by default.
    echo ======================================================================
) else (
    echo [ERROR] Failed to copy files. Please ensure you Run as administrator!
)

echo.
pause

