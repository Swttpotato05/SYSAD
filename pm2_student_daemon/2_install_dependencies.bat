@echo off
title Step 2: Install Agent Dependencies
color 0B
cls
echo ======================================================================
echo   STEP 2: INSTALL AGENT HARDWARE POLLING DEPENDENCIES
echo ======================================================================
echo.

set TARGET_DIR=C:\ProgramData\SysAdmin\student_agent

if exist "%TARGET_DIR%" (
    echo Using deployed directory: %TARGET_DIR%
    cd /d "%TARGET_DIR%"
) else (
    echo [INFO] Deployed folder not found. Installing in current folder: %~dp0
    cd /d "%~dp0"
)

echo.
echo Select which agent dependencies to install:
echo  [1] Node.js Agent: npm install systeminformation (Recommended)
echo  [2] Python Agent : pip install psutil requests
echo.
set /p dep_choice="Enter choice (1 or 2) [Default 1]: "
if "%dep_choice%"=="" set dep_choice=1

if "%dep_choice%"=="1" (
    echo.
    echo Running: npm install systeminformation...
    call npm install systeminformation
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================================================
        echo [SUCCESS] Step 2 Complete: 'systeminformation' installed successfully!
        echo The terminal displays no critical red error text.
        echo ======================================================================
    ) else (
        echo [ERROR] npm install encountered an error.
    )
) else (
    echo.
    echo Running: pip install psutil requests...
    python -m pip install psutil requests
    if %ERRORLEVEL% equ 0 (
        echo.
        echo ======================================================================
        echo [SUCCESS] Step 2 Complete: 'psutil' and 'requests' installed!
        echo ======================================================================
    ) else (
        echo [ERROR] pip install encountered an error.
    )
)

echo.
pause

