@echo off
title Campus Web Filter External Browser Test
color 0C
cls
echo ======================================================================
echo     SYSAD CAMPUS WEB FILTER - REAL BROWSER INSPECTION TEST
echo ======================================================================
echo.
echo This tool tests how the campus web filter blocks forbidden websites
echo inside Microsoft Edge or Google Chrome WITHOUT using localhost in the URL!
echo.
echo Choose your test target:
echo  [1] www.roblox.com             (Online Gaming - Category: Non-academic)
echo  [2] torrent-tracker.org        (P2P File Sharing)
echo  [3] free-proxy-vpn.net         (Proxy / VPN Evasion)
echo  [4] crypto-miner.io            (Unauthorized Cryptomining)
echo  [5] canvas.campus.edu          (Permitted Academic LMS - 200 OK)
echo  [6] Custom domain / URL
echo.
set /p target_choice="Select website to test (1-6) [Default 1]: "

if "%target_choice%"=="" set target_choice=1
if "%target_choice%"=="1" set TEST_URL=http://www.roblox.com
if "%target_choice%"=="2" set TEST_URL=http://torrent-tracker.org
if "%target_choice%"=="3" set TEST_URL=http://free-proxy-vpn.net
if "%target_choice%"=="4" set TEST_URL=http://crypto-miner.io
if "%target_choice%"=="5" set TEST_URL=http://canvas.campus.edu
if "%target_choice%"=="6" (
    set /p custom_input="Enter domain or URL (e.g. www.roblox.com): "
    set TEST_URL=http://%custom_input%
)

echo.
echo Target URL to browse: %TEST_URL%
echo.
echo How would you like to open it in your browser?
echo  [1] Real Browser Proxy Mode (Opens Edge/Chrome directly showing %TEST_URL% in address bar - NO localhost!)
echo  [2] Standard Gateway URL (Opens default browser via http://127.0.0.1:8000/gateway)
echo.
set /p mode_choice="Select mode (1 or 2) [Default 1]: "
if "%mode_choice%"=="" set mode_choice=1

if "%mode_choice%"=="1" (
    echo.
    echo [*] Launching browser in Campus Filter Proxy mode...
    echo [*] Checking browser executable...
    
    if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
        echo [OK] Found Microsoft Edge. Opening %TEST_URL%...
        start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --proxy-server="http://127.0.0.1:8000" "%TEST_URL%"
    ) else if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
        echo [OK] Found Google Chrome. Opening %TEST_URL%...
        start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server="http://127.0.0.1:8000" "%TEST_URL%"
    ) else (
        echo [!] Using default browser via gateway fallback...
        start "" "http://127.0.0.1:8000/gateway?url=%TEST_URL%"
    )
) else (
    echo.
    echo [*] Opening via Central Gateway...
    start "" "http://127.0.0.1:8000/gateway?url=%TEST_URL%"
)

echo.
echo ======================================================================
echo [RESULT EXPECTATION]
echo  - The browser address bar will show: %TEST_URL%
echo  - The screen renders the 403 Forbidden Campus Block Page
echo  - The violation is logged in data/audit_ticket_logs.db
echo  - Real-time toast alert will appear on IT Staff / Admin Dashboards!
echo ======================================================================
echo.
pause
