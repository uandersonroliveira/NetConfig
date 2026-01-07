@echo off
echo ========================================
echo    NetConfig - Stop Server
echo ========================================
echo.

echo Stopping NetConfig server...

:: Find and kill Python processes running src.main
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq python.exe" /fo list ^| find "PID:"') do (
    wmic process where "processid=%%a" get commandline 2>nul | find "src.main" >nul
    if not errorlevel 1 (
        echo Stopping process %%a...
        taskkill /pid %%a /f >nul 2>&1
    )
)

:: Also try to kill uvicorn processes
taskkill /f /im python.exe /fi "WINDOWTITLE eq *NetConfig*" >nul 2>&1

echo.
echo NetConfig server stopped.
echo.
pause
