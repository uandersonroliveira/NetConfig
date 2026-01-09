@echo off
echo ========================================
echo    NetConfig - Stop Server
echo ========================================
echo.

echo Stopping NetConfig server...
echo.

set PORT=8080
set FOUND=0

:: Method 1: Find and kill process by port binding (most reliable)
echo Checking for processes on port %PORT%...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
    if not "%%a"=="0" (
        echo Found process PID %%a on port %PORT%
        taskkill /PID %%a /F >nul 2>&1
        if not errorlevel 1 (
            echo   - Terminated process %%a
            set FOUND=1
        ) else (
            echo   - Failed to terminate process %%a
        )
    )
)

:: Method 2: Find Python processes running src.main or uvicorn
echo Checking for NetConfig Python processes...
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq python.exe" /fo list 2^>nul ^| find "PID:"') do (
    wmic process where "processid=%%a" get commandline 2>nul | find "src.main" >nul
    if not errorlevel 1 (
        echo Found NetConfig process PID %%a
        taskkill /PID %%a /F >nul 2>&1
        if not errorlevel 1 (
            echo   - Terminated process %%a
            set FOUND=1
        )
    )
    wmic process where "processid=%%a" get commandline 2>nul | find "uvicorn" >nul
    if not errorlevel 1 (
        echo Found Uvicorn process PID %%a
        taskkill /PID %%a /F >nul 2>&1
        if not errorlevel 1 (
            echo   - Terminated process %%a
            set FOUND=1
        )
    )
)

:: Wait a moment for port to be released
timeout /t 1 /nobreak >nul

:: Verify port is released
echo.
echo Verifying port %PORT% is released...
netstat -ano | findstr ":%PORT% " | findstr "LISTENING" >nul 2>&1
if errorlevel 1 (
    echo Port %PORT% is now free.
) else (
    echo WARNING: Port %PORT% may still be in use.
    echo You may need to wait a few seconds or restart the terminal.
)

echo.
if "%FOUND%"=="1" (
    echo NetConfig server stopped successfully.
) else (
    echo No running NetConfig server was found.
)
echo.
pause
