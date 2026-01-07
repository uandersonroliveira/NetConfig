@echo off
echo ========================================
echo    NetConfig - Network Switch Manager
echo ========================================
echo.

cd /d "%~dp0"

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        echo Make sure Python 3.11+ is installed and in PATH.
        pause
        exit /b 1
    )
)

echo Activating virtual environment...
call venv\Scripts\activate

echo Installing/updating dependencies...
pip install -r requirements.txt -q

echo.
echo Starting NetConfig server...
echo Access the web interface at: http://127.0.0.1:8080
echo Press Ctrl+C to stop the server.
echo.

python -m src.main

pause
