@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Creating the project Python environment...
    python -m venv --system-site-packages .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -c "import fastapi, uvicorn, playwright, garak, litellm, email_validator" >nul 2>&1
if errorlevel 1 (
    echo Installing project dependencies. This may take several minutes...
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if errorlevel 1 goto failed
)
echo Checking the Chromium browser used for scans...
".venv\Scripts\python.exe" -m playwright install chromium
if errorlevel 1 goto failed
set PYTHONUTF8=1
echo Open http://127.0.0.1:8000/ in your browser.
echo Keep this window open while using Arisec. Press Ctrl+C to stop.
".venv\Scripts\python.exe" demo\run_demo.py %*
if errorlevel 1 goto failed
exit /b 0
:failed
echo.
echo Arisec could not start. Read the error above before closing this window.
pause
exit /b 1
