@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Create the virtual environment and install requirements.txt first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" "tools\run_customer_preview.py" %*
pause
