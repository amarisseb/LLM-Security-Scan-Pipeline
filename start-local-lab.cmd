@echo off
setlocal
rem Prisma's binary engine emits the ready message at INFO level. An inherited
rem RUST_LOG=warn hides it and leaves AnythingLLM waiting indefinitely.
rem This change applies only to this launcher and its child process.
set "RUST_LOG="
set "ARISEC_LAB_APP=%LOCALAPPDATA%\Programs\AnythingLLM\AnythingLLM.exe"
if not exist "%ARISEC_LAB_APP%" (
  echo AnythingLLM Desktop was not found in its default per-user installation folder.
  echo Install it from https://anythingllm.com/download and try again.
  pause
  exit /b 1
)
start "" "%ARISEC_LAB_APP%"
endlocal
