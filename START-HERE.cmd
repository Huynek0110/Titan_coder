@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is required. Install Node.js 22 or newer, then run this file again.
  pause
  exit /b 1
)
if not exist "node_modules\electron\dist\electron.exe" (
  echo Installing dependencies for the first run...
  call npm.cmd install
  if errorlevel 1 (
    pause
    exit /b 1
  )
)
call npm.cmd start
