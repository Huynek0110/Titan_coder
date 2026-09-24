@echo off
setlocal
cd /d "%~dp0"
call npm.cmd run dist
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
echo.
echo Build complete. Check the "release" folder.
pause
