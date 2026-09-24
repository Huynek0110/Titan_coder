@echo off
setlocal
cd /d "%~dp0"
where git >nul 2>nul
if errorlevel 1 (
  echo Git is not installed. Install Git for Windows first.
  pause
  exit /b 1
)
if not exist ".git" git init
if not exist ".git\config" (
  echo Cannot initialize Git repository.
  pause
  exit /b 1
)
git add -A
if errorlevel 1 (
  pause
  exit /b 1
)
git diff --cached --quiet
if errorlevel 1 (
  git -c user.name="CodePilot Local Backup" -c user.email="backup@localhost" commit -m "backup: save working source"
  if errorlevel 1 (
    echo Commit failed.
    pause
    exit /b 1
  )
) else (
  echo Nothing new to commit.
)
git status --short
echo Local Git backup complete.
pause
