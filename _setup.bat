@echo off
rem Shared setup used by the launchers: makes sure Python and the build tools are ready.
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto :tools

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  python --version >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo  Python isn't installed on this PC.
  echo  1. Download it from https://www.python.org/downloads/
  echo  2. In the installer, tick "Add python.exe to PATH".
  echo  3. Double-click this file again.
  echo.
  start "" "https://www.python.org/downloads/"
  pause
  exit /b 1
)

echo First-time setup: creating a private Python environment in .venv ...
%PY% -m venv .venv
if errorlevel 1 (
  echo Couldn't create the Python environment.
  pause
  exit /b 1
)

:tools
echo Checking build tools (the first run downloads them and takes a few minutes) ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements-dev.txt
if errorlevel 1 (
  echo.
  echo Installing the build tools failed. Check your internet connection and try again.
  pause
  exit /b 1
)
exit /b 0
