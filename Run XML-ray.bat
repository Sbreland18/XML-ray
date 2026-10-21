@echo off
title XML-ray
cd /d "%~dp0"
call "%~dp0_setup.bat" || exit /b 1
start "" ".venv\Scripts\pythonw.exe" "run.py"
