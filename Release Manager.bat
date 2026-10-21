@echo off
title XML-ray Release Manager
cd /d "%~dp0"
call "%~dp0_setup.bat" || exit /b 1
start "" ".venv\Scripts\pythonw.exe" "builder\release_manager.py"
