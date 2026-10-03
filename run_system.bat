@echo off
title Health Archive Server
cd /d "%~dp0"
if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
)
start "" http://localhost:8000
python server.py
pause
