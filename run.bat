@echo off
title Health Archive Server v3
echo.
echo ============================================================
echo   Health Directorate Employee Archive System  ^|  v3
echo ============================================================
echo.

echo [1/2] Installing packages (offline)...
pip install --no-index --find-links=packages -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo   Offline install failed – trying online...
    pip install -r requirements.txt --quiet
)

echo [2/2] Starting server on port 8000...
echo.
python server.py

pause
