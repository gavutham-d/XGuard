@echo off
echo ========================================================
echo    Starting XGuard FastAPI Detection Backend
echo ========================================================
cd /d "%~dp0"
set PYTHONPATH=%CD%\backend;%CD%\ml;%PYTHONPATH%
python backend\app\main.py
pause
