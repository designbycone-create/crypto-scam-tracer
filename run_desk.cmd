@echo off
REM ScamHunter Desk -- starts and supervises all watchers + the dashboard.
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
python desk.py
