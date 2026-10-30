@echo off
REM ScamHunter Desk -- starts and supervises all watchers + the dashboard.
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
where py >nul 2>nul && (py -3 -u desk.py %* >> desk.log 2>&1) || (python -u desk.py %* >> desk.log 2>&1)
