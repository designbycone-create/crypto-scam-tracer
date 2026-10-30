@echo off
REM ScamHunter Desk -- starts and supervises all watchers + the dashboard.
REM Uses whichever Python has the dependencies installed (python, else py -3).
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
python -c "import websockets" >nul 2>nul && (python -u desk.py %* >> desk.log 2>&1 & goto :eof)
py -3 -u desk.py %* >> desk.log 2>&1
