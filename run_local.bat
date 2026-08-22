@echo off
rem Run NOVA directly on this PC - no Docker needed.
setlocal
set "ROOT=%~dp0"
set "VENV=%ROOT%build\venv-win"

if not exist "%VENV%\Scripts\python.exe" (
    echo [NOVA] First run: creating local Python environment...
    python -m venv "%VENV%" || goto :fail
    "%VENV%\Scripts\python.exe" -m pip install --quiet -r "%ROOT%backend\requirements.txt" || goto :fail
)

set "NOVA_MODE=portable"
set "ENVIRONMENT=development"
set "DATA_DIR=%ROOT%backend\data"
set "DATABASE_URL=sqlite:///%DATA_DIR:/=\%/nova.sqlite3"

if "%~1"=="smoke" (
    cd /d "%ROOT%backend"
    "%VENV%\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
    goto :eof
)

start "" cmd /c "timeout /t 3 >nul & start "" http://127.0.0.1:8000/"
cd /d "%ROOT%backend"
echo [NOVA] Dashboard will open at http://127.0.0.1:8000 (Ctrl+C to stop)
"%VENV%\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
goto :eof

:fail
echo [NOVA] Setup failed - is Python installed and on PATH?
pause
