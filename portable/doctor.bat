@echo off
setlocal
set "ROOT=%~dp0"
set "PY=%ROOT%runtime\windows-x86_64\python\python.exe"
if not exist "%PY%" (
    echo [NOVA] Missing runtime windows-x86_64.
    exit /b 1
)
set "NOVA_MODE=portable"
set "ENVIRONMENT=development"
set "DATA_DIR=%ROOT%data"
if exist "%ROOT%secure\data" set "DATA_DIR=%ROOT%secure\data"
set "DATABASE_URL=sqlite:///%DATA_DIR%/nova.sqlite3"
set "PYTHONPATH=%ROOT%app\backend"
cd /d "%ROOT%app\backend"
echo === NOVA doctor: bootstrap check ===
"%PY%" bootstrap_portable.py
echo === NOVA doctor: security tools on PATH ===
"%PY%" doctor_tools.py
pause
