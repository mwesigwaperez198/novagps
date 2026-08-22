@echo off
setlocal enabledelayedexpansion
set "ROOT=%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8000"

set "PY=%ROOT%runtime\windows-x86_64\python\python.exe"
if not exist "%PY%" (
    echo [NOVA] Missing runtime for windows-x86_64. Run build_portable.py first.
    pause
    exit /b 1
)

rem Prefer data inside the mounted encrypted container (see secure\README_ENCRYPTION.txt)
set "DATA_DIR=%ROOT%data"
if exist "%ROOT%secure\data" set "DATA_DIR=%ROOT%secure\data"
if "%DATA_DIR%"=="%ROOT%data" (
    echo [NOVA] WARNING: using unencrypted %ROOT%data - mount your VeraCrypt container into secure\data for at-rest protection.
)

set "NOVA_MODE=portable"
set "ENVIRONMENT=development"
set "DATA_DIR=%DATA_DIR%"
set "DATABASE_URL=sqlite:///%DATA_DIR%/nova.sqlite3"
set "PYTHONPATH=%ROOT%app\backend"
set "PYTHONHOME=%ROOT%runtime\windows-x86_64\python"
set "PATH=%ROOT%runtime\windows-x86_64\python;%PATH%"

cd /d "%ROOT%app\backend"
echo [NOVA] Bootstrapping portable database...
"%PY%" bootstrap_portable.py || (pause & exit /b 1)

start "" cmd /c "timeout /t 2 >nul & start "" http://127.0.0.1:%PORT%/"
echo [NOVA] Starting NOVA on http://127.0.0.1:%PORT%/ (Ctrl+C to stop)
"%PY%" -m uvicorn main:app --host 127.0.0.1 --port %PORT%
endlocal
