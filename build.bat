@echo off
REM NOVA GPS Desktop App — Windows Build Script
REM Usage: build.bat [win|portable|all]
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "ELECTRON=%ROOT%electron"
set "SCRIPTS=%ROOT%scripts"
set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=win"

echo [NOVA] Build system for Windows
echo [NOVA] Target: %TARGET%

where node >nul 2>&1 || (echo [ERROR] Node.js not found. Install from https://nodejs.org & pause & exit /b 1)
where npm >nul 2>&1 || (echo [ERROR] npm not found. & pause & exit /b 1)
where python >nul 2>&1 || where python3 >nul 2>&1 || (echo [ERROR] Python 3 not found. & pause & exit /b 1)
where py >nul 2>&1 || (echo [ERROR] py launcher not found. & pause & exit /b 1)

echo [NOVA] Deps OK: node, npm, python

if "%TARGET%"=="win" goto :build_electron
if "%TARGET%"=="portable" goto :build_portable
if "%TARGET%"=="all" goto :build_all
echo [ERROR] Unknown target: %TARGET%
echo Usage: build.bat [win^|portable^|all]
pause
exit /b 1

:build_all
:build_electron
echo [NOVA] Building frontend...
cd /d "%ROOT%frontend"
call npm install --silent
call npm run build
if errorlevel 1 (echo [ERROR] Frontend build failed & pause & exit /b 1)

echo [NOVA] Building backend binary...
cd /d "%ROOT%"
call py "%ELECTRON%\build_backend.py" --platform win --skip-frontend --skip-electron
if errorlevel 1 (echo [ERROR] Backend build failed & pause & exit /b 1)

echo [NOVA] Building Electron installer...
cd /d "%ELECTRON%"
call npm install --silent
call npx electron-builder --win nsis
if errorlevel 1 (echo [ERROR] Electron build failed & pause & exit /b 1)

echo [NOVA] Build complete! Check electron\release\
dir "%ELECTRON%\release\"
goto :eof

:build_portable
echo [NOVA] Building portable bundle...
cd /d "%ROOT%"
call py "%SCRIPTS%\build_portable.py"
echo [NOVA] Portable bundle complete!
goto :eof
