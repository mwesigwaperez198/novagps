@echo off
rem End-to-end smoke test against a running NOVA instance (portable or full).
setlocal
set "BASE=%~1"
if "%BASE%"=="" set "BASE=http://127.0.0.1:8000"

echo == health ==
curl -fsS "%BASE%/health" || goto :fail
echo.

echo == register device with consent ==
curl -fsS -X POST "%BASE%/register" -H "Content-Type: application/json" -d "{\"name\":\"Smoke Phone\",\"email\":\"smoke@nova.local\",\"phone\":\"+15550000001\",\"identifier\":\"smoke-001\",\"device_type\":\"phone\",\"consent_source\":\"manual\",\"consent_scope\":\"smoke-test\"}" > "%TEMP%\nova_device.json" || goto :fail
type "%TEMP%\nova_device.json"
echo.

for /f "tokens=2 delims=:," %%a in ('findstr /c:"\"id\"" "%TEMP%\nova_device.json"') do set "RAWID=%%a"
set "ID=%RAWID:"=%"

echo == update location ==
curl -fsS -X POST "%BASE%/update-location" -H "Content-Type: application/json" -d "{\"device_id\":\"%ID%\",\"latitude\":37.7749,\"longitude\":-122.4194,\"speed\":42.5,\"heading\":90,\"source\":\"mobile\"}" || goto :fail
echo.

echo == devices list ==
curl -fsS "%BASE%/devices" | findstr "smoke-001" >nul && echo devices=ok

echo == tools probe ==
curl -fsS "%BASE%/diagnose/tools"

echo == builtin diagnose ==
curl -fsS -X POST "%BASE%/diagnose" -H "Content-Type: application/json" -d "{\"command_id\":\"system.info\",\"args\":{}}" | findstr "NOVA BUILTIN" >nul && echo diagnose=ok

echo == smoke PASS ==
exit /b 0
:fail
echo smoke FAILED
exit /b 1
