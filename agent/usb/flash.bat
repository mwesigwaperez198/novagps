@echo off
rem NOVA USB flash tool -- run this from the flash drive.
rem Provisions an Android phone with the encrypted .nova payload over ADB.
rem Drag & drop a .nova file onto this .bat, or run: flash payloads\device.nova

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PAYLOAD=%~1"
if "%PAYLOAD%"=="" set "PAYLOAD=payloads\device.nova"
if not exist "%PAYLOAD%" (
    echo [NOVA] payload not found: %PAYLOAD%
    echo        place a .nova file in the payloads\ folder or drag it onto this script.
    goto :err
)

set "ADB=platform-tools\adb.exe"
if not exist "%ADB%" set "ADB=adb"
"%ADB%" version >nul 2>&1 || (
    echo [NOVA] adb missing. Keep platform-tools\adb.exe beside me on the stick.
    goto :err
)

echo [NOVA] USB flash tool
echo [NOVA] waiting for a phone (USB debugging enabled)...
"%ADB%" wait-for-device
echo [NOVA] device detected.

set "AGENT=com.novara.agent"
"%ADB%" shell pm path %AGENT% >nul 2>&1
if errorlevel 1 (
    echo [NOVA] installing bootstrap agent once...
    "%ADB%" install -r -t "bootstrap\bootstrap-agent.apk" || goto :err
)

echo [NOVA] pushing encrypted payload...
"%ADB%" push "%PAYLOAD%" /sdcard/Download/nova-payload.nova || goto :err

echo [NOVA] telling the agent to unlock and attach...
"%ADB%" shell am start -n %AGENT%/.ImportActivity --es file /sdcard/Download/nova-payload.nova >nul

set "OWNER=%~2"
if /i "%OWNER%"=="--owner" (
    echo [NOVA] provisioning hidden device-owner mode...
    "%ADB%" shell dpm set-device-owner %AGENT%/.bootstrap.DeviceOwnerAdmin >nul 2>&1 && (
        echo [NOVA] device owner granted: icon hidden, boots with phone.
    ) || (
        echo [NOVA] owner failed. Needs a fresh device with no accounts.
    )
)

echo [NOVA] done. Verify the phone appears LIVE on the NOVA dashboard.
exit /b 0

:err
echo [NOVA] failed.
exit /b 1