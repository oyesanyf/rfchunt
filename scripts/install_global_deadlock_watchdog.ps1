<#
.SYNOPSIS
    Installs (or removes) the global Windows Scheduled Task
    `Antigravity-Global-ConPTY-Deadlock-Watchdog` so Windows automatically clears
    orphaned conhost.exe / OpenConsole.exe zombies, hung non-interactive agent shells,
    and stale .git/index.lock files across all D:\harfile\* repos every 5 minutes —
    even when Antigravity's internal ConPTY shell is deadlocked.

.DESCRIPTION
    Zero Registry/PATH mutations. Runs strictly under the current Windows user account
    with Hidden window style and a 2-minute execution cap.

.EXAMPLE
    # Install and run immediately:
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\install_global_deadlock_watchdog.ps1

.EXAMPLE
    # Customize interval (e.g., every 3 minutes):
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\install_global_deadlock_watchdog.ps1 -EveryMinutes 3

.EXAMPLE
    # Remove the scheduled task cleanly:
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\install_global_deadlock_watchdog.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [string]$TaskName = "Antigravity-Global-ConPTY-Deadlock-Watchdog",
    [int]$EveryMinutes = 5,
    [string]$CleanerScript = "D:\harfile\rfchunt\scripts\clear_conpty_deadlocks.ps1",
    [string]$LogPath = "D:\harfile\rfchunt\reports\ensemble_hunt\conpty_deadlock_watchdog.log",
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[+] Removed Windows Scheduled Task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "[=] Scheduled Task '$TaskName' was not installed." -ForegroundColor Yellow
    }
    exit 0
}

if (-not (Test-Path -LiteralPath $CleanerScript)) {
    throw "Cleaner script not found at '$CleanerScript'."
}

$logDir = Split-Path -Parent $LogPath
if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

$interval = [math]::Max(1, [math]::Min(60, $EveryMinutes))
$argList = @(
    "-NoProfile",
    "-NonInteractive",
    "-WindowStyle", "Hidden",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$CleanerScript`"",
    "-GlobalScan",
    "-IncludeStaleWorkers",
    "-MinAgeMinutes", "3",
    "-Quiet",
    "-LogPath", "`"$LogPath`""
) -join " "

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argList
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $interval) -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
    -MultipleInstances IgnoreNew `
    -Hidden

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Global Windows ConPTY/PowerShell deadlock cleaner across D:\harfile\* repos (zero PATH/Registry mutations)." `
    -Force | Out-Null

Write-Host "[+] Registered global Windows Scheduled Task '$TaskName' (every $interval min, hidden)." -ForegroundColor Green
Write-Host "[+] Watchdog log: $LogPath" -ForegroundColor Cyan

Write-Host "[*] Running initial global sweep now..." -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CleanerScript -GlobalScan -IncludeStaleWorkers -MinAgeMinutes 3 -LogPath $LogPath
$rc = $LASTEXITCODE
Write-Host ("[+] Initial sweep exited with code {0}. Task status:" -f $rc) -ForegroundColor Green
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
