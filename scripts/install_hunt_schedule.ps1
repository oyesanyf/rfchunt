<#
.SYNOPSIS
    Installs, runs, or removes a Windows Scheduled Task for RFCHunt's standalone
    headless defensive hunting pipeline (`scripts/autonomous_hunt.py`).

.DESCRIPTION
    Strictly process-scoped: NEVER modifies Windows Registry environment variables or PATH.
    Uses Windows Task Scheduler (`Register-ScheduledTask`) to execute `autonomous_hunt.py`
    automatically on a repeating interval (default: every 60 minutes) with zero `/browser`.

.EXAMPLE
    # Install hourly scheduled hunt over unlocked watchlist repos
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\install_hunt_schedule.ps1 -IntervalMinutes 60 -CloneUnlocked

.EXAMPLE
    # Install scheduled hunt targeting a specific local repo & HackerOne handle
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\install_hunt_schedule.ps1 -TargetRepo "d:\harfile\target_repo" -Program "common_codes" -IntervalMinutes 120 -RunNow

.EXAMPLE
    # Remove the scheduled task
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\install_hunt_schedule.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [string]$TaskName = "RFCHunt-Autonomous-Defensive-Hunt",
    [string]$RfcHuntRoot = "d:\harfile\rfchunt",
    [string]$PythonExe = "python",
    [string]$TargetRepo = "",
    [string]$Program = "generic",
    [int]$IntervalMinutes = 60,
    [switch]$CloneUnlocked,
    [switch]$StartModelFusion,
    [switch]$Embedded,
    [switch]$RunNow,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[OK] Removed Windows Scheduled Task '$TaskName'."
    } else {
        Write-Host "[INFO] Scheduled Task '$TaskName' was not registered."
    }
    exit 0
}

$scriptPath = Join-Path $RfcHuntRoot "scripts\autonomous_hunt.py"
if (-not (Test-Path $scriptPath)) {
    throw "Hunting script not found at '$scriptPath'."
}

$argList = @("`"$scriptPath`"")
if ($TargetRepo -and $TargetRepo.Trim().Length -gt 0) {
    $argList += @("--target", "`"$TargetRepo`"", "--program", $Program)
}
if ($CloneUnlocked) {
    $argList += "--clone-unlocked"
}
if ($StartModelFusion) {
    $argList += "--start-modelfusion"
}
if ($Embedded) {
    $argList += "--embedded"
}
$argList += @("--out", "`"$(Join-Path $RfcHuntRoot 'out\autonomous_hunt')`"")
$arguments = $argList -join " "

$action = New-ScheduledTaskAction -Execute $PythonExe -Argument $arguments -WorkingDirectory $RfcHuntRoot
$minutesClamped = [Math]::Max(5, $IntervalMinutes)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes $minutesClamped) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "RFCHunt + ModelFusion headless defensive security audit, violation checks, and draft QA." `
    -Force | Out-Null

Write-Host "[OK] Registered Scheduled Task '$TaskName' (every $minutesClamped min, headless, zero /browser)."
Write-Host "     Command: $PythonExe $arguments"

if ($RunNow) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "[OK] Triggered immediate run of '$TaskName'."
}
