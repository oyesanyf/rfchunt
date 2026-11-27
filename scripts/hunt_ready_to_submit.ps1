<#
.SYNOPSIS
    One-command autonomous RFCHunt + ModelFusion hunter that handles everything up to
    your final manual "Submit report" click.

.DESCRIPTION
    Automatically:
      1. Starts ModelFusion local server (:5000) with abliterated security models + Anti-Junk Guards
      2. Polls & shallow-clones unlocked in-scope watchlist repos (or your -TargetRepo)
      3. Runs 3-stage parallel fast-ooda + exhaustive --all --ensemble SARIF + Lean 4 verification
      4. Enforces ProgramEligibilityDB + secret/PHI redaction + strict HTML/entity/QA checks
      5. Stages ONLY QA-passed, zero-violation drafts into HackerOne (via HugOS Browser CDP :9222
         or a persistent Chromium profile — NEVER clicks Submit and NEVER bypasses CAPTCHAs)
      6. Drops clickable links into out\autonomous_hunt\READY_TO_CLICK_SUBMIT.md

.EXAMPLE
    # Default: continuous 60-minute autonomous loop (all you do is review & click Submit)
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\hunt_ready_to_submit.ps1

.EXAMPLE
    # Single pass on a specific local repo & program
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\hunt_ready_to_submit.ps1 -TargetRepo "d:\harfile\my_target" -Program "common_codes" -Once

.EXAMPLE
    # Install in Windows Task Scheduler (runs automatically every 60 minutes)
    powershell -ExecutionPolicy Bypass -File d:\harfile\rfchunt\scripts\hunt_ready_to_submit.ps1 -InstallSchedule
#>

[CmdletBinding()]
param(
    [string]$RfcHuntRoot = "d:\harfile\rfchunt",
    [string]$TargetRepo = "",
    [string]$Program = "generic",
    [int]$IntervalMinutes = 60,
    [int]$MaxRepos = 4,
    [switch]$Once,
    [switch]$HeadlessOnly,
    [switch]$InstallSchedule,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location $RfcHuntRoot

if ($InstallSchedule) {
    $schedArgs = @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $RfcHuntRoot "scripts\install_hunt_schedule.ps1"),
        "-IntervalMinutes", "$IntervalMinutes",
        "-StartModelFusion",
        "-RunNow"
    )
    if ($TargetRepo -and $TargetRepo.Trim().Length -gt 0) {
        $schedArgs += @("-TargetRepo", $TargetRepo, "-Program", $Program)
    } else {
        $schedArgs += "-CloneUnlocked"
    }
    & powershell @schedArgs
    exit $LASTEXITCODE
}

$pyArgs = @(
    (Join-Path $RfcHuntRoot "scripts\autonomous_hunt.py"),
    "--start-modelfusion"
)

if ($TargetRepo -and $TargetRepo.Trim().Length -gt 0) {
    $pyArgs += @("--target", $TargetRepo, "--program", $Program)
} else {
    $pyArgs += @("--clone-unlocked", "--max-repos", "$MaxRepos")
}

if (-not $HeadlessOnly) {
    $pyArgs += @("--stage-drafts", "--open-chrome")
}

if (-not $Once) {
    $pyArgs += @("--watch", "--interval-minutes", "$IntervalMinutes")
}

if ($DryRun) {
    $pyArgs += "--dry-run"
}

Write-Host "========================================================================"
Write-Host " RFCHunt + ModelFusion Autonomous Hunter (Draft-Only HITL Mode)"
Write-Host " -> Auto-Submit: FORBIDDEN | CAPTCHA Bypass: FORBIDDEN"
Write-Host " -> Ready links: $RfcHuntRoot\out\autonomous_hunt\READY_TO_CLICK_SUBMIT.md"
Write-Host "========================================================================"

& python @pyArgs
exit $LASTEXITCODE
