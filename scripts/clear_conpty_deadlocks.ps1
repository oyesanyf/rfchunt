<#
.SYNOPSIS
    Global Windows ConPTY / PowerShell Deadlock Cleaner & Watchdog (`clear_conpty_deadlocks.ps1`).
    Diagnoses and clears orphaned conhost.exe / OpenConsole.exe pseudo-consoles, hung
    non-interactive agent shells, orphaned git/pytest/cargo workers, and stale .git/index.lock
    files across all repositories under D:\harfile (zero Windows Registry or PATH mutation).

.EXAMPLE
    # Read-only diagnostic preview:
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\clear_conpty_deadlocks.ps1 -DryRun

.EXAMPLE
    # Immediate global cleanup across all D:\harfile\* repos:
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\clear_conpty_deadlocks.ps1 -GlobalScan -IncludeStaleWorkers

.EXAMPLE
    # Install automatic 5-minute global Windows Scheduled Task (runs outside Antigravity even if ConPTY hangs):
    powershell -ExecutionPolicy Bypass -File D:\harfile\rfchunt\scripts\install_global_deadlock_watchdog.ps1
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$MinAgeMinutes = 3,
    [switch]$IncludeStaleWorkers,
    [int]$WorkerMinAgeMinutes = 15,
    [switch]$GlobalScan = $true,
    [string]$WorkspaceBaseDir = "D:\harfile",
    [string[]]$RepoRoots = @("D:\harfile\rfchunt", "D:\harfile\ModelFusion", "D:\harfile\rfc", "D:\harfile\OshoosiClaw", "D:\harfile\QuorumRAG"),
    [switch]$Quiet,
    [string]$LogPath = "",
    [switch]$Watch,
    [int]$IntervalSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

function Write-WatchdogLog {
    param(
        [string]$Message,
        [string]$Color = "Gray",
        [switch]$Important
    )
    if (-not $Quiet) {
        Write-Host $Message -ForegroundColor $Color
    }
    if ($LogPath -and ($Important -or -not $Quiet)) {
        try {
            $dir = Split-Path -Parent $LogPath
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }
            if ((Test-Path -LiteralPath $LogPath) -and ((Get-Item -LiteralPath $LogPath).Length -gt 2MB)) {
                $tail = Get-Content -LiteralPath $LogPath -Tail 400 -ErrorAction SilentlyContinue
                Set-Content -LiteralPath $LogPath -Value $tail -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Add-Content -LiteralPath $LogPath -Value ("[{0}] {1}" -f $ts, $Message) -Encoding UTF8 -ErrorAction SilentlyContinue
        } catch {}
    }
}

function Get-ProtectedAncestorPids {
    param([hashtable]$ProcByPid)
    $protected = New-Object 'System.Collections.Generic.HashSet[int]'
    $curr = [int]$PID
    $guard = 0
    while ($curr -gt 0 -and $guard -lt 32) {
        [void]$protected.Add($curr)
        if (-not $ProcByPid.ContainsKey($curr)) { break }
        $parent = [int]$ProcByPid[$curr].ParentProcessId
        if ($parent -eq $curr -or $parent -le 0) { break }
        $curr = $parent
        $guard++
    }
    return $protected
}

function Resolve-GlobalRepoRoots {
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $RepoRoots) {
        if ($r -and (Test-Path -LiteralPath $r)) { [void]$set.Add($r) }
    }
    if ($GlobalScan -and $WorkspaceBaseDir -and (Test-Path -LiteralPath $WorkspaceBaseDir)) {
        if (Test-Path -LiteralPath (Join-Path $WorkspaceBaseDir ".git")) {
            [void]$set.Add($WorkspaceBaseDir)
        }
        $children = Get-ChildItem -LiteralPath $WorkspaceBaseDir -Directory -ErrorAction SilentlyContinue
        foreach ($d in $children) {
            if (Test-Path -LiteralPath (Join-Path $d.FullName ".git")) {
                [void]$set.Add($d.FullName)
            }
        }
    }
    return @($set)
}

function Show-MemoryHealth {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalRamGb = [math]::Round(($os.TotalVisibleMemorySize / 1MB), 2)
    $freeRamGb = [math]::Round(($os.FreePhysicalMemory / 1MB), 2)
    $totalVirtGb = [math]::Round(($os.TotalVirtualMemorySize / 1MB), 2)
    $freeVirtGb = [math]::Round(($os.FreeVirtualMemory / 1MB), 2)
    $usedVirtPct = if ($totalVirtGb -gt 0) { [math]::Round((($totalVirtGb - $freeVirtGb) / $totalVirtGb) * 100, 1) } else { 0.0 }

    Write-WatchdogLog "=== [1/5] Windows Memory & Commit Charge Health ===" -Color Cyan
    Write-WatchdogLog ("  Physical RAM  : {0} GB free / {1} GB total" -f $freeRamGb, $totalRamGb)
    Write-WatchdogLog ("  Virtual Commit: {0} GB free / {1} GB limit ({2}% committed)" -f $freeVirtGb, $totalVirtGb, $usedVirtPct)
    if ($usedVirtPct -ge 88.0 -or $freeVirtGb -lt 4.0) {
        Write-WatchdogLog ("  [WARN] High virtual commit pressure ({0}%, {1} GB free) can freeze Windows ConPTY spawns." -f $usedVirtPct, $freeVirtGb) -Color Yellow -Important
    }
}

function Stop-TargetProcessSafe {
    param(
        [int]$TargetPid,
        [string]$Name,
        [string]$Reason,
        [switch]$DryRunMode
    )
    if ($DryRunMode) {
        Write-WatchdogLog ("  [DRY-RUN] Would stop PID {0} ({1}) - {2}" -f $TargetPid, $Name, $Reason) -Color Yellow -Important
        return $false
    }
    try {
        Stop-Process -Id $TargetPid -Force -ErrorAction Stop
        Write-WatchdogLog ("  [CLEARED] Stopped PID {0} ({1}) - {2}" -f $TargetPid, $Name, $Reason) -Color Green -Important
        return $true
    } catch {
        Write-WatchdogLog ("  [SKIP] Could not stop PID {0} ({1}): {2}" -f $TargetPid, $Name, $_.Exception.Message) -Color DarkYellow
        return $false
    }
}

function Test-ConPtySpawn {
    Write-WatchdogLog "=== [5/5] Live ConPTY / PowerShell Spawn Verification ===" -Color Cyan
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -NonInteractive -Command `"Write-Output CONPTY_OK`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    try {
        [void]$proc.Start()
        $finished = $proc.WaitForExit(6000)
        $sw.Stop()
        if ($finished) {
            $out = ($proc.StandardOutput.ReadToEnd()).Trim()
            if ($out -eq "CONPTY_OK") {
                Write-WatchdogLog ("  [PASS] Fresh PowerShell probe returned CONPTY_OK in {0} ms." -f $sw.ElapsedMilliseconds) -Color Green
                return $true
            }
            Write-WatchdogLog ("  [WARN] PowerShell probe exited ({0}) in {1} ms with '{2}'" -f $proc.ExitCode, $sw.ElapsedMilliseconds, $out) -Color Yellow -Important
            return $false
        } else {
            try { $proc.Kill() } catch {}
            Write-WatchdogLog "  [FAIL] Fresh PowerShell probe timed out (>6s); ConPTY subsystem saturated." -Color Red -Important
            return $false
        }
    } catch {
        Write-WatchdogLog ("  [FAIL] Probe launch error: {0}" -f $_.Exception.Message) -Color Red -Important
        return $false
    } finally {
        $proc.Dispose()
    }
}

function Invoke-DeadlockSweep {
    $now = Get-Date
    Write-WatchdogLog ("Starting Global Windows ConPTY & Shell Deadlock Sweep (DryRun={0})" -f [bool]$DryRun) -Color White

    Show-MemoryHealth

    $allProcs = @(Get-CimInstance Win32_Process)
    $procByPid = @{}
    foreach ($p in $allProcs) {
        $procByPid[[int]$p.ProcessId] = $p
    }
    $protectedPids = Get-ProtectedAncestorPids -ProcByPid $procByPid
    $clearedCount = 0

    # --- [2/5] Orphaned conhost.exe / OpenConsole.exe zombies ---
    Write-WatchdogLog "=== [2/5] Orphaned ConPTY Consoles (conhost.exe / OpenConsole.exe) ===" -Color Cyan
    $consoleProcs = @($allProcs | Where-Object { $_.Name -in @("conhost.exe", "OpenConsole.exe") })
    $orphanConsoles = @()
    foreach ($cp in $consoleProcs) {
        $cpid = [int]$cp.ProcessId
        $ppid = [int]$cp.ParentProcessId
        if ($protectedPids.Contains($cpid)) { continue }
        if (-not $procByPid.ContainsKey($ppid)) {
            $orphanConsoles += $cp
        }
    }
    Write-WatchdogLog ("  Total conhost/OpenConsole: {0} | True orphans (dead parent): {1}" -f $consoleProcs.Count, $orphanConsoles.Count)
    foreach ($oc in $orphanConsoles) {
        if (Stop-TargetProcessSafe -TargetPid ([int]$oc.ProcessId) -Name $oc.Name -Reason ("dead parent PID {0}" -f $oc.ParentProcessId) -DryRunMode:$DryRun) {
            $clearedCount++
        }
    }

    # --- [3/5] Hung non-interactive / agent-spawned shells ---
    Write-WatchdogLog ("=== [3/5] Hung Non-Interactive Shells (age >= {0} min) ===" -f $MinAgeMinutes) -Color Cyan
    $shellNames = @("powershell.exe", "pwsh.exe", "cmd.exe")
    $agentParentHints = @("language_server", "antigravity", "node.exe", "python.exe", "pytest")
    $hungShells = @()
    foreach ($sp in ($allProcs | Where-Object { $_.Name -in $shellNames })) {
        $spid = [int]$sp.ProcessId
        if ($protectedPids.Contains($spid)) { continue }
        $created = $sp.CreationDate
        if (-not $created) { continue }
        $ageMin = ($now - $created).TotalMinutes
        if ($ageMin -lt $MinAgeMinutes) { continue }

        $ppid = [int]$sp.ParentProcessId
        $parentAlive = $procByPid.ContainsKey($ppid)
        $parentName = if ($parentAlive) { [string]$procByPid[$ppid].Name } else { "<dead>" }
        $cmdLine = [string]$sp.CommandLine

        $isOrphanShell = -not $parentAlive
        $isNonInteractiveCmd = ($cmdLine -match "(?i)(-EncodedCommand|-Command|-NonInteractive|/c\s)")
        $isWatchdogSelf = ($cmdLine -match "(?i)clear_conpty_deadlocks\.ps1")
        if ($isWatchdogSelf) { continue }

        $isAgentChild = $false
        foreach ($hint in $agentParentHints) {
            if ($parentName -like "*$hint*") { $isAgentChild = $true; break }
        }

        if ($isOrphanShell -or ($isNonInteractiveCmd -and $isAgentChild)) {
            $hungShells += [PSCustomObject]@{
                Pid    = $spid
                Name   = $sp.Name
                Reason = if ($isOrphanShell) {
                    "orphaned shell (dead parent $ppid, age $([math]::Round($ageMin, 1))m)"
                } else {
                    "hung non-interactive child of $parentName (age $([math]::Round($ageMin, 1))m)"
                }
            }
        }
    }
    Write-WatchdogLog ("  Candidate hung shells found: {0}" -f $hungShells.Count)
    foreach ($hs in $hungShells) {
        if (Stop-TargetProcessSafe -TargetPid $hs.Pid -Name $hs.Name -Reason $hs.Reason -DryRunMode:$DryRun) {
            $clearedCount++
        }
    }

    if ($IncludeStaleWorkers) {
        Write-WatchdogLog ("  [OPT] Checking orphaned git/pytest/cargo workers (age >= {0} min)..." -f $WorkerMinAgeMinutes) -Color Cyan
        $workerProcs = @($allProcs | Where-Object { $_.Name -in @("git.exe", "pytest.exe", "cargo.exe") })
        foreach ($wp in $workerProcs) {
            $wpid = [int]$wp.ProcessId
            if ($protectedPids.Contains($wpid)) { continue }
            $created = $wp.CreationDate
            if (-not $created) { continue }
            $ageMin = ($now - $created).TotalMinutes
            if ($ageMin -lt $WorkerMinAgeMinutes) { continue }
            $ppid = [int]$wp.ParentProcessId
            if (-not $procByPid.ContainsKey($ppid)) {
                if (Stop-TargetProcessSafe -TargetPid $wpid -Name $wp.Name -Reason ("orphaned worker age {0}m" -f [math]::Round($ageMin, 1)) -DryRunMode:$DryRun) {
                    $clearedCount++
                }
            }
        }
    }

    # --- [4/5] Global stale .git/index.lock files across all D:\harfile\* repos ---
    $resolvedRepos = Resolve-GlobalRepoRoots
    Write-WatchdogLog ("=== [4/5] Stale Git Lock Files ({0} repos scanned) ===" -f $resolvedRepos.Count) -Color Cyan
    $liveGit = @($allProcs | Where-Object { $_.Name -eq "git.exe" }).Count
    foreach ($root in $resolvedRepos) {
        $lockPath = Join-Path $root ".git\index.lock"
        if (Test-Path -LiteralPath $lockPath) {
            $info = Get-Item -LiteralPath $lockPath
            $lockAgeMin = [math]::Round(($now - $info.LastWriteTime).TotalMinutes, 1)
            if ($liveGit -gt 0) {
                Write-WatchdogLog ("  [SKIP] {0} exists (age {1}m) while {2} git.exe active." -f $lockPath, $lockAgeMin, $liveGit) -Color Yellow
            } elseif ($lockAgeMin -lt $MinAgeMinutes) {
                Write-WatchdogLog ("  [SKIP] {0} too recent ({1}m < {2}m)." -f $lockPath, $lockAgeMin, $MinAgeMinutes) -Color DarkYellow
            } elseif ($DryRun) {
                Write-WatchdogLog ("  [DRY-RUN] Would remove stale lock: {0} (age {1}m)" -f $lockPath, $lockAgeMin) -Color Yellow -Important
            } else {
                Remove-Item -LiteralPath $lockPath -Force -ErrorAction SilentlyContinue
                Write-WatchdogLog ("  [CLEARED] Removed stale git lock: {0} (age {1}m)" -f $lockPath, $lockAgeMin) -Color Green -Important
                $clearedCount++
            }
        }
    }

    # --- [5/5] Verify fresh shell spawns cleanly ---
    $probeOk = Test-ConPtySpawn
    $summaryLine = "Summary: cleared=$clearedCount item(s) | ConPTY Probe=$(if ($probeOk) { 'PASS' } else { 'NEEDS_RESTART' })"
    Write-WatchdogLog $summaryLine -Color White -Important:($clearedCount -gt 0 -or -not $probeOk)
    if (-not $probeOk) {
        Write-WatchdogLog "  [TIP] If Antigravity's internal run_command still hangs, restart Antigravity to reset its PTY handle pool." -Color Yellow -Important
    }
    return $probeOk
}

if ($Watch) {
    $sleepSec = [math]::Max(30, $IntervalSeconds)
    Write-WatchdogLog ("Watching globally for ConPTY/shell deadlocks every {0}s (Ctrl+C to stop)..." -f $sleepSec) -Color Cyan
    while ($true) {
        [void](Invoke-DeadlockSweep)
        Start-Sleep -Seconds $sleepSec
    }
} else {
    $ok = Invoke-DeadlockSweep
    if (-not $ok) { exit 1 }
    exit 0
}
