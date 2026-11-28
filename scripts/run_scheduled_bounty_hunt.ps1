# RFCHunt 6-Hour Automated Freshness + Bounded-Concurrent Exhaustive --all --ensemble --proxy Hunt
# Zero Registry/PATH mutation; all outputs saved strictly under gitignored reports/ensemble_hunt/.
param(
    [string]$ProxyUrl = "auto",
    [switch]$IncludeFullSwarmAll = $true,
    [int]$MaxConcurrentRepos = 2
)
$ErrorActionPreference = "Continue"

# Enforce strict concurrency ceiling (1..3) to prevent Windows paging-file / commit-memory violations
$BoundedConcurrency = [Math]::Max(1, [Math]::Min(3, $MaxConcurrentRepos))

$RepoRoot = "D:\harfile\rfchunt"
$PythonExe = "C:\Python314\python.exe"
$OutRoot = Join-Path $RepoRoot "reports\ensemble_hunt"
$LogFile = Join-Path $OutRoot "scheduled_hunt.log"

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content -Path $LogFile -Value "[$ts] Starting 6-hour Freshness + Bounded-Concurrent (max=$BoundedConcurrency) --all --ensemble --proxy Hunt..." -Encoding UTF8

Push-Location $RepoRoot
try {
    & $PythonExe "revenue_cli.py" "freshness-watch" `
        "--watchlist" "config/freshness_watchlist.example.json" `
        "--repo" "anthropics/claude-code-action" `
        "--repo" "anthropics/claude-agent-sdk-python" `
        "--repo" "anthropics/claude-agent-sdk-typescript" `
        "--repo" "vercel/ai" `
        "--hours" "72" `
        "--min-score" "20" `
        "--out" "reports/ensemble_hunt/fresh_hunt_queue" *>> $LogFile

    $localRepos = @(
        @{ slug = "anthropics__claude-code-action"; dir = "reports\ensemble_hunt\repos\anthropics__claude-code-action"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-code-action" },
        @{ slug = "anthropics__claude-agent-sdk-python"; dir = "reports\ensemble_hunt\repos\anthropics__claude-agent-sdk-python"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-agent-sdk-python" },
        @{ slug = "anthropics__claude-agent-sdk-typescript"; dir = "reports\ensemble_hunt\repos\anthropics__claude-agent-sdk-typescript"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-agent-sdk-typescript" },
        @{ slug = "vercel__ai"; dir = "reports\ensemble_hunt\repos\vercel__ai"; prog = "vercel"; out = "reports\ensemble_hunt\vercel__ai" }
    )

    $activeJobs = @()
    $jobLogs = @()

    foreach ($item in $localRepos) {
        $fullDir = Join-Path $RepoRoot $item.dir
        $outDir = Join-Path $RepoRoot $item.out
        if (-not (Test-Path $fullDir)) {
            continue
        }

        # Throttle active jobs strictly at $BoundedConcurrency to avoid memory/handle violations
        while (($activeJobs | Where-Object { $_.State -eq "Running" }).Count -ge $BoundedConcurrency) {
            Start-Sleep -Milliseconds 500
        }

        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        $repoLog = Join-Path $outDir "hunt_worker.log"
        $jobLogs += $repoLog

        $job = Start-Job -ArgumentList $RepoRoot, $PythonExe, $fullDir, $outDir, $item.prog, $ProxyUrl, [bool]$IncludeFullSwarmAll, $repoLog -ScriptBlock {
            param($rRoot, $pyExe, $fDir, $oDir, $prog, $pUrl, $incSwarm, $rLog)
            Set-Location $rRoot
            & git -C $fDir pull --ff-only *>> $rLog
            if ($incSwarm) {
                $swarmArgs = @("rfc_hunt_swarm.py", "--all", $fDir, "--output-dir", $oDir)
                if ($pUrl) {
                    $swarmArgs += @("--proxy", $pUrl)
                }
                & $pyExe @swarmArgs *>> $rLog
            }
            $ensArgs = @(
                "revenue_cli.py", "ensemble-audit",
                "--target", $fDir,
                "--program", $prog,
                "--freshness-hours", "72",
                "--all",
                "--ensemble",
                "--proxy", $pUrl,
                "--out", $oDir
            )
            & $pyExe @ensArgs *>> $rLog
        }
        $activeJobs += $job
    }

    if ($activeJobs.Count -gt 0) {
        Wait-Job -Job $activeJobs | Out-Null
        Remove-Job -Job $activeJobs -Force | Out-Null
    }

    # Deterministic single-writer log merge (zero concurrent file-append race)
    foreach ($rLog in $jobLogs) {
        if (Test-Path $rLog) {
            Add-Content -Path $LogFile -Value "=== Worker Log: $rLog ===" -Encoding UTF8
            Get-Content -Path $rLog -Encoding UTF8 | Add-Content -Path $LogFile -Encoding UTF8
        }
    }
} finally {
    Pop-Location
}

$tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content -Path $LogFile -Value "[$tsEnd] 6-hour Freshness + Bounded-Concurrent --all --ensemble --proxy Hunt complete." -Encoding UTF8
