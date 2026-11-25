# RFCHunt 6-Hour Automated Freshness + Exhaustive --all --ensemble (--essemble) + --proxy Hunt
# Zero Registry/PATH mutation; all outputs saved strictly under gitignored reports/ensemble_hunt/.
param(
    [string]$ProxyUrl = "",
    [switch]$IncludeFullSwarmAll = $true
)
$ErrorActionPreference = "Continue"

$RepoRoot = "D:\harfile\rfchunt"
$PythonExe = "C:\Python314\python.exe"
$OutRoot = Join-Path $RepoRoot "reports\ensemble_hunt"
$LogFile = Join-Path $OutRoot "scheduled_hunt.log"

New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content -Path $LogFile -Value "[$ts] Starting 6-hour Freshness + Exhaustive --all --ensemble Hunt..." -Encoding UTF8

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
        @{ dir = "reports\ensemble_hunt\repos\anthropics__claude-code-action"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-code-action" },
        @{ dir = "reports\ensemble_hunt\repos\anthropics__claude-agent-sdk-python"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-agent-sdk-python" },
        @{ dir = "reports\ensemble_hunt\repos\anthropics__claude-agent-sdk-typescript"; prog = "anthropic"; out = "reports\ensemble_hunt\anthropic_core\anthropics__claude-agent-sdk-typescript" },
        @{ dir = "reports\ensemble_hunt\repos\vercel__ai"; prog = "vercel"; out = "reports\ensemble_hunt\vercel__ai" }
    )
    foreach ($item in $localRepos) {
        $fullDir = Join-Path $RepoRoot $item.dir
        $outDir = Join-Path $RepoRoot $item.out
        if (Test-Path $fullDir) {
            & git -C $fullDir pull --ff-only *>> $LogFile
            if ($IncludeFullSwarmAll) {
                $swarmArgs = @("rfc_hunt_swarm.py", "--all", $fullDir, "--output-dir", $outDir)
                if ($ProxyUrl) {
                    $swarmArgs += @("--proxy", $ProxyUrl)
                }
                & $PythonExe @swarmArgs *>> $LogFile
            }
            $ensArgs = @(
                "revenue_cli.py", "ensemble-audit",
                "--target", $fullDir,
                "--program", $item.prog,
                "--freshness-hours", "72",
                "--out", $outDir
            )
            if ($ProxyUrl) {
                $ensArgs += @("--proxy", $ProxyUrl)
            }
            & $PythonExe @ensArgs *>> $LogFile
        }
    }
} finally {
    Pop-Location
}

$tsEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Add-Content -Path $LogFile -Value "[$tsEnd] 6-hour Freshness + Exhaustive --all --ensemble Hunt complete." -Encoding UTF8
