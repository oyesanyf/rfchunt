param(
    [string]$Title = "chore: verified RFCHunt update",
    [string]$Body = "Verified RFCHunt Solo-Developer Pull Request checked by CI, Lean 4 formal proofs, and RFCHunt Invariant Gate.",
    [string]$BaseBranch = "main",
    [switch]$WaitForChecks = $true,
    [switch]$MergeWhenReady = $true
)
$ErrorActionPreference = "Stop"

# 1. Fail-Closed Repository Boundary Verification (repository_boundaries.md)
$repoRoot = (& git rev-parse --show-toplevel).Trim().Replace("\", "/")
$originUrl = (& git remote get-url origin).Trim()
if (-not $repoRoot.ToLower().EndsWith("/rfchunt")) {
    throw "Repository boundary mismatch: expected rfchunt root, got '$repoRoot'."
}
if ($originUrl.ToLower() -notmatch "oyesanyf/rfchunt(\.git)?$") {
    throw "Origin boundary mismatch: expected oyesanyf/rfchunt, got '$originUrl'."
}

$repoSlug = "oyesanyf/rfchunt"
$currentBranch = (& git branch --show-current).Trim()
Write-Host "[1/5] Repo verified ($repoSlug @ $currentBranch)" -ForegroundColor Cyan

# 2. Prepare branch & commit any tracked/staged updates safely (never touch untracked temp files automatically)
& git fetch origin $BaseBranch --quiet
$statusLines = (& git status --porcelain)

if ($currentBranch -eq $BaseBranch) {
    $branchName = "pr/solo-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    $headSha = (& git rev-parse HEAD).Trim()
    $originBaseSha = (& git rev-parse "origin/$BaseBranch").Trim()
    if ($statusLines) {
        Write-Host "[2/5] Creating solo branch $branchName for working tree changes..." -ForegroundColor Yellow
        & git checkout -b $branchName
        & git add -u
        $msgFile = Join-Path ([System.IO.Path]::GetTempPath()) ("rfchunt_solo_msg_" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + ".txt")
        [System.IO.File]::WriteAllText($msgFile, $Title, [System.Text.UTF8Encoding]::new($false))
        try { & git commit -F $msgFile } finally { Remove-Item -Force -ErrorAction SilentlyContinue $msgFile }
    } elseif ($headSha -ne $originBaseSha) {
        Write-Host "[2/5] Moving local commits onto $branchName..." -ForegroundColor Yellow
        & git branch $branchName HEAD
        & git reset --hard "origin/$BaseBranch"
        & git checkout $branchName
    } else {
        throw "No uncommitted changes or commits ahead of origin/$BaseBranch to ship."
    }
    $currentBranch = $branchName
} elseif ($statusLines) {
    Write-Host "[2/5] Committing tracked changes on existing feature branch $currentBranch..." -ForegroundColor Yellow
    & git add -u
    $staged = (& git diff --cached --name-only)
    if ($staged) {
        $msgFile = Join-Path ([System.IO.Path]::GetTempPath()) ("rfchunt_solo_msg_" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + ".txt")
        [System.IO.File]::WriteAllText($msgFile, $Title, [System.Text.UTF8Encoding]::new($false))
        try { & git commit -F $msgFile } finally { Remove-Item -Force -ErrorAction SilentlyContinue $msgFile }
    }
}

Write-Host "[3/5] Pushing $currentBranch to origin..." -ForegroundColor Cyan
& git push -u origin $currentBranch

# 3. Find existing PR for $currentBranch or open a new PR using UTF-8 --body-file
$existingPr = (& gh pr list --repo $repoSlug --head $currentBranch --state open --json number --jq ".[0].number").Trim()
if ($existingPr) {
    $prNumber = $existingPr
    Write-Host "[4/5] Using existing open PR #$prNumber for $currentBranch." -ForegroundColor Cyan
} else {
    $bodyFile = Join-Path ([System.IO.Path]::GetTempPath()) ("rfchunt_solo_pr_" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + ".md")
    [System.IO.File]::WriteAllText($bodyFile, $Body, [System.Text.UTF8Encoding]::new($false))
    try {
        $prUrl = (& gh pr create --repo $repoSlug --base $BaseBranch --head $currentBranch --title $Title --body-file $bodyFile).Trim()
    } finally {
        Remove-Item -Force -ErrorAction SilentlyContinue $bodyFile
    }
    $prNumber = (& gh pr list --repo $repoSlug --head $currentBranch --state open --json number --jq ".[0].number").Trim()
    Write-Host "[4/5] Opened PR #$prNumber ($prUrl)." -ForegroundColor Green
}

if ($WaitForChecks) {
    Write-Host "[5/5] Watching GitHub Actions checks on PR #$prNumber..." -ForegroundColor Cyan
    & gh pr checks $prNumber --repo $repoSlug --watch
}

if ($MergeWhenReady) {
    $prStateJson = (& gh pr view $prNumber --repo $repoSlug --json reviewDecision,mergeStateStatus,url) | ConvertFrom-Json
    if ($prStateJson.reviewDecision -eq "APPROVED" -and $prStateJson.mergeStateStatus -eq "CLEAN") {
        & gh pr merge $prNumber --repo $repoSlug --squash --delete-branch
        Write-Host "Successfully squash-merged PR #$prNumber into $BaseBranch!" -ForegroundColor Green
    } else {
        Write-Host "PR #$prNumber checks are complete, awaiting review/merge clearance (reviewDecision=$($prStateJson.reviewDecision), mergeStateStatus=$($prStateJson.mergeStateStatus)): $($prStateJson.url)" -ForegroundColor Yellow
    }
}
