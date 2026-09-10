#Requires -Version 7
<#
.SYNOPSIS
    Run OWASP ZAP scans against the local AuthGlow dev stack.

.DESCRIPTION
    Modes:
      baseline  Spider + passive scan only. Non-invasive, safe anytime.
      full      Unauthenticated active scan of SPA + API. INVASIVE.
      auth      Authenticated active scan (browser login as the demo admin). INVASIVE.
      all       baseline, then full, then auth.

    Runs ZAP natively (zap.bat) by default, or in Docker with -Docker.
    For invasive modes the backend `data/` directory is backed up first.

.PARAMETER Mode
    baseline | full | auth | all. Default: baseline.

.PARAMETER Docker
    Run ZAP from the official zaproxy/zap-stable image instead of zap.bat.
    Targets are reached via host.docker.internal (Vite must listen on 0.0.0.0).

.PARAMETER ZapImage
    Docker image to use. Default: zaproxy/zap-stable:2.17.0

.PARAMETER ZapPath
    Path to zap.bat (or its install directory). Native mode only.

.PARAMETER Frontend
    Frontend base URL. Default: http://localhost:5173 (Docker:
    http://host.docker.internal:5173).

.PARAMETER Api
    API base URL. Default: http://localhost:8001 (Docker:
    http://host.docker.internal:8001).

.PARAMETER Yes
    Skip the confirmation prompt for invasive modes.

.EXAMPLE
    pwsh -File security/zap/run-zap.ps1 -Mode baseline -Docker
    pwsh -File security/zap/run-zap.ps1 -Mode auth -Docker -Yes
#>
[CmdletBinding()]
 param(
    [ValidateSet('baseline', 'full', 'auth', 'all')]
    [string]$Mode = 'baseline',
    [switch]$Docker,
    [string]$ZapImage = 'zaproxy/zap-stable:2.17.0',
    [string]$ZapPath,
    [string]$Frontend,
    [string]$Api,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

$RepoRoot   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$PlanDir    = $PSScriptRoot
$BackendDir = Join-Path $RepoRoot 'backend'
$DataDir    = Join-Path $BackendDir 'data'
$ReportsDir = Join-Path $RepoRoot 'security\reports'
$BackupsDir = Join-Path $RepoRoot 'security\backups'
$MetaApi    = 'http://localhost:8001'

# In Docker the container must reach services on the host, not its own loopback.
$DefaultFrontend = if ($Docker) { 'http://host.docker.internal:5173' } else { 'http://localhost:5173' }
$DefaultApi      = if ($Docker) { 'http://host.docker.internal:8001' } else { 'http://localhost:8001' }
if (-not $Frontend) { $Frontend = $DefaultFrontend }
if (-not $Api)      { $Api = $DefaultApi }

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "!!  $msg" -ForegroundColor Yellow }

# ----------------------------------------------------------------------
# Locate native ZAP (skipped in Docker mode)
# ----------------------------------------------------------------------
function Resolve-ZapBat {
    param([string]$Explicit)
    $candidates = @()
    if ($Explicit) {
        if (Test-Path -LiteralPath $Explicit -PathType Leaf) { return (Resolve-Path $Explicit).Path }
        $candidates += (Join-Path $Explicit 'zap.bat')
    }
    if ($env:ZAP_HOME) { $candidates += (Join-Path $env:ZAP_HOME 'zap.bat') }
    $candidates += @(
        (Join-Path $PlanDir 'zap\zap.bat'),
        'C:\Program Files\ZAP\Zed Attack Proxy\zap.bat',
        'C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat',
        (Join-Path $env:LOCALAPPDATA 'Programs\ZAP\zap.bat')
    )
    foreach ($c in $candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path $c).Path }
    }
    $cmd = Get-Command zap.bat -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Ensure-Java {
    if (Get-Command java -ErrorAction SilentlyContinue) { return }
    foreach ($base in @('C:\Program Files\Eclipse Adoptium', 'C:\Program Files (x86)\Eclipse Adoptium')) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $jre = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'jre-*' -or $_.Name -like 'jdk-*' } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($jre) {
            $env:JAVA_HOME = $jre.FullName
            $env:Path = (Join-Path $jre.FullName 'bin') + ';' + $env:Path
            Write-Step "Using Java from $($jre.FullName)"
            return
        }
    }
    Write-Warn 'No Java found. Portable ZAP needs JAVA_HOME; the Windows installer bundles its own JRE.'
}

# ----------------------------------------------------------------------
# Health checks (run from the host, so localhost is correct here)
# ----------------------------------------------------------------------
function Assert-Targets {
    foreach ($u in @("$MetaApi/health", "$MetaApi/openapi.json")) {
        try {
            $r = Invoke-WebRequest -Uri $u -UseBasicParsing -TimeoutSec 10
            Write-Step "OK $u -> $($r.StatusCode)"
        } catch {
            throw "Target not reachable: $u ($($_.Exception.Message))"
        }
    }
    try {
        $null = Invoke-WebRequest -Uri "$MetaApi/api/meta" -UseBasicParsing -TimeoutSec 10
    } catch {
        Write-Warn "GET /api/meta failed ($($_.Exception.Message)); `auth` mode will fail."
    }
}

function Get-DemoPassword {
    $meta = Invoke-RestMethod -Uri "$MetaApi/api/meta" -TimeoutSec 10
    if (-not $meta.demo_mode) { throw 'DEMO_MODE is not enabled; fill credentials in zap-auth.yaml manually.' }
    if (-not $meta.demo_user_password) { throw 'GET /api/meta did not return demo_user_password.' }
    Write-Step "Demo user: $($meta.demo_user_email)"
    return $meta.demo_user_password
}

# ----------------------------------------------------------------------
# Backup / confirmation
# ----------------------------------------------------------------------
function Backup-Data {
    if (-not (Test-Path -LiteralPath $DataDir)) { Write-Warn "No data dir at $DataDir; skipping backup."; return }
    New-Item -ItemType Directory -Force -Path $BackupsDir | Out-Null
    $dest = Join-Path $BackupsDir ("data-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -LiteralPath $DataDir -Destination $dest -Recurse -Force
    Write-Step "Backed up backend/data -> $dest"
}

function Confirm-Invasive {
    param([string]$what)
    if ($Yes) { return }
    Write-Warn "$what is INVASIVE and can create/modify/delete data in the running instance."
    $answer = Read-Host "Type 'yes' to continue"
    if ($answer -ne 'yes') { throw 'Aborted by user.' }
}

# ----------------------------------------------------------------------
# Run a single plan
# ----------------------------------------------------------------------
function Invoke-Plan {
    param(
        [string]$Template,
        [string]$Tag,
        [string]$Password
    )
    $stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
    $reportDir = Join-Path $ReportsDir "$stamp-$Tag"
    New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

    $reportPlaceholder = if ($Docker) { '/zap/reports' } else { $reportDir.Replace('\', '/') }

    $planText = Get-Content -LiteralPath (Join-Path $PlanDir $Template) -Raw
    $planText = $planText.Replace('__REPORT_DIR__', $reportPlaceholder)
    $planText = $planText.Replace('__FRONTEND__', $Frontend)
    $planText = $planText.Replace('__API__', $Api)
    if ($Password) { $planText = $planText.Replace('__DEMO_PASSWORD__', $Password) }

    $tmpPlan = Join-Path $env:TEMP "authglow-zap-$Tag.yaml"
    Set-Content -LiteralPath $tmpPlan -Value $planText -Encoding utf8

    try {
        Write-Step "Running $Template -> $reportDir"
        Write-Step "  frontend=$Frontend  api=$Api"
        if ($Docker) {
            $dockerArgs = @(
                'run', '--rm',
                '-v', "${tmpPlan}:/zap/plan.yaml:ro",
                '-v', "${reportDir}:/zap/reports",
                $ZapImage, 'zap.sh', '-cmd', '-autorun', '/zap/plan.yaml'
            )
            & docker @dockerArgs
        } else {
            & $script:ZapBat -cmd -autorun $tmpPlan
        }
        $code = $LASTEXITCODE
        Write-Step "ZAP exit code: $code"
        if ($code -ne 0) { Write-Warn "ZAP reported a non-zero exit code ($code) — inspect $reportDir" }
    } finally {
        Remove-Item -LiteralPath $tmpPlan -Force -ErrorAction SilentlyContinue
    }
    return $reportDir
}

# ======================================================================
# Main
# ======================================================================
if ($Docker) {
    docker info *> $null
    if ($LASTEXITCODE -ne 0) { throw 'Docker daemon is not reachable. Start Docker Desktop first.' }
    docker image inspect $ZapImage *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Step "Image $ZapImage not found locally; pulling..."
        docker pull $ZapImage
    }
} else {
    $ZapBat = Resolve-ZapBat -Explicit $ZapPath
    if (-not $ZapBat) {
        throw 'zap.bat not found. Install OWASP ZAP or pass -ZapPath, or use -Docker.'
    }
    $script:ZapBat = $ZapBat
    Write-Step "ZAP: $ZapBat"
    Ensure-Java
}

Assert-Targets
New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null

$modes = if ($Mode -eq 'all') { @('baseline', 'full', 'auth') } else { @($Mode) }

$outDirs = @()
foreach ($m in $modes) {
    switch ($m) {
        'baseline' {
            $outDirs += Invoke-Plan -Template 'zap-baseline.yaml' -Tag 'baseline'
        }
        'full' {
            Confirm-Invasive 'The full active scan'
            Backup-Data
            $outDirs += Invoke-Plan -Template 'zap-full.yaml' -Tag 'full'
        }
        'auth' {
            Confirm-Invasive 'The authenticated active scan'
            $pw = Get-DemoPassword
            Backup-Data
            $outDirs += Invoke-Plan -Template 'zap-auth.yaml' -Tag 'auth' -Password $pw
        }
    }
}

Write-Host ''
Write-Step 'Reports:'
$outDirs | ForEach-Object { Write-Host "  $_" }
