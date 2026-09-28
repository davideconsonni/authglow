#!/usr/bin/env pwsh
# Launch the AuthGlow checktool.
# On first run it creates a local virtual environment (.venv) and installs the
# tool in editable mode, so later runs are instant and reflect code changes.
# It re-installs automatically when pyproject.toml (dependencies) changes.
#
# Usage:
#   .\run.ps1                 # interactive: pick groups
#   .\run.ps1 --all           # run every group
#   .\run.ps1 --groups auth,rbac
#   .\run.ps1 --base-url https://my-instance --all
#   .\run.ps1 --help

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = Join-Path $here ".venv"
$stamp = Join-Path $venv ".checktool-installed"
$pyproject = Join-Path $here "pyproject.toml"

if ($env:OS -eq "Windows_NT") {
    $py = Join-Path $venv "Scripts\python.exe"
} else {
    $py = Join-Path $venv "bin/python"
}

if (-not (Test-Path $py)) {
    $base = $null
    foreach ($candidate in @("python", "python3")) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) { $base = $found.Source; break }
    }
    if (-not $base) {
        $launcher = Get-Command py -ErrorAction SilentlyContinue
        if ($launcher) { $base = $launcher.Source }
    }
    if (-not $base) {
        Write-Error "Python 3.11+ was not found on PATH. Install Python and retry."
        exit 1
    }
    Write-Host "Creating virtual environment at $venv ..."
    if ((Split-Path $base -Leaf) -eq "py.exe") {
        & $base -3 -m venv $venv
    } else {
        & $base -m venv $venv
    }
}

$needsInstall = -not (Test-Path $stamp)
if (-not $needsInstall -and (Test-Path $pyproject)) {
    if ((Get-Item $pyproject).LastWriteTime -gt (Get-Item $stamp).LastWriteTime) {
        $needsInstall = $true
    }
}
if ($needsInstall) {
    Write-Host "Installing checktool dependencies ..."
    & $py -m pip install --quiet --disable-pip-version-check -e $here
    New-Item -ItemType File -Force -Path $stamp | Out-Null
}

& $py -m checktool @args
exit $LASTEXITCODE
