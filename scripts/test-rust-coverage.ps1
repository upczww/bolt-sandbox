$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$requiredCargoLlvmCovVersion = '0.9.0'
$minimumLineCoverage = 90.0
$minimumBranchCoverage = 85.0
$minimumRegionCoverage = 80.0
$minimumFunctionCoverage = 80.0
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$reportPath = Join-Path $repositoryRoot 'target\rust-coverage.json'

$installedVersion = (& cargo llvm-cov --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'cargo-llvm-cov is required. Install the pinned version documented in README.md.'
}
if ($installedVersion -notmatch "cargo-llvm-cov $([regex]::Escape($requiredCargoLlvmCovVersion))($|\s)") {
    throw "cargo-llvm-cov $requiredCargoLlvmCovVersion is required; found: $installedVersion"
}

Push-Location $repositoryRoot
try {
    & cargo +nightly llvm-cov `
        --all-targets `
        --all-features `
        --branch `
        --json `
        --output-path $reportPath
    if ($LASTEXITCODE -ne 0) {
        throw 'Instrumented Rust tests or coverage report generation failed.'
    }

    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json -Depth 100
    $totals = $report.data[0].totals
    $measurements = @(
        [pscustomobject]@{ Name = 'lines'; Actual = [double]$totals.lines.percent; Minimum = $minimumLineCoverage }
        [pscustomobject]@{ Name = 'branches'; Actual = [double]$totals.branches.percent; Minimum = $minimumBranchCoverage }
        [pscustomobject]@{ Name = 'regions'; Actual = [double]$totals.regions.percent; Minimum = $minimumRegionCoverage }
        [pscustomobject]@{ Name = 'functions'; Actual = [double]$totals.functions.percent; Minimum = $minimumFunctionCoverage }
    )

    foreach ($measurement in $measurements) {
        Write-Output ("Rust {0} coverage: {1:N2}% (minimum {2:N2}%)" -f `
                $measurement.Name, $measurement.Actual, $measurement.Minimum)
        if ($measurement.Actual -lt $measurement.Minimum) {
            throw ("Rust {0} coverage {1:N2}% is below {2:N2}%" -f `
                    $measurement.Name, $measurement.Actual, $measurement.Minimum)
        }
    }
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $reportPath) {
        Remove-Item -LiteralPath $reportPath -Force
    }
}
