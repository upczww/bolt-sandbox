[CmdletBinding()]
param(
    [switch]$RequireComplete
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$catalogPath = Join-Path $repositoryRoot 'docs\testing\test-catalog.md'
$evidencePath = Join-Path $repositoryRoot 'docs\testing\filesystem-evidence.json'

if (-not (Test-Path -LiteralPath $evidencePath)) {
    throw "Filesystem executable evidence inventory is missing: $evidencePath"
}

$catalog = Get-Content -Raw -LiteralPath $catalogPath
$expectedIds = @(
    [regex]::Matches($catalog, '(?m)^\|\s*(FS-\d{3})\s*\|') |
        ForEach-Object { $_.Groups[1].Value }
)
$inventory = Get-Content -Raw -LiteralPath $evidencePath | ConvertFrom-Json
if ($inventory.schema_version -ne 1) {
    throw 'Filesystem evidence inventory has an unsupported schema.'
}
$entries = @($inventory.cases)
$actualIds = @($entries | ForEach-Object { [string]$_.id })
$idDifference = @(Compare-Object $expectedIds $actualIds)
if ($idDifference.Count -ne 0 -or
    ($actualIds | Sort-Object -Unique).Count -ne $actualIds.Count) {
    throw 'Filesystem evidence inventory must contain every FS-001..064 ID exactly once.'
}

$allowedStatuses = @('covered', 'partial', 'gap')
foreach ($entry in $entries) {
    if ($entry.status -notin $allowedStatuses) {
        throw "Filesystem case $($entry.id) has invalid status '$($entry.status)'."
    }
    if ($entry.status -eq 'gap') {
        if ([string]::IsNullOrWhiteSpace([string]$entry.reason)) {
            throw "Filesystem gap $($entry.id) requires a reason."
        }
        continue
    }
    $evidenceItems = @($entry.evidence)
    if ($evidenceItems.Count -eq 0) {
        throw "Filesystem case $($entry.id) requires executable evidence."
    }
    foreach ($item in $evidenceItems) {
        $relativePath = [string]$item.file
        $anchor = [string]$item.anchor
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            [string]::IsNullOrWhiteSpace($anchor)) {
            throw "Filesystem case $($entry.id) has incomplete evidence metadata."
        }
        $absolutePath = Join-Path $repositoryRoot $relativePath
        if (-not (Test-Path -LiteralPath $absolutePath)) {
            throw "Filesystem case $($entry.id) cites missing file '$relativePath'."
        }
        if ((Get-Content -Raw -LiteralPath $absolutePath).IndexOf($anchor) -lt 0) {
            throw "Filesystem case $($entry.id) anchor '$anchor' is missing from '$relativePath'."
        }
    }
    if ($entry.status -eq 'partial' -and
        [string]::IsNullOrWhiteSpace([string]$entry.reason)) {
        throw "Partial filesystem case $($entry.id) requires a remaining-gap reason."
    }
}

$covered = @($entries | Where-Object { $_.status -eq 'covered' })
$partial = @($entries | Where-Object { $_.status -eq 'partial' })
$gaps = @($entries | Where-Object { $_.status -eq 'gap' })
Write-Output 'Filesystem executable evidence audit passed.'
Write-Output "Covered: $($covered.Count)"
Write-Output "Partial: $($partial.Count)"
Write-Output "Gaps: $($gaps.Count)"
if ($partial.Count -ne 0) {
    Write-Output "Partial IDs: $(($partial.id) -join ', ')"
}
if ($gaps.Count -ne 0) {
    Write-Output "Gap IDs: $(($gaps.id) -join ', ')"
}
if ($RequireComplete -and ($partial.Count -ne 0 -or $gaps.Count -ne 0)) {
    throw 'Filesystem release evidence is incomplete.'
}
