[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$detoursRoot = Join-Path $repositoryRoot 'native\third_party\detours'
$provenancePath = Join-Path $detoursRoot 'provenance.json'
$noticePath = Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md'
$expectedRevision = 'e4bfd6b03e50de46b47abfbd1e46b384f0c5f833'
$expectedUpstream = 'https://github.com/microsoft/Detours'

if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
    throw 'Detours provenance manifest is missing.'
}

$provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
if ($provenance.upstream -ne $expectedUpstream) {
    throw 'Detours provenance does not identify the official Microsoft upstream.'
}
if ($provenance.revision -ne $expectedRevision) {
    throw 'Detours revision is not pinned to the audited v4.0.1 commit.'
}
if ($provenance.tag -ne 'v4.0.1' -or $provenance.license -ne 'MIT') {
    throw 'Detours tag or license metadata is invalid.'
}

$importedFiles = @($provenance.imported_files)
if ($importedFiles.Count -eq 0) {
    throw 'Detours imported source list is empty.'
}

$listedPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($entry in $importedFiles) {
    $relativePath = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($relativePath) -or
        [System.IO.Path]::IsPathRooted($relativePath) -or
        $relativePath.Contains('..')) {
        throw "Unsafe Detours manifest path: $relativePath"
    }
    if (-not $listedPaths.Add($relativePath)) {
        throw "Duplicate Detours manifest path: $relativePath"
    }

    $importedPath = Join-Path $detoursRoot $relativePath
    if (-not (Test-Path -LiteralPath $importedPath -PathType Leaf)) {
        throw "Missing Detours source: $relativePath"
    }
    $actualHash = (Get-FileHash -LiteralPath $importedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne [string]$entry.sha256) {
        throw "Detours source hash mismatch: $relativePath"
    }
}

$unlistedFiles = Get-ChildItem -LiteralPath $detoursRoot -File -Recurse |
    ForEach-Object {
        [System.IO.Path]::GetRelativePath($detoursRoot, $_.FullName).Replace('\', '/')
    } |
    Where-Object { $_ -ne 'provenance.json' -and -not $listedPaths.Contains($_) }
if ($unlistedFiles) {
    throw "Unlisted Detours files: $($unlistedFiles -join ', ')"
}

$notice = Get-Content -LiteralPath $noticePath -Raw
if (-not $notice.Contains($expectedRevision) -or
    -not $notice.Contains('native/third_party/detours/provenance.json')) {
    throw 'THIRD_PARTY_NOTICES.md does not record the Detours revision and import boundary.'
}

Write-Host "Detours provenance verified at $expectedRevision."

$buildXlRoot = Join-Path $repositoryRoot 'native\third_party\buildxl'
$buildXlProvenancePath = Join-Path $buildXlRoot 'provenance.json'
$expectedBuildXlRevision = '24a3f64655741d9ab8619d35d12513e6a7baabc1'
$expectedBuildXlUpstream = 'https://github.com/microsoft/BuildXL'

if (-not (Test-Path -LiteralPath $buildXlProvenancePath -PathType Leaf)) {
    throw 'BuildXL provenance manifest is missing.'
}

$buildXlProvenance = Get-Content -LiteralPath $buildXlProvenancePath -Raw | ConvertFrom-Json
if ($buildXlProvenance.upstream -ne $expectedBuildXlUpstream -or
    $buildXlProvenance.revision -ne $expectedBuildXlRevision -or
    $buildXlProvenance.license -ne 'MIT') {
    throw 'BuildXL provenance does not match the audited official revision.'
}

$buildXlFiles = @($buildXlProvenance.imported_files)
if ($buildXlFiles.Count -eq 0) {
    throw 'BuildXL imported source list is empty.'
}

$buildXlListedPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
foreach ($entry in $buildXlFiles) {
    $relativePath = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($relativePath) -or
        [System.IO.Path]::IsPathRooted($relativePath) -or
        $relativePath.Contains('..')) {
        throw "Unsafe BuildXL manifest path: $relativePath"
    }
    if (-not $buildXlListedPaths.Add($relativePath)) {
        throw "Duplicate BuildXL manifest path: $relativePath"
    }

    $importedPath = Join-Path $buildXlRoot $relativePath
    if (-not (Test-Path -LiteralPath $importedPath -PathType Leaf)) {
        throw "Missing BuildXL source: $relativePath"
    }
    $actualHash = (Get-FileHash -LiteralPath $importedPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne [string]$entry.sha256) {
        throw "BuildXL source hash mismatch: $relativePath"
    }
}

$buildXlUnlistedFiles = Get-ChildItem -LiteralPath $buildXlRoot -File -Recurse |
    ForEach-Object {
        [System.IO.Path]::GetRelativePath($buildXlRoot, $_.FullName).Replace('\', '/')
    } |
    Where-Object { $_ -ne 'provenance.json' -and -not $buildXlListedPaths.Contains($_) }
if ($buildXlUnlistedFiles) {
    throw "Unlisted BuildXL files: $($buildXlUnlistedFiles -join ', ')"
}

if (-not $notice.Contains($expectedBuildXlRevision) -or
    -not $notice.Contains('native/third_party/buildxl/provenance.json')) {
    throw 'THIRD_PARTY_NOTICES.md does not record the BuildXL revision and import boundary.'
}

Write-Host "BuildXL provenance verified at $expectedBuildXlRevision."
