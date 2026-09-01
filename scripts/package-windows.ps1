[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$Version = '0.1.0',
    [string]$OutputRoot = '',
    [switch]$SkipBuildCli,
    [switch]$RequireSigned
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repositoryRoot 'target\packages'
}
$outputAbsolute = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $outputAbsolute | Out-Null
$packageName = "bolt-sandbox-$Version-windows-x64"
$finalPath = Join-Path $outputAbsolute $packageName
if (Test-Path -LiteralPath $finalPath) {
    throw "Package already exists: $finalPath"
}
$stagingName = ".staging-$packageName-$([Guid]::NewGuid().ToString('N'))"
$stagingPath = Join-Path $outputAbsolute $stagingName
$stagingAbsolute = [IO.Path]::GetFullPath($stagingPath)
$expectedPrefix = $outputAbsolute.TrimEnd('\') + '\'
if (-not $stagingAbsolute.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($stagingAbsolute)).StartsWith('.staging-')) {
    throw 'Resolved staging path escaped the package output root.'
}

try {
    New-Item -ItemType Directory -Path $stagingAbsolute | Out-Null
    if (-not $SkipBuildCli) {
        & cargo build --release --bin bolt-sandbox
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }

    $sources = [ordered]@{
        'bolt-sandbox.exe' = Join-Path $repositoryRoot 'target\release\bolt-sandbox.exe'
        'bolt-sandbox-launcher.exe' = Join-Path $repositoryRoot "target\native\x64\$Configuration\bolt-sandbox-launcher.exe"
        'bolt-sandbox-launcher-x86.exe' = Join-Path $repositoryRoot "target\native\x86\$Configuration\bolt-sandbox-launcher-x86.exe"
        'bolt-sandbox-x64.dll' = Join-Path $repositoryRoot "target\native\x64\$Configuration\bolt-sandbox-x64.dll"
        'bolt-sandbox-x86.dll' = Join-Path $repositoryRoot "target\native\x86\$Configuration\bolt-sandbox-x86.dll"
    }
    foreach ($entry in $sources.GetEnumerator()) {
        if (-not (Test-Path -LiteralPath $entry.Value -PathType Leaf)) {
            throw "Required component is missing: $($entry.Value)"
        }
        Copy-Item -LiteralPath $entry.Value -Destination (Join-Path $stagingAbsolute $entry.Key)
    }
    & (Join-Path $PSScriptRoot 'verify-component-signatures.ps1') `
        -ComponentRoot $stagingAbsolute -RequireSigned:$RequireSigned
    & (Join-Path $PSScriptRoot 'write-component-manifest.ps1') `
        -ComponentRoot $stagingAbsolute
    & (Join-Path $PSScriptRoot 'set-package-acl.ps1') `
        -PackageRoot $stagingAbsolute
    & (Join-Path $PSScriptRoot 'verify-package-acl.ps1') `
        -PackageRoot $stagingAbsolute
    Move-Item -LiteralPath $stagingAbsolute -Destination $finalPath
    Write-Output "Windows package created: $finalPath"
} finally {
    if (Test-Path -LiteralPath $stagingAbsolute) {
        Remove-Item -LiteralPath $stagingAbsolute -Recurse -Force
    }
}
