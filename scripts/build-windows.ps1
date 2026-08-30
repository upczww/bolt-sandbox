[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [ValidateSet('x64', 'x86', 'All')]
    [string]$Architecture = 'All'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'verify-hook-manifest.ps1')
& (Join-Path $PSScriptRoot 'audit-filesystem-evidence.ps1')
& (Join-Path $PSScriptRoot 'audit-process-evidence.ps1')
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio locator was not found.'
}

$installationPath = & $vswhere -latest -products '*' -property installationPath
if (-not $installationPath) {
    throw 'Visual Studio Build Tools were not found.'
}

$cmake = Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $cmake)) {
    throw 'The Visual Studio CMake component was not found.'
}

$architectures = if ($Architecture -eq 'All') { @('x64', 'x86') } else { @($Architecture) }
foreach ($currentArchitecture in $architectures) {
    $platform = if ($currentArchitecture -eq 'x64') { 'x64' } else { 'Win32' }
    $buildDirectory = Join-Path $repositoryRoot "target\native\$currentArchitecture"
    & $cmake -S (Join-Path $repositoryRoot 'native') -B $buildDirectory -A $platform
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $cmake --build $buildDirectory --config $Configuration
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
