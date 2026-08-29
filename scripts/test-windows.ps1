[CmdletBinding()]
param(
    [ValidateSet('Unit')]
    [string]$Suite = 'Unit',

    [ValidateSet('x64', 'x86')]
    [string]$Architecture = 'x64',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',

    [string[]]$Case = @()
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installationPath = & $vswhere -latest -products '*' -property installationPath
$ctest = Join-Path $installationPath 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\ctest.exe'
$buildDirectory = Join-Path $repositoryRoot "target\native\$Architecture"
if (-not (Test-Path -LiteralPath $buildDirectory)) {
    throw "Native $Architecture outputs have not been configured."
}

$arguments = @('--test-dir', $buildDirectory, '-C', $Configuration, '--output-on-failure')
if ($Case.Count -gt 0) {
    $escapedCases = $Case | ForEach-Object { [regex]::Escape($_) }
    $arguments += @('-R', ($escapedCases -join '|'))
}
& $ctest @arguments
exit $LASTEXITCODE
