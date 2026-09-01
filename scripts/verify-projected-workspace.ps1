[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot
)

$ErrorActionPreference = 'Stop'
$projectedFsLibrary = Join-Path $env:SystemRoot 'System32\ProjectedFSLib.dll'
if (-not (Test-Path -LiteralPath $projectedFsLibrary -PathType Leaf)) {
    throw 'NOT_CONFIGURED: enable the Windows Client-ProjFS optional component and reboot if required.'
}
if (-not [IO.Path]::IsPathFullyQualified($ComponentRoot) -or
    -not (Test-Path -LiteralPath $ComponentRoot -PathType Container)) {
    throw 'INVALID_COMPONENT_ROOT: pass an absolute existing component directory.'
}
$resolvedRoot = (Resolve-Path -LiteralPath $ComponentRoot).Path
$manifest = Join-Path $resolvedRoot 'bolt-sandbox-components.manifest'
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw 'INVALID_COMPONENT_ROOT: component manifest is missing.'
}
$cargo = Get-Command cargo -ErrorAction Stop
$env:BOLT_NATIVE_COMPONENT_ROOT = $resolvedRoot
& $cargo.Source test --test runtime_integration `
    ws_005_projected_mode_never_falls_back_when_optional_component_is_unavailable `
    -- --nocapture --test-threads=1
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Write-Output 'Projected workspace functionality and cold/warm budgets passed.'
