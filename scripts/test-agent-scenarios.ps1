[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot,
    [string]$NodePath = '',
    [string]$PythonPath = '',
    [string]$GitPath = '',
    [string]$CargoPath = ''
)

$ErrorActionPreference = 'Stop'
$componentAbsolute = (Resolve-Path -LiteralPath $ComponentRoot).Path

function Resolve-RequiredTool(
    [string]$Requested,
    [string]$CommandName,
    [string]$Label
) {
    $candidate = $Requested
    if (-not $candidate) {
        $command = Get-Command $CommandName -ErrorAction SilentlyContinue
        if ($command) { $candidate = $command.Source }
    }
    if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        throw "$Label runtime is required; pass its absolute executable path."
    }
    return (Resolve-Path -LiteralPath $candidate).Path
}

$node = Resolve-RequiredTool $NodePath 'node' 'Node'
$python = Resolve-RequiredTool $PythonPath 'python' 'Python'
$cargo = Resolve-RequiredTool $CargoPath 'cargo' 'Cargo'
$git = Resolve-RequiredTool $GitPath 'git' 'Git'

# Resolve Git for Windows' relaunching shim to the actual MinGW executable.
if ((Get-Item -LiteralPath $git).Length -lt 1MB) {
    $execPath = & $git --exec-path
    if ($LASTEXITCODE -ne 0 -or -not $execPath) { throw 'Git executable resolution failed.' }
    $mingwRoot = Split-Path -Parent (Split-Path -Parent $execPath)
    $actualGit = Join-Path $mingwRoot 'bin\git.exe'
    if (-not (Test-Path -LiteralPath $actualGit -PathType Leaf)) {
        throw 'Git for Windows runtime executable was not found.'
    }
    $git = (Resolve-Path -LiteralPath $actualGit).Path
}

# Resolve rustup's Cargo shim to the selected toolchain executable.
if ((Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $cargo))) -ieq '.cargo') {
    $rustup = Get-Command rustup -ErrorAction SilentlyContinue
    if (-not $rustup) { throw 'rustup is required to resolve the Cargo toolchain.' }
    $resolvedCargo = & $rustup.Source which cargo
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $resolvedCargo -PathType Leaf)) {
        throw 'Cargo toolchain resolution failed.'
    }
    $cargo = (Resolve-Path -LiteralPath $resolvedCargo).Path
}

$env:BOLT_NATIVE_COMPONENT_ROOT = $componentAbsolute
$env:BOLT_TEST_NODE = $node
$env:BOLT_TEST_PYTHON = $python
$env:BOLT_TEST_GIT = $git
$env:BOLT_TEST_CARGO = $cargo

& cargo test --test cli_integration -- --nocapture
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'Agent scenario suite passed.'
Write-Output "Node: $node"
Write-Output "Python: $python"
Write-Output "Git: $git"
Write-Output "Cargo: $cargo"
