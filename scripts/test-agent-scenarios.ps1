[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot,
    [string]$NodePath = '',
    [string]$PythonPath = '',
    [string]$GitPath = '',
    [string]$CargoPath = '',
    [string]$ShellPath = '',
    [string]$PowerShellPath = '',
    [string]$NativeCompilerPath = '',
    [ValidateSet('', 'gcc', 'msvc')]
    [string]$NativeCompilerKind = '',
    [string[]]$NativeCompilerReadRoot = @()
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
$shell = Resolve-RequiredTool $ShellPath 'cmd' 'command shell'
$powerShell = Resolve-RequiredTool $PowerShellPath 'pwsh' 'PowerShell'

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

if (-not $NativeCompilerPath) {
    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    if ($gcc) {
        $NativeCompilerPath = $gcc.Source
        $NativeCompilerKind = 'gcc'
    } else {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
            $NativeCompilerPath = & $vswhere -latest -products * `
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                -find 'VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe' |
                Select-Object -First 1
            if ($NativeCompilerPath) { $NativeCompilerKind = 'msvc' }
        }
    }
}
$nativeCompiler = Resolve-RequiredTool $NativeCompilerPath $NativeCompilerKind 'native compiler'
if (-not $NativeCompilerKind) {
    $NativeCompilerKind = if ((Split-Path -Leaf $nativeCompiler) -ieq 'cl.exe') { 'msvc' } else { 'gcc' }
}

if ($NativeCompilerKind -eq 'msvc' -and $NativeCompilerReadRoot.Count -eq 0) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'vswhere is required to discover the MSVC read-only SDK roots.'
    }
    $installation = & $vswhere -latest -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath
    $vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path -LiteralPath $vcvars -PathType Leaf)) {
        throw 'MSVC vcvars64.bat was not found.'
    }
    & $shell /d /s /c "`"$vcvars`" >nul && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }
    $NativeCompilerReadRoot = @($env:INCLUDE -split ';') + @($env:LIB -split ';')
}
$nativeCompilerReadRoots = @(
    $NativeCompilerReadRoot |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } |
        ForEach-Object { (Resolve-Path -LiteralPath $_).Path } |
        Sort-Object -Unique
)

$env:BOLT_NATIVE_COMPONENT_ROOT = $componentAbsolute
$env:BOLT_TEST_NODE = $node
$env:BOLT_TEST_PYTHON = $python
$env:BOLT_TEST_GIT = $git
$env:BOLT_TEST_CARGO = $cargo
$env:BOLT_TEST_SHELL = $shell
$env:BOLT_TEST_POWERSHELL = $powerShell
$env:BOLT_TEST_NATIVE_COMPILER = $nativeCompiler
$env:BOLT_TEST_NATIVE_COMPILER_KIND = $NativeCompilerKind
$env:BOLT_TEST_NATIVE_COMPILER_READ_ROOTS = $nativeCompilerReadRoots -join ';'

& cargo test --test cli_integration -- --nocapture --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'Agent scenario suite passed.'
Write-Output "Node: $node"
Write-Output "Python: $python"
Write-Output "Git: $git"
Write-Output "Cargo: $cargo"
Write-Output "Shell: $shell"
Write-Output "PowerShell: $powerShell"
Write-Output "Native compiler ($NativeCompilerKind): $nativeCompiler"
