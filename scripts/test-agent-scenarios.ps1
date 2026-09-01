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

function Resolve-SystemLanguageResourceRoots {
    if (-not ('BoltSandbox.MuiLocator' -as [type])) {
        $null = Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace BoltSandbox {
    public static class MuiLocator {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetFileMUIPath(
            uint flags, string filePath, StringBuilder language,
            ref uint languageLength, StringBuilder muiPath,
            ref uint muiPathLength, ref ulong enumerator);
    }
}
'@
    }
    $systemFile = Join-Path $env:SystemRoot 'System32\kernelbase.dll'
    $windowsApps = Join-Path $env:ProgramFiles 'WindowsApps'
    $enumerator = [uint64]0
    $roots = [System.Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt 16; $index++) {
        $language = [System.Text.StringBuilder]::new(85)
        $languageLength = [uint32]$language.Capacity
        $muiPath = [System.Text.StringBuilder]::new(32768)
        $muiPathLength = [uint32]$muiPath.Capacity
        $found = [BoltSandbox.MuiLocator]::GetFileMUIPath(
            0x18, $systemFile, $language, [ref]$languageLength,
            $muiPath, [ref]$muiPathLength, [ref]$enumerator)
        if (-not $found) { break }
        $candidate = [System.IO.DirectoryInfo]::new($muiPath.ToString()).Parent
        while ($candidate -and $candidate.Parent -and
            $candidate.Parent.FullName -ine $windowsApps) {
            $candidate = $candidate.Parent
        }
        if ($candidate -and $candidate.Parent -and
            $candidate.Parent.FullName -ieq $windowsApps -and
            -not $roots.Contains($candidate.FullName)) {
            $roots.Add($candidate.FullName)
        }
    }
    $overlayPackages = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\LanguageOverlay\OverlayPackages'
    if (Test-Path -LiteralPath $overlayPackages) {
        Get-ChildItem -LiteralPath $overlayPackages | ForEach-Object {
            $latest = (Get-ItemProperty -LiteralPath $_.PSPath -Name Latest -ErrorAction SilentlyContinue).Latest
            if ($latest -and (Test-Path -LiteralPath $latest -PathType Container)) {
                $candidate = [System.IO.DirectoryInfo]::new($latest)
                if ($candidate.Parent -and $candidate.Parent.FullName -ieq $windowsApps -and
                    -not $roots.Contains($candidate.FullName)) {
                    $roots.Add($candidate.FullName)
                }
            }
        }
    }
    return $roots.ToArray()
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
$systemLanguageResourceRoots = @(Resolve-SystemLanguageResourceRoots)

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
$env:BOLT_TEST_SYSTEM_LANGUAGE_ROOTS = $systemLanguageResourceRoots -join ';'
$env:BOLT_TOOL_NODE = $node
$env:BOLT_TOOL_PYTHON = $python
$env:BOLT_TOOL_GIT = $git
$env:BOLT_TOOL_CARGO = $cargo
$env:BOLT_TOOL_RUSTC = Join-Path (Split-Path -Parent $cargo) 'rustc.exe'
$env:BOLT_TOOL_RUSTFMT = Join-Path (Split-Path -Parent $cargo) 'rustfmt.exe'
$env:BOLT_TOOL_CLIPPY_DRIVER = Join-Path (Split-Path -Parent $cargo) 'clippy-driver.exe'
if ($NativeCompilerKind -eq 'msvc') { $env:BOLT_TOOL_CL = $nativeCompiler }
$env:BOLT_SYSTEM_LANGUAGE_ROOTS = $systemLanguageResourceRoots -join ';'

& cargo test --test cli_integration --test tool_matrix_contract -- --nocapture --test-threads=1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'Agent scenario suite passed.'
Write-Output "Node: $node"
Write-Output "Python: $python"
Write-Output "Git: $git"
Write-Output "Cargo: $cargo"
Write-Output "Shell: $shell"
Write-Output "PowerShell: $powerShell"
Write-Output "Native compiler ($NativeCompilerKind): $nativeCompiler"
Write-Output "System language resource roots: $($systemLanguageResourceRoots.Count)"
