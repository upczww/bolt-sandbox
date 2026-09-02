[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$')]
    [string]$Version,

    [string]$PythonPath = '',
    [string]$CargoPath = '',
    [string]$NativeCompilerPath = '',
    [ValidateSet('', 'gcc', 'msvc')]
    [string]$NativeCompilerKind = '',
    [string[]]$NativeCompilerReadRoot = @(),

    [switch]$RequireSigned,
    [string]$CertificateThumbprint = '',
    [string]$TimestampUrl = ''
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$releaseComponentRoot = Join-Path $repositoryRoot 'target\native\x64\Release'
$evidencePath = Join-Path $repositoryRoot 'target\performance-evidence-x64.json'
$benchmarkPath = Join-Path $repositoryRoot 'target\release\bolt-sandbox-benchmark.exe'

if ($RequireSigned -and -not $CertificateThumbprint) {
    throw 'A code-signing certificate thumbprint is required for a signed release.'
}
if ($CertificateThumbprint) {
    if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') {
        throw 'CertificateThumbprint must be a 40-character hexadecimal SHA-1 thumbprint.'
    }
    $timestamp = $null
    if (-not [Uri]::TryCreate(
            $TimestampUrl, [UriKind]::Absolute, [ref]$timestamp) -or
        $timestamp.Scheme -ne 'https') {
        throw 'TimestampUrl must be an absolute HTTPS URI when signing.'
    }
    $RequireSigned = $true
}

& cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cargo clippy --all-targets --all-features -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'verify-test-traceability.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'test-third-party.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& (Join-Path $PSScriptRoot 'build-windows.ps1') `
    -Configuration Release -Architecture All
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cargo build --release --bin bolt-sandbox --bin bolt-sandbox-benchmark
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cargo test --release --all-targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'test-windows.ps1') `
    -Architecture x64 -Configuration Release -Case native.protocol
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'test-windows.ps1') `
    -Architecture x86 -Configuration Release -Case native.protocol
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$agentParameters = @{
    ComponentRoot = $releaseComponentRoot
}
if ($PythonPath) { $agentParameters.PythonPath = $PythonPath }
if ($CargoPath) { $agentParameters.CargoPath = $CargoPath }
if ($NativeCompilerPath) {
    $agentParameters.NativeCompilerPath = $NativeCompilerPath
}
if ($NativeCompilerKind) {
    $agentParameters.NativeCompilerKind = $NativeCompilerKind
}
if ($NativeCompilerReadRoot.Count -ne 0) {
    $agentParameters.NativeCompilerReadRoot = $NativeCompilerReadRoot
}
& (Join-Path $PSScriptRoot 'test-agent-scenarios.ps1') @agentParameters
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& (Join-Path $PSScriptRoot 'measure-windows-performance.ps1') `
    -ComponentRoot $releaseComponentRoot `
    -BenchmarkPath $benchmarkPath `
    -EvidencePath $evidencePath `
    -WarmupSamples 1 `
    -MeasuredSamples 7 `
    -FilesystemIterations 1000 `
    -TimeoutSeconds 180
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $PSScriptRoot 'verify-performance-evidence.ps1') `
    -BudgetPath (Join-Path $repositoryRoot 'docs\testing\performance-budgets.json') `
    -EvidencePath $evidencePath
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($CertificateThumbprint) {
    $certificate = Get-ChildItem `
        "Cert:\CurrentUser\My\$CertificateThumbprint" `
        -ErrorAction SilentlyContinue
    if (-not $certificate) {
        $certificate = Get-ChildItem `
            "Cert:\LocalMachine\My\$CertificateThumbprint" `
            -ErrorAction SilentlyContinue
    }
    if (-not $certificate -or -not $certificate.HasPrivateKey) {
        throw 'The requested code-signing certificate with private key was not found.'
    }
    $signtool = Get-ChildItem `
        'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe' `
        | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe was not found.' }
    $files = @(
        (Join-Path $repositoryRoot 'target\release\bolt-sandbox.exe'),
        (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-launcher.exe'),
        (Join-Path $repositoryRoot 'target\native\x86\Release\bolt-sandbox-launcher-x86.exe'),
        (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-x64.dll'),
        (Join-Path $repositoryRoot 'target\native\x86\Release\bolt-sandbox-x86.dll'),
        (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-dns-proxy.exe')
    )
    foreach ($file in $files) {
        & $signtool.FullName sign /sha1 $CertificateThumbprint `
            /fd SHA256 /tr $TimestampUrl /td SHA256 $file
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
}

& (Join-Path $PSScriptRoot 'package-windows.ps1') `
    -Version $Version -SkipBuildCli -RequireSigned:$RequireSigned
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output "Local Windows release completed for version $Version."
Write-Output "Performance evidence: $evidencePath"
