[CmdletBinding()]
param(
    [string]$Version = 'ephemeral-signed-audit'
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$subject = 'CN=Bolt Sandbox Ephemeral Signing Test ' +
    [guid]::NewGuid().ToString('N')
$certificate = $null
$trustedRoot = $null
$trustedPublisher = $null
$cerPath = Join-Path $repositoryRoot 'target\ephemeral-signing-test.cer'
$signtool = Get-ChildItem -LiteralPath `
    'C:\Program Files (x86)\Windows Kits\10\bin' `
    -Filter signtool.exe -Recurse |
    Where-Object FullName -Match '\\x64\\signtool\.exe$' |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if (-not $signtool) {
    throw 'signtool.exe is unavailable.'
}

$files = @(
    (Join-Path $repositoryRoot 'target\release\bolt-sandbox.exe'),
    (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-launcher.exe'),
    (Join-Path $repositoryRoot 'target\native\x86\Release\bolt-sandbox-launcher-x86.exe'),
    (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-x64.dll'),
    (Join-Path $repositoryRoot 'target\native\x86\Release\bolt-sandbox-x86.dll'),
    (Join-Path $repositoryRoot 'target\native\x64\Release\bolt-sandbox-dns-proxy.exe')
)
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw 'A required generated component is missing.'
    }
}

try {
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject $subject -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddDays(1)
    Export-Certificate -Cert $certificate -FilePath $cerPath -Force |
        Out-Null
    $trustedRoot = Import-Certificate -FilePath $cerPath `
        -CertStoreLocation 'Cert:\CurrentUser\Root'
    $trustedPublisher = Import-Certificate -FilePath $cerPath `
        -CertStoreLocation 'Cert:\CurrentUser\TrustedPublisher'

    foreach ($file in $files) {
        & $signtool.FullName sign /sha1 $certificate.Thumbprint `
            /fd SHA256 $file | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Ephemeral component signing failed.'
        }
    }
    $invalid = @($files | Where-Object {
        (Get-AuthenticodeSignature -LiteralPath $_).Status -ne 'Valid'
    })
    if ($invalid.Count -ne 0) {
        throw 'An ephemeral component signature is not valid.'
    }

    pwsh -NoProfile -File $PSScriptRoot\package-windows.ps1 `
        -Version $Version -SkipBuildCli -RequireSigned
    if ($LASTEXITCODE -ne 0) {
        throw 'Strict signed package creation failed.'
    }
    [ordered]@{
        signedComponents = $files.Count
        allSignaturesValid = $true
        strictPackageCreated = $true
        privateKeyExported = $false
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $certificate) {
        Remove-Item -LiteralPath `
            "Cert:\CurrentUser\My\$($certificate.Thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $trustedPublisher) {
        Remove-Item -LiteralPath `
            "Cert:\CurrentUser\TrustedPublisher\$($trustedPublisher.Thumbprint)" `
            -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $trustedRoot) {
        & certutil.exe -user -delstore Root $trustedRoot.SerialNumber |
            Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Error 'Ephemeral CurrentUser Root cleanup failed.'
        }
    }
    if (Test-Path -LiteralPath $cerPath) {
        Remove-Item -LiteralPath $cerPath -Force
    }
}
