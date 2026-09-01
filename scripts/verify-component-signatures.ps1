[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot,

    [switch]$RequireSigned
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $ComponentRoot).Path
$names = @(
    'bolt-sandbox.exe',
    'bolt-sandbox-launcher.exe',
    'bolt-sandbox-launcher-x86.exe',
    'bolt-sandbox-x64.dll',
    'bolt-sandbox-x86.dll'
)
$found = 0
foreach ($name in $names) {
    $path = Join-Path $resolvedRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        continue
    }
    $found++
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($RequireSigned -and $signature.Status -ne 'Valid') {
        throw "Component signature is not valid: $name ($($signature.Status))"
    }
    Write-Output "Component signature: $name status=$($signature.Status)"
}
if ($found -eq 0) {
    throw 'No release components were found.'
}
