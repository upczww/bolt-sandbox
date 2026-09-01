[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $ComponentRoot).Path
$knownNames = @(
    'bolt-sandbox.exe',
    'bolt-sandbox-launcher.exe',
    'bolt-sandbox-launcher-x86.exe',
    'bolt-sandbox-x64.dll',
    'bolt-sandbox-x86.dll',
    'bolt-sandbox-dns-proxy.exe'
)
$records = @()
foreach ($name in $knownNames) {
    $path = Join-Path $resolvedRoot $name
    if (Test-Path -LiteralPath $path -PathType Leaf) {
        $bytes = [IO.File]::ReadAllBytes($path)
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = $hash.ComputeHash($bytes)
        } finally {
            $hash.Dispose()
        }
        $records += [pscustomobject]@{
            Name = $name
            Length = [UInt64]$bytes.LongLength
            Digest = $digest
        }
    }
}
if ($records.Count -lt 2) {
    throw 'At least one architecture-matched launcher and hook are required.'
}

$output = [Collections.Generic.List[byte]]::new()
function Add-Bytes([byte[]]$Bytes) {
    $output.AddRange($Bytes)
}
Add-Bytes ([Text.Encoding]::ASCII.GetBytes('BCM1'))
Add-Bytes ([BitConverter]::GetBytes([UInt16]1))
Add-Bytes ([BitConverter]::GetBytes([UInt16]16))
Add-Bytes ([BitConverter]::GetBytes([UInt16]$records.Count))
Add-Bytes ([BitConverter]::GetBytes([UInt16]1))
Add-Bytes ([byte[]](0, 0, 0, 0))
foreach ($record in $records) {
    $nameBytes = [Text.Encoding]::ASCII.GetBytes($record.Name)
    Add-Bytes ([BitConverter]::GetBytes([UInt16]$nameBytes.Length))
    Add-Bytes ([BitConverter]::GetBytes([UInt16]0))
    Add-Bytes ([BitConverter]::GetBytes([UInt64]$record.Length))
    Add-Bytes $record.Digest
    Add-Bytes $nameBytes
}

$manifest = Join-Path $resolvedRoot 'bolt-sandbox-components.manifest'
$temporary = "$manifest.$PID.tmp"
[IO.File]::WriteAllBytes($temporary, $output.ToArray())
Move-Item -LiteralPath $temporary -Destination $manifest -Force
Write-Output "Component manifest written: $manifest ($($records.Count) records)"
$manifestHash = [Security.Cryptography.SHA256]::Create()
try {
    $manifestDigest = $manifestHash.ComputeHash([IO.File]::ReadAllBytes($manifest))
} finally {
    $manifestHash.Dispose()
}
$manifestHex = -join ($manifestDigest | ForEach-Object { $_.ToString('x2') })
Write-Output "Manifest SHA-256: $manifestHex"
