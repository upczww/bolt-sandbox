[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path $repositoryRoot 'native\hook\filesystem\hooks-manifest.json'
$sourcePath = Join-Path $repositoryRoot 'native\hook\filesystem\file_hooks.cpp'
$runtimeTestPath = Join-Path $repositoryRoot 'native\tests\process_tests.cpp'
$catalogPath = Join-Path $repositoryRoot 'docs\testing\test-catalog.md'
$coveragePath = Join-Path $repositoryRoot 'docs\testing\api-coverage.md'

if (-not (Test-Path -LiteralPath $manifestPath)) {
    throw "Filesystem hook manifest is missing: $manifestPath"
}

$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or $manifest.component -ne 'filesystem') {
    throw 'Filesystem hook manifest has an unsupported schema or component.'
}
if (@($manifest.architectures) -join ',' -ne 'x86,x64') {
    throw 'Filesystem hook manifest must declare x86 and x64 in canonical order.'
}
if ($manifest.minimum_windows_sdk -notmatch '^10\.0\.\d+\.0$') {
    throw 'Filesystem hook manifest must declare a concrete Windows SDK baseline.'
}

$hooks = @($manifest.hooks)
if ($hooks.Count -eq 0) {
    throw 'Filesystem hook manifest cannot be empty.'
}
$allowedOperations = @(
    'read', 'write', 'metadata', 'create', 'delete', 'rename', 'enumerate',
    'link', 'mapping', 'notification', 'shell'
)
$manifestPairs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$symbols = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
$catalog = Get-Content -Raw -LiteralPath $catalogPath
$catalogIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($match in [regex]::Matches($catalog, '(?m)^\|\s*((?:FS|SEM|BYP|HOOK)-\d{3})\s*\|')) {
    [void]$catalogIds.Add($match.Groups[1].Value)
}

foreach ($hook in $hooks) {
    foreach ($field in @('target', 'detour', 'symbol', 'module')) {
        if ([string]::IsNullOrWhiteSpace([string]$hook.$field)) {
            throw "Filesystem hook entry has an empty '$field' field."
        }
    }
    $pair = "$($hook.target)|$($hook.detour)"
    if (-not $manifestPairs.Add($pair)) {
        throw "Duplicate filesystem hook attachment: $pair"
    }
    if (-not $symbols.Add([string]$hook.symbol)) {
        throw "Duplicate filesystem hook symbol: $($hook.symbol)"
    }
    if ($hook.module -notmatch '^(advapi32|kernel32|ntdll|shell32)\.dll$') {
        throw "Unexpected filesystem hook module: $($hook.module)"
    }
    $hookArchitectures = if ($null -eq $hook.architectures) {
        @($manifest.architectures)
    } else {
        @($hook.architectures)
    }
    if ($hookArchitectures -join ',' -ne 'x86,x64') {
        throw "Hook $($hook.symbol) must cover x86 and x64."
    }
    if ($hook.availability -notin @('required', 'if_present')) {
        throw "Hook $($hook.symbol) has invalid availability."
    }
    if (@($hook.operations).Count -eq 0) {
        throw "Hook $($hook.symbol) has no operation classification."
    }
    foreach ($operation in @($hook.operations)) {
        if ($operation -notin $allowedOperations) {
            throw "Hook $($hook.symbol) has unknown operation '$operation'."
        }
    }
    if (@($hook.cases).Count -eq 0) {
        throw "Hook $($hook.symbol) has no catalog evidence."
    }
    foreach ($caseId in @($hook.cases)) {
        if (-not $catalogIds.Contains([string]$caseId)) {
            throw "Hook $($hook.symbol) cites unknown catalog case '$caseId'."
        }
    }
}

$source = Get-Content -Raw -LiteralPath $sourcePath
$attachPattern = 'DetourAttach\(\s*reinterpret_cast<PVOID\*>\(&(?<target>g_[a-z0-9_]+)\),\s*reinterpret_cast<PVOID>\((?<detour>Detoured[A-Za-z0-9_]+)\)'
$sourcePairs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($match in [regex]::Matches(
    $source, $attachPattern,
    [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
    [void]$sourcePairs.Add(
        "$($match.Groups['target'].Value)|$($match.Groups['detour'].Value)")
}
if ($sourcePairs.Count -eq 0) {
    throw 'No filesystem DetourAttach calls were discovered in production source.'
}
$attachmentDifference = @(
    Compare-Object @($sourcePairs) @($manifestPairs)
)
if ($attachmentDifference.Count -ne 0) {
    $details = $attachmentDifference | ForEach-Object {
        "$($_.SideIndicator) $($_.InputObject)"
    }
    throw "Filesystem hook manifest differs from InstallFileHooks:`n$($details -join "`n")"
}

$requiredHookCount = @(
    $hooks | Where-Object { $_.availability -eq 'required' }
).Count
$countMatch = [regex]::Match(
    $source, 'kRequiredFilesystemHookCount\s*=\s*(\d+)')
if (-not $countMatch.Success -or
    [int]$countMatch.Groups[1].Value -ne $requiredHookCount) {
    throw "Runtime required hook count does not match manifest count $requiredHookCount."
}
$runtimeTest = Get-Content -Raw -LiteralPath $runtimeTestPath
$testCountMatch = [regex]::Match(
    $runtimeTest, 'required_filesystem_hook_count\s*=\s*(\d+)')
if (-not $testCountMatch.Success -or
    [int]$testCountMatch.Groups[1].Value -ne $requiredHookCount) {
    throw "Runtime test hook count does not match manifest count $requiredHookCount."
}
if ($source -notmatch 'InstalledFileHookCount\(\)' -or
    $runtimeTest -notmatch 'BoltSandboxInstalledFilesystemHookCount') {
    throw 'Runtime filesystem hook count export or probe is missing.'
}

$coverage = Get-Content -Raw -LiteralPath $coveragePath
$filesystemStart = $coverage.IndexOf('## Filesystem')
$filesystemEnd = $coverage.IndexOf('## Process creation and control')
if ($filesystemStart -lt 0 -or $filesystemEnd -le $filesystemStart) {
    throw 'Filesystem API coverage section could not be located.'
}
$filesystemCoverage = $coverage.Substring(
    $filesystemStart, $filesystemEnd - $filesystemStart)
$documentedClaims = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($match in [regex]::Matches($filesystemCoverage, '`([^`]+)`')) {
    [void]$documentedClaims.Add($match.Groups[1].Value)
}
$manifestClaims = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($claim in @($manifest.coverage_claims)) {
    [void]$manifestClaims.Add([string]$claim)
}
$claimDifference = @(Compare-Object @($documentedClaims) @($manifestClaims))
if ($claimDifference.Count -ne 0) {
    $details = $claimDifference | ForEach-Object {
        "$($_.SideIndicator) $($_.InputObject)"
    }
    throw "Filesystem API coverage claims differ from the manifest:`n$($details -join "`n")"
}

Write-Output 'Filesystem hook manifest verification passed.'
Write-Output "Installed attachment contracts: $($hooks.Count)"
Write-Output "Filesystem API coverage claims: $($manifestClaims.Count)"
