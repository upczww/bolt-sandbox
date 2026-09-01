[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Configuration
)

$ErrorActionPreference = 'Stop'
$maximumBytes = 256KB
$configurationPath = (Resolve-Path -LiteralPath $Configuration).Path
$configurationFile = Get-Item -LiteralPath $configurationPath
if ($configurationFile.Length -gt $maximumBytes) {
    throw "Agent tool matrix exceeds $maximumBytes bytes."
}

$raw = [System.IO.File]::ReadAllText($configurationPath, [System.Text.UTF8Encoding]::new($false, $true))
if ($raw.IndexOf([char]0) -ge 0) { throw 'Agent tool matrix contains NUL.' }
$matrix = $raw | ConvertFrom-Json -Depth 16
if ($null -eq $matrix -or $matrix.version -ne 1) {
    throw 'Agent tool matrix version must be 1.'
}
if ($matrix.requiredFamilies -isnot [array] -or $matrix.scenarios -isnot [array]) {
    throw 'Agent tool matrix families and scenarios must be arrays.'
}

$allowedRootProperties = @('version', 'requiredFamilies', 'scenarios')
$unknownRoot = @($matrix.PSObject.Properties.Name | Where-Object { $_ -notin $allowedRootProperties })
if ($unknownRoot.Count -ne 0) {
    throw "Unknown Agent tool matrix property: $($unknownRoot[0])"
}

$familyPattern = '^[a-z][a-z0-9-]{1,63}$'
$requiredFamilies = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)
foreach ($family in $matrix.requiredFamilies) {
    if ($family -isnot [string] -or $family -notmatch $familyPattern -or
        -not $requiredFamilies.Add($family)) {
        throw "Invalid or duplicate required tool family: $family"
    }
}
if ($requiredFamilies.Count -eq 0) { throw 'At least one required tool family is needed.' }

$allowedScenarioProperties = @(
    'id', 'family', 'requiredOnHost', 'commands', 'candidates', 'terminal', 'privileged',
    'arguments', 'environment', 'readOnly', 'metadataRead', 'files', 'expectedFiles',
    'stdoutContains', 'acceptedExitCodes', 'timeoutMilliseconds', 'network', 'requiredCapabilities'
)
$allowedTokens = @(
    'ProgramFiles', 'ProgramFilesX86', 'ProgramData', 'SystemRoot', 'UserProfile',
    'LocalAppData', 'AppData', 'Workspace', 'Tool', 'ToolDirectory', 'ToolRoot', 'ToolParentRoot',
    'VisualStudio', 'RustToolchain', 'PythonRoot', 'ComponentRoot'
)
$ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$representedFamilies = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal)

function Assert-TokenizedValue([string]$Value, [string]$Field) {
    if (-not $Value -or $Value.IndexOf([char]0) -ge 0) {
        throw "$Field contains an empty or invalid value."
    }
    $withoutTokens = $Value
    foreach ($match in [regex]::Matches($Value, '\{([A-Za-z0-9]+)\}')) {
        if ($match.Groups[1].Value -notin $allowedTokens) {
            throw "$Field contains unknown token $($match.Value)."
        }
        $withoutTokens = $withoutTokens.Replace($match.Value, '')
    }
    if ($withoutTokens -match '\{[^}]*\}' -or
        [System.IO.Path]::IsPathFullyQualified($withoutTokens) -or
        $withoutTokens.StartsWith('\\')) {
        throw "$Field embeds an absolute or malformed machine path."
    }
}

foreach ($scenario in $matrix.scenarios) {
    $unknown = @($scenario.PSObject.Properties.Name | Where-Object {
        $_ -notin $allowedScenarioProperties
    })
    if ($unknown.Count -ne 0) { throw "Unknown scenario property: $($unknown[0])" }
    if ($scenario.id -isnot [string] -or $scenario.id -notmatch $familyPattern -or
        -not $ids.Add($scenario.id)) {
        throw "Invalid or duplicate scenario id: $($scenario.id)"
    }
    if ($scenario.family -isnot [string] -or $scenario.family -notmatch $familyPattern) {
        throw "Invalid scenario family for $($scenario.id)."
    }
    $null = $representedFamilies.Add($scenario.family)
    if ($scenario.requiredOnHost -isnot [bool]) {
        throw "requiredOnHost must be Boolean for $($scenario.id)."
    }
    if ($scenario.terminal -notin @('pipes', 'pseudo-console')) {
        throw "Invalid terminal mode for $($scenario.id)."
    }
    if ($scenario.privileged -eq $true -and $scenario.requiredOnHost) {
        throw "Privileged scenario cannot be required by default: $($scenario.id)."
    }
    if ($scenario.commands -isnot [array] -or $scenario.commands.Count -eq 0) {
        throw "Scenario must declare command candidates: $($scenario.id)."
    }
    foreach ($command in $scenario.commands) {
        if ($command -isnot [string] -or $command -notmatch '^[A-Za-z0-9][A-Za-z0-9+_.-]{0,63}$') {
            throw "Invalid command candidate for $($scenario.id)."
        }
    }
    $candidateValues = if ($null -eq $scenario.candidates) { @() } else { @($scenario.candidates) }
    foreach ($candidate in $candidateValues) {
        if ($candidate -isnot [string]) { throw "Invalid path candidate for $($scenario.id)." }
        Assert-TokenizedValue $candidate "candidate for $($scenario.id)"
    }
    foreach ($capability in @($scenario.requiredCapabilities | Where-Object { $null -ne $_ })) {
        if ($capability -notin @(
            'private-named-pipes', 'workspace-volume-metadata', 'dynamic-host-grants'
        )) {
            throw "Unknown required capability for $($scenario.id): $capability"
        }
    }
}

foreach ($family in $requiredFamilies) {
    if (-not $representedFamilies.Contains($family)) {
        throw "Required tool family is not represented: $family"
    }
}

Write-Output 'Agent tool matrix verification passed.'
Write-Output "Required families: $($requiredFamilies.Count)"
Write-Output "Scenarios: $($ids.Count)"
