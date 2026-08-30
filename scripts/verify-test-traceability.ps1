[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$testingRoot = Join-Path $repositoryRoot 'docs\testing'
$catalogPath = Join-Path $testingRoot 'test-catalog.md'
$matrixPath = Join-Path $testingRoot 'requirements-matrix.md'

$errors = [System.Collections.Generic.List[string]]::new()

function Get-UniqueMatches {
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $Pattern,

        [int] $Group = 1
    )

    return [regex]::Matches(
        $Text,
        $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::Multiline
    ) | ForEach-Object { $_.Groups[$Group].Value }
}

foreach ($requiredPath in @($catalogPath, $matrixPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        $errors.Add("Required file is missing: $requiredPath")
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

$catalogText = Get-Content -Raw -LiteralPath $catalogPath
$matrixText = Get-Content -Raw -LiteralPath $matrixPath
$caseIds = @(Get-UniqueMatches -Text $catalogText -Pattern '^\| ([A-Z]+-\d{3}) \|')
$requirementIds = @(Get-UniqueMatches -Text $matrixText -Pattern '^\| (ARC-[A-Z]+-\d{3}) \|')

foreach ($duplicate in @($caseIds | Group-Object | Where-Object Count -gt 1)) {
    $errors.Add("Duplicate catalog case ID: $($duplicate.Name)")
}

foreach ($duplicate in @($requirementIds | Group-Object | Where-Object Count -gt 1)) {
    $errors.Add("Duplicate architecture requirement ID: $($duplicate.Name)")
}

$caseIdSet = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)
$caseIds | ForEach-Object { [void] $caseIdSet.Add($_) }

$testingDocuments = Get-ChildItem -LiteralPath $testingRoot -Filter '*.md' -File
foreach ($document in $testingDocuments) {
    $text = Get-Content -Raw -LiteralPath $document.FullName
    $references = Get-UniqueMatches `
        -Text $text `
        -Pattern '(?<!ARC-)\b([A-Z]+-\d{3})\b'

    foreach ($reference in $references) {
        if (-not $caseIdSet.Contains($reference)) {
            $errors.Add("Unknown case ID $reference in $($document.FullName)")
        }
    }
}

$coveredCaseIds = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)

$rangePattern = '\b([A-Z]+)-(\d{3})\.\.(?:([A-Z]+)-)?(\d{3})\b'
foreach ($range in [regex]::Matches($matrixText, $rangePattern)) {
    $startPrefix = $range.Groups[1].Value
    $endPrefix = $range.Groups[3].Value
    if ([string]::IsNullOrEmpty($endPrefix)) {
        $endPrefix = $startPrefix
    }

    if ($startPrefix -ne $endPrefix) {
        $errors.Add("Cross-prefix case range is not allowed: $($range.Value)")
        continue
    }

    $start = [int] $range.Groups[2].Value
    $end = [int] $range.Groups[4].Value
    if ($start -gt $end) {
        $errors.Add("Descending case range is not allowed: $($range.Value)")
        continue
    }

    for ($number = $start; $number -le $end; $number++) {
        [void] $coveredCaseIds.Add(
            ('{0}-{1:D3}' -f $startPrefix, $number)
        )
    }
}

$explicitMatrixCases = Get-UniqueMatches `
    -Text $matrixText `
    -Pattern '(?<!ARC-)\b([A-Z]+-\d{3})\b'
$explicitMatrixCases | ForEach-Object { [void] $coveredCaseIds.Add($_) }

foreach ($caseId in $caseIds) {
    if ($caseId -like 'GATE-*') {
        continue
    }

    if (-not $coveredCaseIds.Contains($caseId)) {
        $errors.Add("Catalog case has no requirement mapping: $caseId")
    }
}

$forbiddenOraclePhrases = @(
    'allow or deny',
    'according to the implementation',
    'documented behavior',
    'where supported',
    'if supported',
    'may succeed',
    'or fails safely'
)

$lineNumber = 0
foreach ($line in Get-Content -LiteralPath $catalogPath) {
    $lineNumber++
    if ($line -notmatch '^\| [A-Z]+-\d{3} \|') {
        continue
    }

    $columns = $line.Split('|')
    if ($columns.Count -ne 5) {
        $errors.Add("Malformed catalog row at line $lineNumber")
        continue
    }

    $expected = $columns[3].Trim()
    foreach ($phrase in $forbiddenOraclePhrases) {
        if ($expected.Contains($phrase, [System.StringComparison]::OrdinalIgnoreCase)) {
            $errors.Add(
                "Ambiguous expected result '$phrase' at catalog line $lineNumber"
            )
        }
    }
}

$markdownPaths = @(
    & git -C $repositoryRoot ls-files --cached --others --exclude-standard -- '*.md'
)
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to enumerate repository Markdown files.'
}
$markdownDocuments = @(
    $markdownPaths | ForEach-Object {
        Get-Item -LiteralPath (Join-Path $repositoryRoot $_)
    }
)
foreach ($document in $markdownDocuments) {
    $text = Get-Content -Raw -LiteralPath $document.FullName
    foreach ($link in [regex]::Matches($text, '\[[^\]]+\]\(([^)#]+\.md)(?:#[^)]+)?\)')) {
        $target = Join-Path $document.DirectoryName $link.Groups[1].Value
        if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
            $errors.Add("Broken Markdown link in $($document.FullName): $($link.Groups[1].Value)")
        }
    }
}

if ($errors.Count -gt 0) {
    $errors | ForEach-Object { Write-Error $_ }
    exit 1
}

$behaviorCount = @($caseIds | Where-Object { $_ -notlike 'GATE-*' }).Count
$gateCount = @($caseIds | Where-Object { $_ -like 'GATE-*' }).Count
Write-Output "Traceability verification passed."
Write-Output "Architecture requirements: $($requirementIds.Count)"
Write-Output "Behavior cases: $behaviorCount"
Write-Output "Release gates: $gateCount"
