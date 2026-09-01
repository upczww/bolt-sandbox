[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BudgetPath,

    [Parameter(Mandatory)]
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'

function Read-JsonObject {
    param(
        [string]$Path,
        [string]$Kind
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "INSUFFICIENT_EVIDENCE: $Kind file is missing."
    }
    try {
        return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "INSUFFICIENT_EVIDENCE: $Kind file is not valid JSON."
    }
}

function Require-PositiveNumber {
    param(
        [object]$Object,
        [string]$Name
    )

    if ($Object.PSObject.Properties.Name -notcontains $Name -or
        $null -eq $Object.$Name -or
        $Object.$Name -isnot [ValueType] -or
        [double]$Object.$Name -le 0) {
        throw "NOT_CONFIGURED: performance budget '$Name' must be a positive number."
    }
    return [double]$Object.$Name
}

function Require-Samples {
    param(
        [object]$Evidence,
        [string]$Name,
        [int]$MinimumCount
    )

    if ($Evidence.PSObject.Properties.Name -notcontains $Name) {
        throw "INSUFFICIENT_EVIDENCE: sample set '$Name' is missing."
    }
    $samples = @($Evidence.$Name)
    if ($samples.Count -lt $MinimumCount) {
        throw "INSUFFICIENT_EVIDENCE: sample set '$Name' has $($samples.Count) values; $MinimumCount required."
    }
    foreach ($sample in $samples) {
        if ($null -eq $sample -or $sample -isnot [ValueType] -or [double]$sample -lt 0) {
            throw "INSUFFICIENT_EVIDENCE: sample set '$Name' contains an invalid value."
        }
    }
    return [double[]]$samples
}

function Get-Median {
    param([double[]]$Samples)

    $ordered = @($Samples | Sort-Object)
    $middle = [int][math]::Floor($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) {
        return [double]$ordered[$middle]
    }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2
}

function Get-Growth {
    param([double[]]$Samples)

    return [math]::Max(0, $Samples[$Samples.Count - 1] - $Samples[0])
}

function Assert-WithinBudget {
    param(
        [string]$Metric,
        [double]$Actual,
        [double]$Maximum
    )

    if ($Actual -gt $Maximum) {
        throw "OUT_OF_BUDGET: $Metric actual=$Actual maximum=$Maximum."
    }
}

$budget = Read-JsonObject -Path $BudgetPath -Kind 'budget'
$evidence = Read-JsonObject -Path $EvidencePath -Kind 'evidence'
if ($budget.schemaVersion -ne 1) {
    throw 'NOT_CONFIGURED: unsupported performance budget schema.'
}
if ($evidence.schemaVersion -ne 1) {
    throw 'INSUFFICIENT_EVIDENCE: unsupported performance evidence schema.'
}

$minimumWarmup = Require-PositiveNumber $budget 'minimumWarmupSamples'
$minimumMeasured = Require-PositiveNumber $budget 'minimumMeasuredSamples'
$maximumStartup = Require-PositiveNumber $budget 'maximumWarmStartupMilliseconds'
$maximumFilesystemOverhead = Require-PositiveNumber $budget 'maximumFilesystemOverheadPercent'
$maximumPrivateBytes = Require-PositiveNumber $budget 'maximumPrivateBytes'
$maximumPrivateGrowth = Require-PositiveNumber $budget 'maximumPrivateBytesGrowth'
$maximumHandles = Require-PositiveNumber $budget 'maximumHandles'
$maximumHandleGrowth = Require-PositiveNumber $budget 'maximumHandleGrowth'
$maximumThreads = Require-PositiveNumber $budget 'maximumThreads'
$maximumThreadGrowth = Require-PositiveNumber $budget 'maximumThreadGrowth'

if ($evidence.environmentValid -ne $true) {
    throw 'INVALID_ENVIRONMENT: benchmark environment was not validated.'
}
if ($evidence.warmupSamples -lt $minimumWarmup) {
    throw "INSUFFICIENT_EVIDENCE: warmup sample count is below $minimumWarmup."
}

$sampleCount = [int]$minimumMeasured
$startup = Require-Samples $evidence 'startupMilliseconds' $sampleCount
$control = Require-Samples $evidence 'filesystemControlMilliseconds' $sampleCount
$sandbox = Require-Samples $evidence 'filesystemSandboxMilliseconds' $sampleCount
$privateBytes = Require-Samples $evidence 'privateBytes' $sampleCount
$handles = Require-Samples $evidence 'handles' $sampleCount
$threads = Require-Samples $evidence 'threads' $sampleCount

$controlMedian = Get-Median $control
if ($controlMedian -le 0) {
    throw 'INSUFFICIENT_EVIDENCE: filesystem control median must be positive.'
}
$sandboxMedian = Get-Median $sandbox
$filesystemOverhead = (($sandboxMedian - $controlMedian) / $controlMedian) * 100
$filesystemOverhead = [math]::Max(0, $filesystemOverhead)
$startupMaximum = ($startup | Measure-Object -Maximum).Maximum
$privateMaximum = ($privateBytes | Measure-Object -Maximum).Maximum
$handleMaximum = ($handles | Measure-Object -Maximum).Maximum
$threadMaximum = ($threads | Measure-Object -Maximum).Maximum
$privateGrowth = Get-Growth $privateBytes
$handleGrowth = Get-Growth $handles
$threadGrowth = Get-Growth $threads

Assert-WithinBudget 'warmStartupMilliseconds' $startupMaximum $maximumStartup
Assert-WithinBudget 'filesystemOverheadPercent' $filesystemOverhead $maximumFilesystemOverhead
Assert-WithinBudget 'privateBytes' $privateMaximum $maximumPrivateBytes
Assert-WithinBudget 'privateBytesGrowth' $privateGrowth $maximumPrivateGrowth
Assert-WithinBudget 'handles' $handleMaximum $maximumHandles
Assert-WithinBudget 'handleGrowth' $handleGrowth $maximumHandleGrowth
Assert-WithinBudget 'threads' $threadMaximum $maximumThreads
Assert-WithinBudget 'threadGrowth' $threadGrowth $maximumThreadGrowth

[ordered]@{
    schemaVersion = 1
    status = 'PASS'
    metrics = [ordered]@{
        warmStartupMilliseconds = $startupMaximum
        filesystemOverheadPercent = [math]::Round($filesystemOverhead, 3)
        privateBytes = $privateMaximum
        privateBytesGrowth = $privateGrowth
        handles = $handleMaximum
        handleGrowth = $handleGrowth
        threads = $threadMaximum
        threadGrowth = $threadGrowth
    }
} | ConvertTo-Json -Depth 3 -Compress
