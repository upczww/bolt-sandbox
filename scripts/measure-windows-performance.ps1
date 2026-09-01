[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ComponentRoot,

    [Parameter(Mandatory)]
    [string]$EvidencePath,

    [string]$BenchmarkPath,

    [ValidateRange(1, 10)]
    [int]$WarmupSamples = 1,

    [ValidateRange(1, 100)]
    [int]$MeasuredSamples = 7,

    [ValidateRange(1, 100000)]
    [int]$FilesystemIterations = 1000,

    [ValidateRange(10, 600)]
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($BenchmarkPath)) {
    $BenchmarkPath = Join-Path $repositoryRoot 'target\release\bolt-sandbox-benchmark.exe'
}

if (-not [IO.Path]::IsPathFullyQualified($ComponentRoot) -or
    -not (Test-Path -LiteralPath $ComponentRoot -PathType Container) -or
    -not (Test-Path -LiteralPath (Join-Path $ComponentRoot 'bolt-sandbox-components.manifest') -PathType Leaf) -or
    -not [IO.Path]::IsPathFullyQualified($BenchmarkPath) -or
    -not (Test-Path -LiteralPath $BenchmarkPath -PathType Leaf)) {
    throw 'INVALID_BENCHMARK_INPUT: benchmark input paths are missing or untrusted.'
}

$evidenceFullPath = [IO.Path]::GetFullPath($EvidencePath)
$evidenceDirectory = Split-Path -Parent $evidenceFullPath
if ([string]::IsNullOrWhiteSpace($evidenceDirectory)) {
    throw 'INVALID_BENCHMARK_INPUT: evidence output requires an absolute parent directory.'
}
New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null

$cpu = @(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop)
$cpuLoads = @($cpu | Where-Object { $null -ne $_.LoadPercentage } | ForEach-Object {
    [double]$_.LoadPercentage
})
$cpuLoad = if ($cpuLoads.Count -eq 0) {
    100.0
} else {
    ($cpuLoads | Measure-Object -Average).Average
}
$batteries = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)
$powerValid = $batteries.Count -eq 0 -or @(
    $batteries | Where-Object { $_.BatteryStatus -notin @(2, 6, 7, 8, 9, 11) }
).Count -eq 0
$environmentValid = $cpuLoad -le 30.0 -and $powerValid

$startInfo = [Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = [IO.Path]::GetFullPath($BenchmarkPath)
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
foreach ($argument in @(
    '--component-root', [IO.Path]::GetFullPath($ComponentRoot),
    '--warmup', $WarmupSamples.ToString([Globalization.CultureInfo]::InvariantCulture),
    '--samples', $MeasuredSamples.ToString([Globalization.CultureInfo]::InvariantCulture),
    '--filesystem-iterations', $FilesystemIterations.ToString([Globalization.CultureInfo]::InvariantCulture)
)) {
    $startInfo.ArgumentList.Add($argument)
}

$process = [Diagnostics.Process]::new()
$process.StartInfo = $startInfo
$privateBytes = [Collections.Generic.List[long]]::new()
$handles = [Collections.Generic.List[long]]::new()
$threads = [Collections.Generic.List[long]]::new()
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
try {
    if (-not $process.Start()) {
        throw 'BENCHMARK_FAILED: benchmark process did not start.'
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    while (-not $process.WaitForExit(25)) {
        if ([DateTime]::UtcNow -ge $deadline) {
            try {
                $process.Kill($true)
                $process.WaitForExit(5000) | Out-Null
            }
            catch {
                # The scoped benchmark may have exited between the deadline and kill.
            }
            throw 'BENCHMARK_TIMEOUT: benchmark exceeded its bounded deadline.'
        }
        try {
            $process.Refresh()
            $privateBytes.Add([long]$process.PrivateMemorySize64)
            $handles.Add([long]$process.HandleCount)
            $threads.Add([long]$process.Threads.Count)
        }
        catch {
            # Exit can race with a metric refresh; completed output is checked below.
        }
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "BENCHMARK_FAILED: benchmark exited with code $($process.ExitCode)."
    }
    try {
        $benchmark = $stdout | ConvertFrom-Json
    }
    catch {
        throw 'BENCHMARK_FAILED: benchmark output is not valid JSON.'
    }
    if ($benchmark.schemaVersion -ne 1) {
        throw 'BENCHMARK_FAILED: benchmark output schema is unsupported.'
    }
}
finally {
    $process.Dispose()
}

$evidence = [ordered]@{
    schemaVersion = 1
    environmentValid = $environmentValid
    environment = [ordered]@{
        osVersion = [Environment]::OSVersion.VersionString
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        processorCount = [Environment]::ProcessorCount
        cpuLoadPercentBeforeRun = [math]::Round([double]$cpuLoad, 1)
        externalPower = $powerValid
    }
    warmupSamples = [int]$benchmark.warmupSamples
    startupMilliseconds = @($benchmark.startupMilliseconds)
    filesystemControlMilliseconds = @($benchmark.filesystemControlMilliseconds)
    filesystemSandboxMilliseconds = @($benchmark.filesystemSandboxMilliseconds)
    filesystemPathControlMilliseconds = @($benchmark.filesystemPathControlMilliseconds)
    filesystemPathSandboxMilliseconds = @($benchmark.filesystemPathSandboxMilliseconds)
    privateBytes = @($privateBytes)
    handles = @($handles)
    threads = @($threads)
}

$temporaryPath = "$evidenceFullPath.partial-$PID"
try {
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryPath -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporaryPath -Destination $evidenceFullPath -Force
}
finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}
Write-Output 'Performance evidence collected.'
