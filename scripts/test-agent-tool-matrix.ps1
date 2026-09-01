[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Configuration,
    [Parameter(Mandatory = $true)]
    [string]$ComponentRoot,
    [string]$SandboxExecutable = '',
    [string[]]$ScenarioId = @(),
    [switch]$RequireAllCapabilities
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$configurationPath = (Resolve-Path -LiteralPath $Configuration).Path
$componentPath = (Resolve-Path -LiteralPath $ComponentRoot).Path
& (Join-Path $PSScriptRoot 'verify-agent-tool-matrix.ps1') -Configuration $configurationPath | Out-Null

if (-not $SandboxExecutable) {
    $SandboxExecutable = Join-Path $repositoryRoot 'target\debug\bolt-sandbox.exe'
}
if (-not (Test-Path -LiteralPath $SandboxExecutable -PathType Leaf)) {
    throw 'Sandbox executable is missing; build the Rust CLI first.'
}
$sandboxPath = (Resolve-Path -LiteralPath $SandboxExecutable).Path
$manifestPath = Join-Path $componentPath 'bolt-sandbox-components.manifest'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Native component manifest is missing.'
}
$manifestDigest = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
$matrix = Get-Content -Raw -LiteralPath $configurationPath | ConvertFrom-Json -Depth 16

$visualStudio = ''
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path -LiteralPath $vswhere -PathType Leaf) {
    $visualStudio = & $vswhere -latest -products * -property installationPath
}

function Resolve-DeclaredToolRoot([string]$CommandName) {
    $overrideName = 'BOLT_TOOL_' + ($CommandName.ToUpperInvariant() -replace '[^A-Z0-9]', '_')
    $candidate = [Environment]::GetEnvironmentVariable($overrideName)
    if (-not $candidate) {
        $command = Get-Command $CommandName -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command) { $candidate = $command.Source }
    }
    if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return ''
    }
    return Split-Path -Parent (Resolve-Path -LiteralPath $candidate).Path
}

$pythonRoot = Resolve-DeclaredToolRoot 'python'
$rustBin = Resolve-DeclaredToolRoot 'cargo'
$rustToolchain = if ($rustBin) { Split-Path -Parent $rustBin } else { '' }
$browserExecutable = [Environment]::GetEnvironmentVariable('BOLT_BROWSER_EXECUTABLE')
if ($browserExecutable -and
    (Test-Path -LiteralPath $browserExecutable -PathType Leaf)) {
    $browserExecutable = (Resolve-Path -LiteralPath $browserExecutable).Path
} else {
    $browserExecutable = ''
}
$browserRoot = if ($browserExecutable) {
    Split-Path -Parent $browserExecutable
} else { '' }
$browserEngine = [Environment]::GetEnvironmentVariable('BOLT_BROWSER_ENGINE')
if ($browserEngine -notin @('chromium', 'firefox', 'webkit')) {
    $browserEngine = ''
}
$baseTokens = @{
    ProgramFiles = $env:ProgramFiles
    ProgramFilesX86 = ${env:ProgramFiles(x86)}
    ProgramData = $env:ProgramData
    SystemRoot = $env:SystemRoot
    UserProfile = $env:USERPROFILE
    LocalAppData = $env:LOCALAPPDATA
    AppData = $env:APPDATA
    VisualStudio = $visualStudio
    PythonRoot = $pythonRoot
    RustToolchain = $rustToolchain
    BrowserExecutable = $browserExecutable
    BrowserRoot = $browserRoot
    BrowserEngine = $browserEngine
    ComponentRoot = $componentPath
}

function Expand-MatrixValue([string]$Value, [hashtable]$Tokens) {
    $expanded = $Value
    foreach ($entry in $Tokens.GetEnumerator()) {
        if ($null -ne $entry.Value) {
            $expanded = $expanded.Replace("{$($entry.Key)}", [string]$entry.Value)
        }
    }
    if ($expanded -match '\{[A-Za-z0-9]+\}') {
        throw "Unresolved matrix token in value: $Value"
    }
    return $expanded
}

function Resolve-ScenarioTool($Scenario, [hashtable]$Tokens) {
    foreach ($commandName in $Scenario.commands) {
        $overrideName = 'BOLT_TOOL_' + ($commandName.ToUpperInvariant() -replace '[^A-Z0-9]', '_')
        $override = [Environment]::GetEnvironmentVariable($overrideName)
        if ($override -and (Test-Path -LiteralPath $override -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $override).Path
        }
    }
    foreach ($candidate in @($Scenario.candidates | Where-Object { $null -ne $_ })) {
        $expanded = Expand-MatrixValue ([string]$candidate) $Tokens
        foreach ($match in @(Resolve-Path -Path $expanded -ErrorAction SilentlyContinue)) {
            if (Test-Path -LiteralPath $match.Path -PathType Leaf) { return $match.Path }
        }
    }
    foreach ($commandName in $Scenario.commands) {
        $command = Get-Command ([string]$commandName) -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command -and $command.Source -and
            (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
            return (Resolve-Path -LiteralPath $command.Source).Path
        }
    }
    return $null
}

function Resolve-CommandTool([string]$CommandName) {
    $overrideName = 'BOLT_TOOL_' + ($CommandName.ToUpperInvariant() -replace '[^A-Z0-9]', '_')
    $override = [Environment]::GetEnvironmentVariable($overrideName)
    if ($override -and (Test-Path -LiteralPath $override -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $override).Path
    }
    $command = Get-Command $CommandName -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($command -and $command.Source -and
        (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $command.Source).Path
    }
    return $null
}

function Assert-SafeRelativePath([string]$Relative, [string]$Label) {
    if (-not $Relative -or [IO.Path]::IsPathFullyQualified($Relative) -or
        $Relative.Contains(':') -or $Relative.Contains([char]0)) {
        throw "$Label must be a safe relative path."
    }
    $parts = $Relative -split '[\\/]'
    if ($parts | Where-Object { -not $_ -or $_ -in @('.', '..') }) {
        throw "$Label contains an unsafe component."
    }
}

function Start-CapturedProcess(
    [string]$FilePath,
    [string[]]$Arguments,
    [hashtable]$Environment,
    [int]$MaximumMilliseconds
) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.CreateNoWindow = $true
    foreach ($argument in $Arguments) { $null = $start.ArgumentList.Add($argument) }
    foreach ($entry in $Environment.GetEnumerator()) {
        $start.Environment[[string]$entry.Key] = [string]$entry.Value
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw "Failed to start $FilePath" }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($MaximumMilliseconds)) {
        $process.Kill($true)
        $process.WaitForExit()
        return [pscustomobject]@{ ExitCode = 124; Stdout = $stdout.Result; Stderr = $stderr.Result }
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdout.Result
        Stderr = $stderr.Result
    }
}

$matrixRoot = Join-Path $repositoryRoot 'target\agent-tool-matrix'
if (Test-Path -LiteralPath $matrixRoot) {
    Remove-Item -LiteralPath $matrixRoot -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $matrixRoot
$sentinel = Join-Path $matrixRoot 'outside-sentinel.txt'
[IO.File]::WriteAllText($sentinel, 'unchanged', [Text.UTF8Encoding]::new($false))
$sentinelHash = (Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash
$passed = 0
$unverified = 0
$failed = [System.Collections.Generic.List[string]]::new()
$availableCapabilities = @($env:BOLT_AGENT_CAPABILITIES -split ',' | Where-Object { $_ })

try {
    foreach ($scenario in $matrix.scenarios) {
        if ($ScenarioId.Count -ne 0 -and $scenario.id -notin $ScenarioId) { continue }
        $missingCapabilities = @($scenario.requiredCapabilities | Where-Object {
            $null -ne $_ -and $_ -notin $availableCapabilities
        })
        if ($missingCapabilities.Count -ne 0) {
            if ($RequireAllCapabilities) {
                Write-Output "FAIL $($scenario.id) capability-unavailable=$($missingCapabilities -join ',')"
                $failed.Add([string]$scenario.id)
            } else {
                Write-Output "UNVERIFIED $($scenario.id) capability-unavailable=$($missingCapabilities -join ',')"
                $unverified++
            }
            continue
        }
        if ($scenario.privileged -eq $true) {
            Write-Output "UNVERIFIED $($scenario.id) privileged-capability"
            $unverified++
            continue
        }
        $tool = Resolve-ScenarioTool $scenario $baseTokens
        if (-not $tool) {
            if ($scenario.requiredOnHost) {
                Write-Output "FAIL $($scenario.id) required-tool-missing"
                $failed.Add([string]$scenario.id)
            } else {
                Write-Output "UNVERIFIED $($scenario.id) tool-missing"
                $unverified++
            }
            continue
        }

        $workspace = Join-Path $matrixRoot "工具 场景-$($scenario.id)"
        $null = New-Item -ItemType Directory -Path $workspace
        foreach ($private in @(
            '.home', '.temp', '.local-app-data', '.app-data', '.registry',
            '.git-template')) {
            $null = New-Item -ItemType Directory -Path (Join-Path $workspace $private)
        }
        foreach ($property in @($scenario.files.PSObject.Properties | Where-Object { $null -ne $_ })) {
            Assert-SafeRelativePath $property.Name "fixture path for $($scenario.id)"
            $destination = Join-Path $workspace $property.Name
            $parent = Split-Path -Parent $destination
            if (-not (Test-Path -LiteralPath $parent)) {
                $null = New-Item -ItemType Directory -Path $parent -Force
            }
            [IO.File]::WriteAllText(
                $destination, [string]$property.Value,
                [Text.UTF8Encoding]::new($false))
        }

        $toolDirectory = Split-Path -Parent $tool
        $toolRoot = Split-Path -Parent $toolDirectory
        $toolParentRoot = Split-Path -Parent $toolRoot
        $tokens = $baseTokens.Clone()
        $tokens.Workspace = $workspace
        $tokens.Tool = $tool
        $tokens.ToolDirectory = $toolDirectory
        $tokens.ToolRoot = $toolRoot
        $tokens.ToolParentRoot = $toolParentRoot
        $arguments = @($scenario.arguments | Where-Object { $null -ne $_ } |
            ForEach-Object { Expand-MatrixValue ([string]$_) $tokens })
        if ($arguments.Count -eq 0 -and
            'arguments' -notin $scenario.PSObject.Properties.Name) {
            $arguments = @('--version')
        }

        $targetProgram = $tool
        $targetArguments = $arguments
        if ($scenario.interpreterCommand) {
            $interpreter = Resolve-CommandTool ([string]$scenario.interpreterCommand)
            if (-not $interpreter) {
                Write-Output "UNVERIFIED $($scenario.id) interpreter-missing=$($scenario.interpreterCommand)"
                $unverified++
                continue
            }
            $entrypoint = Expand-MatrixValue ([string]$scenario.entrypoint) $tokens
            if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
                Write-Output "FAIL $($scenario.id) entrypoint-missing"
                $failed.Add([string]$scenario.id)
                continue
            }
            $targetProgram = $interpreter
            $targetArguments = @((Resolve-Path -LiteralPath $entrypoint).Path) + $arguments
        }
        $extension = [IO.Path]::GetExtension($targetProgram)
        if (-not $scenario.interpreterCommand -and $extension -in @('.cmd', '.bat')) {
            $targetProgram = Join-Path $env:SystemRoot 'System32\cmd.exe'
            $wrapper = Join-Path $workspace '.bolt-tool-wrapper.cmd'
            [IO.File]::WriteAllText(
                $wrapper, "@call `"$tool`" %*`r`n",
                [Text.Encoding]::ASCII)
            $targetArguments = @('/d', '/s', '/c', '.bolt-tool-wrapper.cmd') + $arguments
        } elseif (-not $scenario.interpreterCommand -and $extension -eq '.ps1') {
            $targetProgram = (Get-Command pwsh).Source
            $targetArguments = @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $tool) + $arguments
        }

        $cliArguments = @(
            'run', '--component-root', $componentPath,
            '--manifest-sha256', $manifestDigest,
            '--cwd', $workspace,
            '--timeout-ms', [string]($scenario.timeoutMilliseconds ?? 30000)
        )
        foreach ($root in @($scenario.readOnly | Where-Object { $null -ne $_ })) {
            $expanded = Expand-MatrixValue ([string]$root) $tokens
            if (Test-Path -LiteralPath $expanded) { $cliArguments += @('--read-only', $expanded) }
        }
        foreach ($root in @($scenario.metadataRead | Where-Object { $null -ne $_ })) {
            $expanded = Expand-MatrixValue ([string]$root) $tokens
            if (Test-Path -LiteralPath $expanded) { $cliArguments += @('--metadata-read', $expanded) }
        }
        foreach ($root in @($env:BOLT_SYSTEM_LANGUAGE_ROOTS -split ';' | Where-Object { $_ })) {
            if (Test-Path -LiteralPath $root) { $cliArguments += @('--read-only', $root) }
        }
        foreach ($name in @('ProgramFiles', 'ProgramFiles(x86)', 'ProgramData')) {
            $root = [Environment]::GetEnvironmentVariable($name)
            if ($root -and (Test-Path -LiteralPath $root)) {
                $cliArguments += @('--metadata-read', $root)
            }
        }
        $ancestor = Split-Path -Parent $workspace
        while ($ancestor -and (Split-Path -Parent $ancestor)) {
            $cliArguments += @('--metadata-read', $ancestor)
            $ancestor = Split-Path -Parent $ancestor
        }
        $cliArguments += @(
            '--terminal', [string]$scenario.terminal,
            '--named-pipes', [string]($scenario.namedPipes ?? 'denied'),
            '--network', [string]($scenario.network ?? 'denied'),
            '--', $targetProgram
        )
        $cliArguments += $targetArguments

        $environment = @{
            HOME = (Join-Path $workspace '.home')
            USERPROFILE = (Join-Path $workspace '.home')
            TEMP = (Join-Path $workspace '.temp')
            TMP = (Join-Path $workspace '.temp')
            LOCALAPPDATA = (Join-Path $workspace '.local-app-data')
            APPDATA = (Join-Path $workspace '.app-data')
            XDG_CONFIG_HOME = (Join-Path $workspace '.home')
            GIT_CONFIG_GLOBAL = 'NUL'
            GIT_CONFIG_SYSTEM = 'NUL'
            GIT_TEMPLATE_DIR = (Join-Path $workspace '.git-template')
            GIT_ATTR_NOSYSTEM = '1'
        }
        foreach ($property in @($scenario.environment.PSObject.Properties | Where-Object { $null -ne $_ })) {
            $environment[$property.Name] = Expand-MatrixValue ([string]$property.Value) $tokens
        }
        if ($scenario.privateRegistry -eq $true) {
            $environment.BOLT_SANDBOX_PRIVATE_HKCU =
                Join-Path $workspace '.registry\user.hiv'
        }
        $maximum = [int]($scenario.timeoutMilliseconds ?? 30000) + 10000
        $result = Start-CapturedProcess $sandboxPath $cliArguments $environment $maximum
        $accepted = @($scenario.acceptedExitCodes | Where-Object { $null -ne $_ })
        if ($accepted.Count -eq 0) { $accepted = @(0) }
        $errors = [System.Collections.Generic.List[string]]::new()
        if ($result.ExitCode -notin $accepted) { $errors.Add("exit=$($result.ExitCode)") }
        foreach ($text in @($scenario.stdoutContains | Where-Object { $null -ne $_ })) {
            if (-not $result.Stdout.Contains([string]$text)) { $errors.Add("stdout-missing=$text") }
        }
        foreach ($relative in @($scenario.expectedFiles | Where-Object { $null -ne $_ })) {
            Assert-SafeRelativePath ([string]$relative) "expected path for $($scenario.id)"
            if (-not (Test-Path -LiteralPath (Join-Path $workspace $relative))) {
                $errors.Add("artifact-missing=$relative")
            }
        }
        if ((Get-FileHash -LiteralPath $sentinel -Algorithm SHA256).Hash -ne $sentinelHash) {
            $errors.Add('outside-sentinel-changed')
        }
        if ($errors.Count -eq 0) {
            Write-Output "PASS $($scenario.id)"
            $passed++
        } else {
            Write-Output "FAIL $($scenario.id) $($errors -join ',')"
            if ($result.Stdout) { Write-Output "  stdout: $($result.Stdout.Trim())" }
            if ($result.Stderr) { Write-Output "  stderr: $($result.Stderr.Trim())" }
            $failed.Add([string]$scenario.id)
        }
    }
} finally {
    if ($failed.Count -eq 0 -and (Test-Path -LiteralPath $matrixRoot)) {
        Remove-Item -LiteralPath $matrixRoot -Recurse -Force
    }
}

Write-Output "Agent tool matrix: passed=$passed unverified=$unverified failed=$($failed.Count)"
if ($failed.Count -ne 0) { exit 1 }
