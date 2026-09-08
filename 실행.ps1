[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$CasePath = (Split-Path -Parent $PSScriptRoot),

    [string]$MemoryPath,

    [switch]$NoMemory,

    [ValidateRange(1, 100)]
    [int]$MaxMemoryHits = 6
)

$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot 'docker_state_identifier.py'
$outputPath = Join-Path $PSScriptRoot '결과'

$pythonCommand = Get-Command 'py' -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $pythonArgs = @('-3', $scriptPath, $CasePath, '--output', $outputPath, '--max-memory-hits', $MaxMemoryHits)
} else {
    $pythonCommand = Get-Command 'python' -ErrorAction Stop
    $pythonArgs = @($scriptPath, $CasePath, '--output', $outputPath, '--max-memory-hits', $MaxMemoryHits)
}

if ($MemoryPath) {
    $pythonArgs += @('--memory', $MemoryPath)
}
if ($NoMemory) {
    $pythonArgs += '--no-memory'
}

& $pythonCommand.Source @pythonArgs
exit $LASTEXITCODE
