param(
    [Parameter(Mandatory = $true)]
    [string]$Round2Root,
    [string]$OutputDirectory = ".\output\round2",
    [switch]$IncludeLiveSidecars
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$ResolvedRound2Root = (Resolve-Path -LiteralPath $Round2Root).Path

if (-not (Test-Path -LiteralPath $Python)) {
    throw "가상환경이 없습니다. 먼저 'py -m venv .venv'와 '.\.venv\Scripts\python.exe -m pip install -e .'를 실행하세요."
}

$Arguments = @(
    "-m", "container_state_analyzer",
    "round2",
    "--root", $ResolvedRound2Root,
    "--output-dir", $OutputDirectory
)
if ($IncludeLiveSidecars) {
    $Arguments += "--include-live-sidecars"
}

Push-Location -LiteralPath $ProjectRoot
try {
    & $Python @Arguments
    $ExitCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $ExitCode
