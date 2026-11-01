param([Parameter(Mandatory=$true)][ValidateSet('init','up','inspect','reset','down','scan')][string]$Operation,
      [ValidateSet('hardened')][string]$Target, [switch]$Active)
$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $labArgs = @('-m', 'scripts.lab', $Operation)
    if ($Target) { $labArgs += @('--target', $Target) }
    if ($Active) { $labArgs += '--active' }
    & python @labArgs
    if ($LASTEXITCODE -ne 0) { throw 'Aegis operation failed; review the error above.' }
} finally { Pop-Location }
