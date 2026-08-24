# Minimal dependency-free checks for the safety boundary between diagnosis and repair.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    Write-Output "PASS: $Message"
}

$parseErrors = @()
foreach ($file in Get-ChildItem $root -Filter *.ps1 -File -Recurse) {
    [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$parseErrors) | Out-Null
}
Assert-True ($parseErrors.Count -eq 0) 'all PowerShell scripts parse successfully'

$main = Get-Content (Join-Path $root 'main.ps1') -Raw
$stability = Get-Content (Join-Path $root 'modules\Estabilidad.ps1') -Raw
Assert-True ($main -match '\$TargetModeInner -eq ''Remoto''' -and $main -match 'Write-RemoteDiagnosticUnavailable') 'remote mode never executes local modules'
$diagnosticBody = [regex]::Match($stability, '(?s)function Diagnostico-IntegridadSistema.*?(?=function Reparacion-IntegridadSistema)').Value
Assert-True ($diagnosticBody -notmatch "Start-Process[^\r\n]*sfc\.exe|sfcFile|-ArgumentList '/scannow'") 'integrity diagnosis does not execute repairs'
Assert-True ($stability -match 'function Reparacion-IntegridadSistema' -and $stability -match 'ShouldProcess') 'repair is separate and requires confirmation'
Assert-True ($stability -notmatch 'Join-Path \$env:TEMP "(dism_checkhealth|sfc_scan)\.txt"') 'temporary output names are not fixed'
Assert-True ($stability -match '\$boots\.Count -gt 0') 'shutdown ratio guards against division by zero'
Assert-True ($main -notmatch 'Reparacion-IntegridadSistema') 'the UI does not invoke the repair function'
Assert-True ($main -match 'Start-Job -ScriptBlock' -and $main -match 'JobQueue') 'diagnostics run through the queued job boundary'

. (Join-Path $root 'utils\Utils.ps1')
Assert-True (Test-IsLocalComputer -ComputerName 'localhost') 'localhost is identified as local'
Assert-True (-not (Test-IsLocalComputer -ComputerName 'equipo-remoto')) 'a remote target is not treated as local'
$old = [Environment]::GetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', 'Process')
[Environment]::SetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', '192.0.2.10', 'Process')
try {
    Assert-True ((Get-ExternalDiagnosticTarget -Kind Icmp -Default '8.8.8.8') -eq '192.0.2.10') 'external diagnostic targets are configurable'
} finally {
    [Environment]::SetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', $old, 'Process')
}

Write-Output 'PASS: default diagnosis does not invoke repair (static evidence)'
