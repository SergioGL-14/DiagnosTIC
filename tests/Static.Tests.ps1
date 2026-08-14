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
Assert-True ($parseErrors.Count -eq 0) 'todos los scripts PowerShell se pueden parsear'

$main = Get-Content (Join-Path $root 'main.ps1') -Raw
$stability = Get-Content (Join-Path $root 'modules\Estabilidad.ps1') -Raw
Assert-True ($main -match 'TargetMode' -and $main -match 'Write-RemoteDiagnosticUnavailable') 'el modo remoto no ejecuta módulos locales'
$diagnosticBody = [regex]::Match($stability, '(?s)function Diagnostico-IntegridadSistema.*?(?=function Reparacion-IntegridadSistema)').Value
Assert-True ($diagnosticBody -notmatch "Start-Process[^\r\n]*sfc\.exe|sfcFile|-ArgumentList '/scannow'") 'el diagnóstico de integridad no ejecuta reparaciones'
Assert-True ($stability -match 'function Reparacion-IntegridadSistema' -and $stability -match 'ShouldProcess') 'la reparación está separada y requiere confirmación'
Assert-True ($stability -notmatch 'Join-Path \$env:TEMP "(dism_checkhealth|sfc_scan)\.txt"') 'no se usan nombres temporales fijos'
Assert-True ($stability -match '\$boots\.Count -gt 0') 'la proporción de apagados protege la división por cero'

. (Join-Path $root 'utils\Utils.ps1')
Assert-True (Test-IsLocalComputer -ComputerName 'localhost') 'localhost se identifica como destino local'
Assert-True (-not (Test-IsLocalComputer -ComputerName 'equipo-remoto')) 'un destino remoto no se trata como local'
$old = [Environment]::GetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', 'Process')
[Environment]::SetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', '192.0.2.10', 'Process')
try {
    Assert-True ((Get-ExternalDiagnosticTarget -Kind Icmp -Default '8.8.8.8') -eq '192.0.2.10') 'el destino externo se puede configurar'
} finally {
    [Environment]::SetEnvironmentVariable('DIAGNOSTIC_EXTERNAL_ICMP', $old, 'Process')
}

Write-Output 'PASS: diagnóstico por defecto no invoca la función de reparación (comprobado por análisis estático)'
