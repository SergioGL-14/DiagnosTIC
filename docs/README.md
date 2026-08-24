# DiagnosTIC_UI - PowerShell WPF interface

## Overview

DiagnosTIC_UI is a Windows PowerShell 5.1 WPF application for orchestrating
and presenting local system diagnostics. It runs independent diagnostic
functions in isolated PowerShell jobs, captures text and structured events,
and displays results with causes and recommendations.

Remote mode is intentionally unavailable. Selecting it only reports that
remote transport is not configured; the application does not open a remote
session or run local diagnostic functions against another computer.

## Main features

- Runs diagnostic functions from the `modules/` directory.
- Uses a FIFO queue and isolated jobs so selected diagnostics run sequentially
  without blocking the WPF interface.
- Supports structured `DiagnosticEvent` results with severity, causes, and
  recommendations.
- Displays results incrementally and maintains a technical log.

User-interface labels, diagnostic messages, recommendations, and generated
results are intentionally kept in Spanish. This document translates the
project documentation only; it does not define a localization change.

## Requirements

- Windows with Windows PowerShell 5.1.
- .NET `PresentationFramework`, loaded by `main.ps1`.
- Administrator privileges for checks that require them, including DISM and
  some registry or system queries.

## Repository structure

```text
DiagnosTIC/
|- main.ps1                  Entry point, WPF orchestration, job queue, and result rendering
|- ui/
|  `- main.xaml              WPF interface definition
|- utils/
|  `- Utils.ps1              Shared I/O, event, output, and exception helpers
|- modules/
|  |- Network.ps1            Connectivity, DHCP, adapter, and DNS diagnostics
|  |- Rendimiento.ps1        CPU, memory, process, disk, service, startup, temperature, driver, and WinSAT diagnostics
|  |- Estabilidad.ps1        Critical events, SMART, memory dumps, integrity, restart history, and battery diagnostics
|  `- Seguridad.ps1          Defender, firewall, user-account, and security-update diagnostics
|- tests/
|  `- Static.Tests.ps1       Dependency-free static safety and helper checks
|- docs/
|  `- README.md              Project documentation
`- LICENSE                   Project license
```

Each module exposes public functions named `Diagnostico-<Name>`. The UI maps
the analysis tree to those functions.

## Execution flow

1. `main.ps1` loads `ui/main.xaml` and creates the WPF interface.
2. The user selects analyses and starts a run. Each selected analysis is
   placed in the FIFO queue.
3. The next analysis runs in a separate PowerShell job. The job loads
   `utils/Utils.ps1` and the module scripts, then invokes the selected local
   diagnostic function.
4. Job output is polled incrementally. `DiagnosticEvent` objects become
   enriched result entries; other output is treated as text and added to the
   technical log and results.

## External diagnostic targets

Network checks use default external probe destinations. They can be
overridden with process, user, or machine environment variables:

- `DIAGNOSTIC_EXTERNAL_ICMP`
- `DIAGNOSTIC_EXTERNAL_DNS_TCP`
- `DIAGNOSTIC_EXTERNAL_HTTPS_TCP`

## Diagnosis and repair safety contract

Diagnosis and repair are separate operations. The default UI path performs
diagnostic checks only and never invokes `Reparacion-IntegridadSistema`.
`Diagnostico-IntegridadSistema` runs DISM `/CheckHealth`; it does not run SFC
or repair system files. `Reparacion-IntegridadSistema` is a separate,
modifying function protected by PowerShell `ShouldProcess` confirmation.

This separation is an explicit safety boundary: diagnostic output may contain
recommendations for corrective commands, but recommendations are not executed
by the diagnostic run.

## Structured diagnostic events

Modules can emit a `DiagnosticEvent` through `Write-DiagnosticEvent`. The
minimum useful shape is:

- `Type`: `DiagnosticEvent`
- `Severity`: `Info`, `OK`, `Warning`, or `Error`
- `Message`: main result text
- `Causes`: optional array of strings
- `Recommendations`: optional array of strings

The property names and severity values are implementation contracts and are
not translated. Runtime text remains Spanish.

Minimal example:

```powershell
function Diagnostico-Ejemplo {
    [CmdletBinding()]
    param([string]$equipo)
    try {
        Write-Output "Inicio del diagnóstico de ejemplo..."
        Write-DiagnosticEvent -Severity Info -Message 'Prueba completada' -Component 'Example'
    } catch {
        Write-DiagnosticException -Exception $_ -Severity 'Error' -Component 'Example'
    }
}
```

## Module conventions

- Modules do not interact directly with the WPF interface.
- Use `DiagnosticEvent` for relevant findings and `Write-Output` for trace
  lines.
- Handle errors with `try/catch` and use `Write-DiagnosticException` for
  structured errors.
- Avoid interactive input such as `Read-Host` in functions run by jobs.
- Keep diagnostic functions non-modifying. Any repair operation must be a
  separate function and require confirmation.

## Current scope and limitations

- The application diagnoses the local Windows computer only. Remote mode is
  present in the UI as an explicit unavailable state and performs no remote
  query.
- The application targets Windows PowerShell 5.1 and the WPF
  `PresentationFramework`; PowerShell 7 is outside the current documented
  scope.
- Checks depend on Windows APIs, cmdlets, services, event logs, permissions,
  and hardware capabilities. A missing API or insufficient permission can
  make an individual result unavailable.
- The UI presents results and technical logs but does not provide a documented
  JSON, HTML, or other result-export path.
- The static test script checks parsing, safety boundaries, selected helper
  behavior, and job-queue evidence. It is not a full runtime or hardware
  integration test suite.

## Run the application

From the repository root, open Windows PowerShell 5.1 and run:

```powershell
.\main.ps1
```

If execution policy requires a temporary process-scoped exception:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\main.ps1
```

Run as Administrator when a selected check requires it. Review the selected
modules before running diagnostics in production environments.

## Tests

`tests/Static.Tests.ps1` has no external test-framework dependency. From the
repository root, run the exact command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Static.Tests.ps1
```

The script parses all PowerShell files and verifies the diagnosis-versus-
repair boundary, the unavailable remote path, queued job execution, local
target detection, and configurable external targets.

## Attribution

Galvik.
