
<#
.SYNOPSIS
  Helpers compartidos para módulos de diagnóstico locales.

.DESCRIPTION
  Centraliza utilidades usadas por los módulos y la interfaz: construcción y emisión de
  eventos estructurados (DiagnosticEvent), helpers de I/O y funciones de normalización
  de salida. Estas utilidades mantienen la consistencia entre módulos y facilitan el
  renderizado por la UI.

  Diseñado para Windows PowerShell 5.1.

.AUTHOR
  Galvik
#>

# -------------------------------------------------------------------------------------------------
# Utilidades generales
# -------------------------------------------------------------------------------------------------

function Wait-ForFile {
    <#
    .SYNOPSIS
      Espera a que un archivo exista hasta agotar el tiempo máximo.
    .PARAMETER FilePath
      Ruta del archivo a comprobar.
    .PARAMETER TimeoutSeconds
      Tiempo máximo de espera en segundos (por defecto 10).
    .OUTPUTS
      [bool] True si el archivo existe al finalizar; False si expira el tiempo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter()]
        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds = 10
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $FilePath) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return (Test-Path -LiteralPath $FilePath)
}

function Get-ObjectPropertyValue {
    <#
    .SYNOPSIS
      Devuelve el valor de una propiedad si existe en un objeto; si no, devuelve $null.
    .PARAMETER InputObject
      Objeto del que leer la propiedad.
    .PARAMETER Name
      Nombre de la propiedad.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $p = $InputObject.PSObject.Properties.Match($Name)
    if ($p -and $p.Count -gt 0) { return $InputObject.$Name }
    return $null
}

function Write-Lines {
    <#
    .SYNOPSIS
      Emite cada línea de un texto multilinea como una salida independiente.
    .DESCRIPTION
      Útil cuando se necesita mantener compatibilidad con consumidores que procesan por líneas.
      No formatea ni colorea; únicamente normaliza saltos de línea.
    .PARAMETER Text
      Texto a descomponer en líneas.
    #>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [string]$Text
    )

    process {
        if ($null -eq $Text) { return }
        $t = $Text -replace "`r`n", "`n" -replace "`r", "`n"
        foreach ($line in ($t -split "`n")) {
            if ($null -ne $line) { Write-Output $line }
        }
    }
}

# -------------------------------------------------------------------------------------------------
# Modelo de eventos estructurados para UI
# -------------------------------------------------------------------------------------------------

function New-DiagnosticEvent {
    <#
    .SYNOPSIS
      Construye un objeto de evento estructurado para diagnósticos (sin emitirlo).
    .DESCRIPTION
      La UI detecta Type='DiagnosticEvent' y renderiza:
        - Message como línea principal
        - Causes como bloque (color naranja en UI)
        - Recommendations como bloque (color azul en UI)

      Este objeto debe ser el único elemento emitido cuando se quiera un "resultado enriquecido".
    .PARAMETER Severity
      Nivel del evento: Info, OK, Warning, Error
    .PARAMETER Message
      Mensaje principal del resultado (se muestra como línea principal en el panel).
    .PARAMETER Title
      Título conceptual del evento (opcional). Si no se especifica, se deriva de Severity.
    .PARAMETER Causes
      Lista de causas habituales (opcional).
    .PARAMETER Recommendations
      Lista de sugerencias/recomendaciones (opcional).
    .PARAMETER Component
      Componente lógico (ej. Network, System, Disk).
    .PARAMETER Subcomponent
      Subcomponente más granular (ej. AdapterStats:Ethernet).
    .PARAMETER Data
      Metadatos adicionales (hashtable) para extensiones futuras.
    .OUTPUTS
      [pscustomobject]
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Info','OK','Warning','Error')]
        [string]$Severity = 'Info',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Title = '',

        [Parameter()]
        [string[]]$Causes = @(),

        [Parameter()]
        [string[]]$Recommendations = @(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Component = 'General',

        [Parameter()]
        [string]$Subcomponent = '',

        [Parameter()]
        [hashtable]$Data = $null
    )

    if ([string]::IsNullOrWhiteSpace($Title)) {
        switch ($Severity) {
            'Error'   { $Title = 'Error detectado' }
            'Warning' { $Title = 'Posible incidencia detectada' }
            'OK'      { $Title = 'Comprobación correcta' }
            default   { $Title = 'Información' }
        }
    }

    # Normalización básica para evitar valores nulos inesperados.
    if ($null -eq $Causes) { $Causes = @() }
    if ($null -eq $Recommendations) { $Recommendations = @() }

    $evt = [PSCustomObject]@{
        Type            = 'DiagnosticEvent'
        Severity        = $Severity
        State           = $Severity     # Compatibilidad con consumidores que usan State
        Title           = $Title
        Message         = $Message
        Component       = $Component
        Subcomponent    = $Subcomponent
        Causes          = $Causes
        Recommendations = $Recommendations
        Timestamp       = (Get-Date)
        Data            = $Data
    }

    return $evt
}

function Write-DiagnosticEvent {
    <#
    .SYNOPSIS
      Emite un evento estructurado de diagnóstico (objeto DiagnosticEvent).
    .DESCRIPTION
      Esta función NO escribe texto adicional ni usa Write-Host.
      El consumidor (UI) será responsable de renderizar el contenido con formato/colores.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateSet('Info','OK','Warning','Error')]
        [string]$Severity = 'Info',

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Title = '',

        [Parameter()]
        [string[]]$Causes = @(),

        [Parameter()]
        [string[]]$Recommendations = @(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Component = 'General',

        [Parameter()]
        [string]$Subcomponent = '',

        [Parameter()]
        [hashtable]$Data = $null
    )

    $evt = New-DiagnosticEvent -Severity $Severity `
                              -Message $Message `
                              -Title $Title `
                              -Causes $Causes `
                              -Recommendations $Recommendations `
                              -Component $Component `
                              -Subcomponent $Subcomponent `
                              -Data $Data

    Write-Output $evt
}

function Write-DiagnosticException {
    <#
    .SYNOPSIS
      Convierte una excepción en un evento DiagnosticEvent de severidad Error o Warning.
    .DESCRIPTION
      Helper para capturar errores en catch y emitir un evento enriquecido.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Exception]$Exception,

        [Parameter()]
        [ValidateSet('Warning','Error')]
        [string]$Severity = 'Error',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Component = 'General',

        [Parameter()]
        [string]$Subcomponent = '',

        [Parameter()]
        [string]$ContextMessage = 'Se produjo una excepción durante el diagnóstico.',

        [Parameter()]
        [string[]]$Causes = @(),

        [Parameter()]
        [string[]]$Recommendations = @()
    )

    $msg = '{0} Detalle: {1}' -f $ContextMessage, $Exception.Message
    Write-DiagnosticEvent -Severity $Severity `
                         -Message $msg `
                         -Title 'Excepción detectada' `
                         -Component $Component `
                         -Subcomponent $Subcomponent `
                         -Causes $Causes `
                         -Recommendations $Recommendations `
                         -Data @{ ExceptionType = $Exception.GetType().FullName }
}

# -------------------------------------------------------------------------------------------------
# Compatibilidad: alias suave con el nombre antiguo
# -------------------------------------------------------------------------------------------------

function Show-DiagnosticSuggestion {
    <#
    .SYNOPSIS
      Alias compatible con versiones previas.
    .DESCRIPTION
      Sustituye la implementación anterior que emitía texto adicional.
      A partir de ahora emite exclusivamente un DiagnosticEvent estructurado.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Info','Warning','Error','OK')]
        [string]$Severity = 'Warning',

        [string]$Title = '',

        [string[]]$Causes = @(),

        [string[]]$Recommendations = @(),

        [switch]$UseColor,  # Se mantiene por compatibilidad, pero no se usa (la UI colorea)

        [string]$ErrorMessage = '',

        [string]$Component = 'General',

        [string]$Subcomponent = ''
    )

    # Mantener compatibilidad con llamadas antiguas:
    # - Si llega ErrorMessage, se usa como Message principal.
    # - Si no, se usa Title como Message; si Title vacío, se deriva por severidad.
    $message = $null
    if (-not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
        $message = $ErrorMessage
    } elseif (-not [string]::IsNullOrWhiteSpace($Title)) {
        $message = $Title
    } else {
        switch ($Severity) {
            'Error'   { $message = 'Se detectó un error.' }
            'Warning' { $message = 'Se detectó una posible incidencia.' }
            'OK'      { $message = 'Comprobación correcta.' }
            default   { $message = 'Información de diagnóstico.' }
        }
    }

    Write-DiagnosticEvent -Severity $Severity `
                         -Message $message `
                         -Title $Title `
                         -Component $Component `
                         -Subcomponent $Subcomponent `
                         -Causes $Causes `
                         -Recommendations $Recommendations
}
