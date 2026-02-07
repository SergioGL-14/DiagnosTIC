#Requires -Version 5.1
Add-Type -AssemblyName PresentationFramework

# DiagnosTIC UI — Interfaz WPF en PowerShell
# Gestiona la carga de la interfaz, la encolación y la ejecución secuencial
# de diagnósticos locales en jobs aislados.
# Author: Galvik

# -------------------------------------------------------------------------------------------------
# Configuración y carga de UI (WPF)
# -------------------------------------------------------------------------------------------------

$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Cargar XAML desde archivo externo (ui\main.xaml)
$script:XamlPath = Join-Path $script:ScriptRoot 'ui\main.xaml'
if (-not (Test-Path $script:XamlPath)) { Throw "XAML no encontrado: $script:XamlPath" }
$script:Xaml = Get-Content -Raw -Encoding UTF8 -Path $script:XamlPath

[xml]$xml = $script:Xaml
$reader = New-Object System.Xml.XmlNodeReader $xml
$script:Window = [Windows.Markup.XamlReader]::Load($reader)

function Get-UiElement {
    param([Parameter(Mandatory = $true)][string]$Name)
    $script:Window.FindName($Name)
}

# UI Elements
$txtEquipo         = Get-UiElement 'txtEquipo'
$treeAnalisis      = Get-UiElement 'treeAnalisis'
$btnRun            = Get-UiElement 'btnRun'
$btnClear          = Get-UiElement 'btnClear'
$btnToggleLog      = Get-UiElement 'btnToggleLog'
$txtLog            = Get-UiElement 'txtLog'
$borderLog         = Get-UiElement 'borderLog'
$gridRight         = Get-UiElement 'gridRight'
$rtbResults        = Get-UiElement 'rtbResults'
$txtStatsOK        = Get-UiElement 'txtStatsOK'
$txtStatsWarning   = Get-UiElement 'txtStatsWarning'
$txtStatsError     = Get-UiElement 'txtStatsError'
$borderStatOK      = Get-UiElement 'borderStatOK'
$borderStatWarning = Get-UiElement 'borderStatWarning'
$borderStatError   = Get-UiElement 'borderStatError'
$txtFilterStatus   = Get-UiElement 'txtFilterStatus'

# Inicializar el campo 'Equipo' con el nombre del equipo local
$txtEquipo.Text = [System.Environment]::MachineName

# -------------------------------------------------------------------------------------------------
# Estado
# -------------------------------------------------------------------------------------------------

# Nota: Hashtable nativo (PowerShell 5.1) — soporta ContainsKey
$script:Stats = @{ OK = 0; Warning = 0; Error = 0; Info = 0 }
$script:AllResults = New-Object System.Collections.ArrayList
$script:CurrentFilter = 'All'
$script:CurrentRenderedAnalysis = $null
$script:LogExpanded = $true

# Jobs
$script:JobLabels = @{}
$script:JobProcessedCounts = @{}
$script:PollingTimer = $null

# Cola FIFO para ejecución secuencial de análisis (evita concurrencia excesiva)
$script:JobQueue = New-Object System.Collections.Queue

function Enqueue-AnalysisJob {
    param(
        [Parameter(Mandatory = $true)][string]$FuncName,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Equipo
    )
    $script:JobQueue.Enqueue(@{ Func = $FuncName; Label = $Label; Equipo = $Equipo })
}

function Try-StartNextJob {
    # Solo iniciar si no hay jobs en ejecución
    if ($script:JobLabels.Count -gt 0) { return }
    if ($script:JobQueue.Count -gt 0) {
        $task = $script:JobQueue.Dequeue()
        Append-TechLog ("▶️ Iniciando siguiente en cola: {0}" -f $task.Label)
        Start-AnalysisJob -FuncName $task.Func -Label $task.Label -Equipo $task.Equipo
    }
}

# Caché de brushes
$script:BrushCache = @{}
function Get-Brush {
    param([Parameter(Mandatory = $true)][string]$Color)
    if (-not $script:BrushCache.ContainsKey($Color)) {
        $script:BrushCache[$Color] = ([Windows.Media.BrushConverter]::new()).ConvertFromString($Color)
    }
    return $script:BrushCache[$Color]
}

# -------------------------------------------------------------------------------------------------
# Utilidades UI
# -------------------------------------------------------------------------------------------------

function Invoke-Ui {
    param([Parameter(Mandatory = $true)][scriptblock]$Action)
    $script:Window.Dispatcher.Invoke([action]$Action)
}

function Append-TechLog {
    param([Parameter(Mandatory = $true)][string]$Text)
    Invoke-Ui {
        $txtLog.AppendText(("{0} | {1}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $Text))
        $txtLog.ScrollToEnd()
    }
}

function Update-StatsUi {
    Invoke-Ui {
        $txtStatsOK.Text      = [string]$script:Stats.OK
        $txtStatsWarning.Text = [string]$script:Stats.Warning
        $txtStatsError.Text   = [string]$script:Stats.Error
    }
}

function Update-FilterUi {
    Invoke-Ui {
        switch ($script:CurrentFilter) {
            'All'     { $txtFilterStatus.Text = 'Mostrando: Todos los resultados' }
            'OK'      { $txtFilterStatus.Text = 'Mostrando: Solo resultados OK ✅' }
            'Warning' { $txtFilterStatus.Text = 'Mostrando: Solo avisos ⚠️' }
            'Error'   { $txtFilterStatus.Text = 'Mostrando: Solo errores ❌' }
        }
    }
}

function Clear-Results {
    Invoke-Ui {
        $rtbResults.Document.Blocks.Clear()
        $txtLog.Clear()
    }

    $script:Stats = @{ OK = 0; Warning = 0; Error = 0; Info = 0 }
    [void]$script:AllResults.Clear()
    $script:CurrentFilter = 'All'
    $script:CurrentRenderedAnalysis = $null

    Update-StatsUi
    Update-FilterUi
}

# -------------------------------------------------------------------------------------------------
# Normalización / clasificación
# -------------------------------------------------------------------------------------------------

function Normalize-TextLine {
    param([AllowNull()][string]$Text)

    if ($null -eq $Text) { return $null }

    $t = [string]$Text
    $t = $t -replace "`r`n", "`n" -replace "`r", "`n"

    # Quitar BOM, invisibles y caracteres de control
    $t = $t -replace '[\uFEFF\uFFFC\u200B\u200C\u200D\u200E\u200F]', ''
    $t = $t -replace '\uFFFD', ''             # replacement char
    $t = $t -replace '[\x00-\x1F\x7F]', ''    # control chars
    $t = $t.Trim()

    if ([string]::IsNullOrWhiteSpace($t)) { return $null }

    # Ignorar líneas basura (p.ej. solo un caracter "raro")
    if ($t.Length -le 2 -and ($t -notmatch '[A-Za-z0-9✅❌⚠️]')) { return $null }
    if ($t -match '^[�\s]+$') { return $null }

    return $t
}

function Get-LevelFromText {
    param([Parameter(Mandatory = $true)][string]$Line)

    if ($Line -match '(^|[\s])❌|ERROR\b|Error\b') { return 'Error' }
    if ($Line -match '(^|[\s])⚠️|WARN\b|Warning\b') { return 'Warning' }
    if ($Line -match '(^|[\s])✅') { return 'OK' }
    return 'Info'
}

function ConvertTo-Level {
    param([AllowNull()][string]$Value)

    switch ($Value) {
        'OK'      { 'OK' }
        'Warning' { 'Warning' }
        'Error'   { 'Error' }
        'Info'    { 'Info' }
        default   { 'Info' }
    }
}

function Ensure-StringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [System.Array]) { return @($Value | ForEach-Object { [string]$_ }) }
    return @([string]$Value)
}

function New-ResultItem {
    param(
        [Parameter(Mandatory = $true)][string]$Analysis,
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $true)][string]$Level,
        [string]$Component = '',
        [string]$Subcomponent = '',
        [string[]]$Causes = @(),
        [string[]]$Recommendations = @(),
        $RawObject = $null
    )

    [pscustomobject]@{
        Analysis         = $Analysis
        Level            = $Level
        Message          = $Message
        Component        = $Component
        Subcomponent     = $Subcomponent
        Causes           = $Causes
        Recommendations  = $Recommendations
        RawObject        = $RawObject
        Timestamp        = (Get-Date)
    }
}

# -------------------------------------------------------------------------------------------------
# Renderizado (RichTextBox)
# -------------------------------------------------------------------------------------------------

function Add-Separator {
    $para = New-Object Windows.Documents.Paragraph
    $para.Margin = [Windows.Thickness]::new(0,16,0,16)

    $run = New-Object Windows.Documents.Run
    $run.Text = ('━' * 74)
    $run.Foreground = Get-Brush '#E0E0E0'

    [void]$para.Inlines.Add($run)
    [void]$rtbResults.Document.Blocks.Add($para)
}

function Add-AnalysisHeader {
    param([Parameter(Mandatory = $true)][string]$Analysis)

    if ($rtbResults.Document.Blocks.Count -gt 0) { Add-Separator }

    $titlePara = New-Object Windows.Documents.Paragraph
    $titlePara.Margin = [Windows.Thickness]::new(0,8,0,12)

    $titleRun = New-Object Windows.Documents.Run
    $titleRun.Text = "▶ $Analysis"
    $titleRun.FontWeight = 'Bold'
    $titleRun.FontSize = 15
    $titleRun.Foreground = Get-Brush '#1976D2'

    [void]$titlePara.Inlines.Add($titleRun)
    [void]$rtbResults.Document.Blocks.Add($titlePara)

    $script:CurrentRenderedAnalysis = $Analysis
}

function Add-ResultLine {
    param([Parameter(Mandatory = $true)][psobject]$Item)

    if ($script:CurrentRenderedAnalysis -ne $Item.Analysis) {
        Add-AnalysisHeader -Analysis $Item.Analysis
    }

    $para = New-Object Windows.Documents.Paragraph
    $para.Margin = [Windows.Thickness]::new(12,2,0,2)

    $run = New-Object Windows.Documents.Run
    $run.Text = $Item.Message

    switch ($Item.Level) {
        'OK' {
            $run.Foreground = Get-Brush '#2E7D32'
            $run.FontWeight = 'SemiBold'
        }
        'Warning' {
            $run.Foreground = Get-Brush '#F57C00'
            $run.FontWeight = 'SemiBold'
            $run.Background = Get-Brush '#FFF3E0'
        }
        'Error' {
            $run.Foreground = Get-Brush '#C62828'
            $run.FontWeight = 'Bold'
            $run.Background = Get-Brush '#FFEBEE'
        }
        default {
            $run.Foreground = Get-Brush '#424242'
        }
    }

    [void]$para.Inlines.Add($run)
    [void]$rtbResults.Document.Blocks.Add($para)

    # Causas (naranja)
    if ($Item.Causes -and $Item.Causes.Count -gt 0) {
        $hPara = New-Object Windows.Documents.Paragraph
        $hPara.Margin = [Windows.Thickness]::new(24,2,0,0)

        $hRun = New-Object Windows.Documents.Run
        $hRun.Text = "• Causas habituales:"
        $hRun.Foreground = Get-Brush '#F57C00'
        $hRun.FontWeight = 'SemiBold'

        [void]$hPara.Inlines.Add($hRun)
        [void]$rtbResults.Document.Blocks.Add($hPara)

        foreach ($c in $Item.Causes) {
            if ([string]::IsNullOrWhiteSpace($c)) { continue }
            $cPara = New-Object Windows.Documents.Paragraph
            $cPara.Margin = [Windows.Thickness]::new(36,0,0,0)

            $cRun = New-Object Windows.Documents.Run
            $cRun.Text = "- $c"
            $cRun.Foreground = Get-Brush '#F57C00'

            [void]$cPara.Inlines.Add($cRun)
            [void]$rtbResults.Document.Blocks.Add($cPara)
        }
    }

    # Recomendaciones (azul)
    if ($Item.Recommendations -and $Item.Recommendations.Count -gt 0) {
        $hPara = New-Object Windows.Documents.Paragraph
        $hPara.Margin = [Windows.Thickness]::new(24,4,0,0)

        $hRun = New-Object Windows.Documents.Run
        $hRun.Text = "• Sugerencias:"
        $hRun.Foreground = Get-Brush '#1976D2'
        $hRun.FontWeight = 'SemiBold'

        [void]$hPara.Inlines.Add($hRun)
        [void]$rtbResults.Document.Blocks.Add($hPara)

        foreach ($r in $Item.Recommendations) {
            if ([string]::IsNullOrWhiteSpace($r)) { continue }
            $rPara = New-Object Windows.Documents.Paragraph
            $rPara.Margin = [Windows.Thickness]::new(36,0,0,0)

            $rRun = New-Object Windows.Documents.Run
            $rRun.Text = "- $r"
            $rRun.Foreground = Get-Brush '#1976D2'

            [void]$rPara.Inlines.Add($rRun)
            [void]$rtbResults.Document.Blocks.Add($rPara)
        }
    }
}

function Render-Results {
    Invoke-Ui {
        $rtbResults.Document.Blocks.Clear()
        $script:CurrentRenderedAnalysis = $null
        Update-FilterUi

        $items = if ($script:CurrentFilter -eq 'All') {
            $script:AllResults
        } else {
            $script:AllResults | Where-Object { $_.Level -eq $script:CurrentFilter }
        }

        foreach ($it in $items) { Add-ResultLine -Item $it }
        $rtbResults.ScrollToEnd()
    }
}

function Add-ResultToStateAndUi {
    param(
        [Parameter(Mandatory = $true)][psobject]$Item,
        [switch]$RenderIncremental
    )

    if (-not $script:Stats.ContainsKey($Item.Level)) { $script:Stats[$Item.Level] = 0 }
    $script:Stats[$Item.Level]++
    Update-StatsUi

    [void]$script:AllResults.Add($Item)

    if ($RenderIncremental -and ($script:CurrentFilter -eq 'All' -or $script:CurrentFilter -eq $Item.Level)) {
        Invoke-Ui {
            Add-ResultLine -Item $Item
            $rtbResults.ScrollToEnd()
        }
    }
}

# -------------------------------------------------------------------------------------------------
# Árbol de análisis
# Definición de grupos y entradas; cada elemento referencia una función con prefijo 'Diagnostico-'
# -------------------------------------------------------------------------------------------------

$script:TreeDefinition = @(
    @{ Header='Diagnóstico de Red'; Items=@(
        @{ Header='Conectividad';     Func='Diagnostico-Conectividad' },
        @{ Header='DHCP';             Func='Diagnostico-DHCP' },
        @{ Header='Adaptador de red'; Func='Diagnostico-AdaptadorRed' },
        @{ Header='DNS';              Func='Diagnostico-DNS' }
    )},
    @{ Header='Rendimiento del Sistema'; Items=@(
        @{ Header='Uso de CPU/RAM';              Func='Diagnostico-Rendimiento' },
        @{ Header='Procesos activos';            Func='Diagnostico-ProcesosActivos' },
        @{ Header='Espacio en disco';            Func='Diagnostico-EspacioDisco' },
        @{ Header='Servicios críticos';          Func='Diagnostico-ServiciosCriticos' },
        @{ Header='Tiempo de arranque';          Func='Diagnostico-TiempoArranque' },
        @{ Header='Temperatura del sistema';     Func='Diagnostico-Temperatura' },
        @{ Header='Drivers y actualizaciones';   Func='Diagnostico-DriversActualizaciones' },
        @{ Header='Índice de rendimiento';       Func='Diagnostico-IndiceRendimiento' }
    )},
    @{ Header='Estabilidad del Sistema'; Items=@(
        @{ Header='Eventos críticos';            Func='Diagnostico-EventosCriticos' },
        @{ Header='Estado SMART de discos';      Func='Diagnostico-DiscoSMART' },
        @{ Header='Dumps de memoria (BSOD)';     Func='Diagnostico-DumpsMemoria' },
        @{ Header='Integridad del sistema';      Func='Diagnostico-IntegridadSistema' },
        @{ Header='Historial de reinicios';      Func='Diagnostico-HistorialReinicios' },
        @{ Header='Estado de batería';           Func='Diagnostico-EstadoBateria' }
    )},
    @{ Header='Seguridad del Sistema'; Items=@(
        @{ Header='Windows Defender';            Func='Diagnostico-WindowsDefender' },
        @{ Header='Firewall de Windows';         Func='Diagnostico-Firewall' },
        @{ Header='Cuentas de usuario';          Func='Diagnostico-CuentasUsuario' },
        @{ Header='Actualizaciones de seguridad'; Func='Diagnostico-ActualizacionesSeguridad' }
    )}
)

function New-CheckTreeItem {
    param([Parameter(Mandatory = $true)][string]$Text, [Parameter()][string]$Func)

    $chk = New-Object System.Windows.Controls.CheckBox
    $chk.Content = $Text
    $chk.FontSize = 13
    if ($Func) { $chk.Tag = $Func }

    $tvi = New-Object System.Windows.Controls.TreeViewItem
    $tvi.Header = $chk
    return $tvi
}

function Update-ParentCheckState {
    param([Parameter(Mandatory = $true)]$ParentTvi)
    Invoke-Ui {
        $parentChk = $ParentTvi.Header
        $count = $ParentTvi.Items.Count
        if ($count -eq 0) { $parentChk.IsChecked = $false; return }
        $checked = 0
        foreach ($it in $ParentTvi.Items) {
            if ($it.Header.IsChecked) { $checked++ }
        }
        if ($checked -eq 0)         { $parentChk.IsChecked = $false }
        elseif ($checked -eq $count){ $parentChk.IsChecked = $true }
        else                        { $parentChk.IsChecked = $null } # indeterminado
    }
}

foreach ($group in $script:TreeDefinition) {
    $parent = New-Object System.Windows.Controls.TreeViewItem
    $parentChk = New-Object System.Windows.Controls.CheckBox
    $parentChk.Content = $group.Header
    $parentChk.FontWeight = 'Bold'
    $parentChk.FontSize = 13
    $parentChk.IsThreeState = $true   # permitir estado indeterminado
    $parent.Header = $parentChk

    foreach ($sub in $group.Items) {
        [void]$parent.Items.Add((New-CheckTreeItem -Text $sub.Header -Func $sub.Func))
    }

    # Capturar el padre en una variable local por iteración para evitar que las closures compartan
    $localParent = $parent
    $lp = $localParent

    # Usar GetNewClosure() para fijar la referencia actual de $lp en el scriptblock
    $parentChk.Add_Checked(( { foreach ($it in $lp.Items) { $it.Header.IsChecked = $true } } ).GetNewClosure())
    $parentChk.Add_Unchecked(( { foreach ($it in $lp.Items) { $it.Header.IsChecked = $false } } ).GetNewClosure())

    # Cuando un hijo cambia, actualizar el estado del padre (capturamos $lp por hijo)
    foreach ($child in $parent.Items) {
        $cb = $child.Header
        $childParent = $lp
        $cb.Add_Checked(( { Update-ParentCheckState $childParent } ).GetNewClosure())
        $cb.Add_Unchecked(( { Update-ParentCheckState $childParent } ).GetNewClosure())
    }

    [void]$treeAnalisis.Items.Add($parent)
}

function Get-SelectedAnalyses {
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($parent in $treeAnalisis.Items) {
        foreach ($child in $parent.Items) {
            $cb = $child.Header
            if ($cb.IsChecked) {
                [void]$list.Add([pscustomobject]@{ Label = [string]$cb.Content; Func = [string]$cb.Tag })
            }
        }
    }
    return $list
}

# -------------------------------------------------------------------------------------------------
# Jobs y polling
# -------------------------------------------------------------------------------------------------

function Start-AnalysisJob {
    param(
        [Parameter(Mandatory = $true)][string]$FuncName,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Equipo
    )

    $moduleDir = Join-Path $script:ScriptRoot 'modules'
    $utilsPath = Join-Path $script:ScriptRoot 'utils\Utils.ps1'

    $jobScript = {
        param($ModuleDirInner, $UtilsPathInner, $FuncInner, $EquipoInner)

        try {
            # Ajuste de encoding para salida de comandos nativos en PS 5.1 (OEM)
            try {
                $oemCp = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage
                $oemEnc = [System.Text.Encoding]::GetEncoding($oemCp)
                $global:OutputEncoding = $oemEnc
                [Console]::OutputEncoding = $oemEnc
            } catch { }

            # Cargar Utils.ps1 primero (los módulos lo necesitan)
            if (Test-Path $UtilsPathInner) {
                try {
                    . $UtilsPathInner
                } catch {
                    Write-Output ("⚠️ Error cargando Utils.ps1: {0}" -f $_.Exception.Message)
                }
            }

            # Cargar módulos
            Get-ChildItem -Path $ModuleDirInner -Filter *.ps1 -File -ErrorAction SilentlyContinue |
                ForEach-Object { 
                    try {
                        $modulePath = $_.FullName
                        
                        # Leer el contenido del módulo con codificación UTF-8
                        $moduleContent = Get-Content -Path $modulePath -Raw -Encoding UTF8
                        
                        # Reemplazar la línea que carga Utils.ps1 con la ruta absoluta
                        # Escapar comillas simples en la ruta
                        $utilsPathEscaped = $UtilsPathInner -replace "'", "''"
                        $moduleContent = $moduleContent -replace 
                            '\.\s*"\$PSScriptRoot\\\.\.\\utils\\Utils\.ps1"',
                            ". '$utilsPathEscaped'"
                        
                        # Ejecutar el módulo modificado en el scope actual usando el operador de punto
                        # Esto hace que las funciones se definan en el scope del job
                        $moduleScript = [scriptblock]::Create($moduleContent)
                        . $moduleScript
                    } catch {
                        Write-Output ("⚠️ Error cargando módulo $($_.Name): {0}" -f $_.Exception.Message)
                        Write-Output ("   Detalle: {0}" -f $_.Exception.StackTrace)
                    }
                }

            $cmd = Get-Command -Name $FuncInner -CommandType Function -ErrorAction SilentlyContinue
            if ($cmd) {
                # Ejecutar directamente - Write-Output en jobs se captura progresivamente
                # Redirigir errores a stdout para capturarlos también
                $ErrorActionPreference = 'Continue'
                try {
                    & $cmd -equipo $EquipoInner 2>&1 | ForEach-Object {
                        if ($_ -is [System.Management.Automation.ErrorRecord]) {
                            Write-Output ("❌ Error: {0}" -f $_.Exception.Message)
                        } else {
                            Write-Output $_
                        }
                    }
                } catch {
                    Write-Output ("❌ Error ejecutando {0}: {1}" -f $FuncInner, $_.Exception.Message)
                }
            } else {
                Write-Output ("❌ Función no encontrada: {0}" -f $FuncInner)
            }
        } catch {
            Write-Output ("❌ ERROR_JOB: {0}" -f $_.Exception.Message)
            Write-Output ("   Stack: {0}" -f $_.ScriptStackTrace)
        }
    }

    $job = Start-Job -ScriptBlock $jobScript -ArgumentList $moduleDir, $utilsPath, $FuncName, $Equipo
    $script:JobLabels[$job.Id] = $Label
    $script:JobProcessedCounts[$job.Id] = 0
    Append-TechLog ("🚀 Job iniciado: {0} (ID: {1})" -f $Label, $job.Id)
}

function Is-DiagnosticEvent {
    param($Obj)
    if ($null -eq $Obj) { return $false }
    if ($Obj -isnot [psobject]) { return $false }
    return ($Obj.PSObject.Properties.Match('Type').Count -gt 0 -and [string]$Obj.Type -eq 'DiagnosticEvent')
}

function Get-DiagnosticLevelFromEvent {
    param([Parameter(Mandatory = $true)][psobject]$Evt)

    $state = $null
    if ($Evt.PSObject.Properties.Match('State').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$Evt.State)) {
        $state = [string]$Evt.State
    } elseif ($Evt.PSObject.Properties.Match('Severity').Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$Evt.Severity)) {
        $state = [string]$Evt.Severity
    }

    ConvertTo-Level $state
}

function Process-JobOutputItem {
    param([Parameter(Mandatory = $true)][string]$AnalysisLabel, [Parameter(Mandatory = $true)]$Obj)

    if ($null -eq $Obj) { return }

    # Verificar si es un DiagnosticEvent
    if (Is-DiagnosticEvent $Obj) {
        $lvl = Get-DiagnosticLevelFromEvent $Obj

        $msg = $null
        if ($Obj.PSObject.Properties.Match('Message').Count -gt 0) {
            $msg = Normalize-TextLine ([string]$Obj.Message)
        }
        if (-not $msg) { return }

        $component = if ($Obj.PSObject.Properties.Match('Component').Count -gt 0) { [string]$Obj.Component } else { '' }
        $subcomp   = if ($Obj.PSObject.Properties.Match('Subcomponent').Count -gt 0) { [string]$Obj.Subcomponent } else { '' }

        $causes = @()
        $recs   = @()
        if ($Obj.PSObject.Properties.Match('Causes').Count -gt 0) { $causes = Ensure-StringArray $Obj.Causes }
        if ($Obj.PSObject.Properties.Match('Recommendations').Count -gt 0) { $recs = Ensure-StringArray $Obj.Recommendations }

        $item = New-ResultItem -Analysis $AnalysisLabel -Message $msg -Level $lvl -Component $component -Subcomponent $subcomp -Causes $causes -Recommendations $recs -RawObject $Obj
        Add-ResultToStateAndUi -Item $item -RenderIncremental
        return
    }

    # Convertir a string y procesar línea por línea
    try {
        $s = [string]$Obj
        if ([string]::IsNullOrWhiteSpace($s)) { return }
        
        $s = $s -replace "`r`n", "`n" -replace "`r", "`n"
        $lines = $s -split "`n"
        
        foreach ($line in $lines) {
            $ln = Normalize-TextLine $line
            if (-not $ln) { continue }
            
            Append-TechLog ("[{0}] {1}" -f $AnalysisLabel, $ln)

            $lvl = Get-LevelFromText $ln
            $item = New-ResultItem -Analysis $AnalysisLabel -Message $ln -Level $lvl
            Add-ResultToStateAndUi -Item $item -RenderIncremental
        }
    } catch {
        # Si hay error al procesar, al menos intentar mostrar algo
        $errMsg = "Error procesando salida: $($_.Exception.Message)"
        Append-TechLog ("[{0}] ⚠️ {1}" -f $AnalysisLabel, $errMsg)
    }
}

function Ensure-PollingTimer {
    if ($script:PollingTimer) { return }

    $script:PollingTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:PollingTimer.Interval = [TimeSpan]::FromMilliseconds(100)  # Muy frecuente para captura progresiva

    $script:PollingTimer.Add_Tick({
        foreach ($jid in @($script:JobLabels.Keys)) {
            $job = Get-Job -Id $jid -ErrorAction SilentlyContinue
            if (-not $job) {
                $script:JobLabels.Remove($jid)
                $script:JobProcessedCounts.Remove($jid)
                continue
            }

            $label = $script:JobLabels[$jid]
            
            # Capturar salida progresivamente (incluye errores redirigidos con 2>&1)
            $out = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
            
            # Procesar salida normal
            $items = @()
            if ($null -ne $out) {
                # Asegurar que sea un array
                if ($out -is [System.Array]) {
                    $items = $out
                } else {
                    $items = @($out)
                }
            }

            $prev = if ($script:JobProcessedCounts.ContainsKey($jid)) { [int]$script:JobProcessedCounts[$jid] } else { 0 }
            
            # Procesar solo los items nuevos (progresivamente)
            if ($items.Count -gt $prev) {
                for ($i = $prev; $i -lt $items.Count; $i++) {
                    $item = $items[$i]
                    if ($null -ne $item) {
                        try {
                            Process-JobOutputItem -AnalysisLabel $label -Obj $item
                        } catch {
                            # Si hay error procesando un item, al menos intentar mostrar algo
                            $itemStr = try { [string]$item } catch { "Objeto no serializable" }
                            if (-not [string]::IsNullOrWhiteSpace($itemStr)) {
                                Append-TechLog ("[{0}] {1}" -f $label, $itemStr.Substring(0, [Math]::Min(200, $itemStr.Length)))
                            }
                        }
                    }
                }
                $script:JobProcessedCounts[$jid] = $items.Count
            }

            # Si el job terminó, hacer una última verificación para capturar cualquier salida restante
            if ($job.State -ne 'Running') {
                # Hacer una última captura con -Keep para ver si hay algo nuevo
                # (el polling anterior ya procesó todo progresivamente)
                $finalCheck = Receive-Job -Job $job -Keep -ErrorAction SilentlyContinue
                if ($finalCheck) {
                    $finalItems = if ($finalCheck -is [System.Array]) { $finalCheck } else { @($finalCheck) }
                    $alreadyProcessed = if ($script:JobProcessedCounts.ContainsKey($jid)) { [int]$script:JobProcessedCounts[$jid] } else { 0 }
                    
                    # Solo procesar items que no se hayan procesado ya
                    if ($finalItems.Count -gt $alreadyProcessed) {
                        for ($i = $alreadyProcessed; $i -lt $finalItems.Count; $i++) {
                            $item = $finalItems[$i]
                            if ($null -ne $item) {
                                Process-JobOutputItem -AnalysisLabel $label -Obj $item
                            }
                        }
                        $script:JobProcessedCounts[$jid] = $finalItems.Count
                    }
                }
                
                Append-TechLog ("✅ Análisis completado: {0}" -f $label)
                $script:JobLabels.Remove($jid)
                $script:JobProcessedCounts.Remove($jid)
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

                # Intentar iniciar siguiente en cola (si hay)
                Try-StartNextJob
            }
        }
    })

    $script:PollingTimer.Start()
    Append-TechLog '🔁 Sistema de polling iniciado.'
}

# -------------------------------------------------------------------------------------------------
# Eventos UI
# -------------------------------------------------------------------------------------------------

$btnToggleLog.Add_Click({
    Invoke-Ui {
        if ($script:LogExpanded) {
            $gridRight.RowDefinitions[3].Height = [System.Windows.GridLength]::new(40)
            $borderLog.Visibility = 'Collapsed'
            $btnToggleLog.Content = '⬆️ Expandir'
            $script:LogExpanded = $false
        } else {
            $gridRight.RowDefinitions[3].Height = [System.Windows.GridLength]::new(180)
            $borderLog.Visibility = 'Visible'
            $btnToggleLog.Content = '⬇️ Contraer'
            $script:LogExpanded = $true
        }
    }
})

$btnClear.Add_Click({
    Clear-Results
})

$borderStatOK.Add_MouseDown({
    $script:CurrentFilter = if ($script:CurrentFilter -eq 'OK') { 'All' } else { 'OK' }
    Render-Results
})

$borderStatWarning.Add_MouseDown({
    $script:CurrentFilter = if ($script:CurrentFilter -eq 'Warning') { 'All' } else { 'Warning' }
    Render-Results
})

$borderStatError.Add_MouseDown({
    $script:CurrentFilter = if ($script:CurrentFilter -eq 'Error') { 'All' } else { 'Error' }
    Render-Results
})

$btnRun.Add_Click({
    $selected = Get-SelectedAnalyses
    if (-not $selected -or $selected.Count -eq 0) {
        Append-TechLog '⚠️ No se seleccionó ningún análisis.'
        return
    }

    $equipo = ($txtEquipo.Text).Trim()
    if (-not $equipo -or $equipo -eq '$env:COMPUTERNAME') {
        $equipo = [System.Environment]::MachineName
    }

    # Limpiar cola y jobs existentes antes de empezar
    while ($script:JobQueue.Count -gt 0) {
        $null = $script:JobQueue.Dequeue()
    }
    
    # Detener y limpiar jobs en ejecución
    foreach ($jid in @($script:JobLabels.Keys)) {
        $job = Get-Job -Id $jid -ErrorAction SilentlyContinue
        if ($job) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
    }
    $script:JobLabels.Clear()
    $script:JobProcessedCounts.Clear()

    Invoke-Ui { $rtbResults.Document.Blocks.Clear() }

    $script:Stats = @{ OK = 0; Warning = 0; Error = 0; Info = 0 }
    [void]$script:AllResults.Clear()
    $script:CurrentRenderedAnalysis = $null
    $script:CurrentFilter = 'All'
    Update-StatsUi
    Update-FilterUi

    Append-TechLog "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    Append-TechLog ("Iniciando diagnóstico para: {0}" -f $equipo)
    Append-TechLog ("Análisis seleccionados: {0}" -f $selected.Count)
    Append-TechLog "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    Ensure-PollingTimer

    # Encolar análisis únicos (evitar duplicados)
    $uniqueSelected = $selected | Sort-Object -Property Func -Unique
    foreach ($s in $uniqueSelected) {
        Append-TechLog ("▶️ Encolando: {0}" -f $s.Label)
        Enqueue-AnalysisJob -FuncName $s.Func -Label $s.Label -Equipo $equipo
    }

    # Si no hay nada en ejecución, arrancar el primero en cola
    Try-StartNextJob
})

$script:Window.Add_Closed({
    try {
        if ($script:PollingTimer) {
            $script:PollingTimer.Stop()
        }
    } catch { }
    
    try {
        foreach ($jid in @($script:JobLabels.Keys)) {
            $job = Get-Job -Id $jid -ErrorAction SilentlyContinue
            if ($job) {
                Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
    
    $script:JobLabels.Clear()
    $script:JobProcessedCounts.Clear()
})

# -------------------------------------------------------------------------------------------------
# Inicialización
# -------------------------------------------------------------------------------------------------

Ensure-PollingTimer
Update-StatsUi
Update-FilterUi

[void]$script:Window.ShowDialog()