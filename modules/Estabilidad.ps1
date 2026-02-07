# Diagnósticos de estabilidad del sistema (local)
# Implementa comprobaciones: eventos críticos, SMART, dumps, integridad SFC/DISM,
# historial de reinicios y estado de batería.
# Author: Galvik
. "$PSScriptRoot\..\utils\Utils.ps1"

# =================================================================================================
# Diagnóstico: Eventos Críticos del Sistema
# =================================================================================================

function Diagnostico-EventosCriticos {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando eventos críticos del sistema en: $equipo"
        
        # IDs de eventos críticos a monitorizar
        $criticalEventIds = @{
            41   = 'Kernel-Power: Reinicio inesperado o pérdida de energía'
            1001 = 'BugCheck: Pantalla azul (BSOD)'
            6008 = 'EventLog: Apagado inesperado del sistema'
            7031 = 'Service Control Manager: Servicio terminó inesperadamente'
            10016 = 'DistributedCOM: Error de permisos DCOM'
            1014 = 'DNS Client: Error de resolución de nombres'
            129  = 'Disk: Error de restablecimiento del disco'
            153  = 'Disk: Tiempo de espera de E/S agotado'
        }
        
        Write-Output "🔍 Buscando eventos críticos en las últimas 72 horas..."
        $startTime = (Get-Date).AddDays(-3)
        
        $foundEvents = @()
        
        foreach ($eventId in $criticalEventIds.Keys) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = 'System'
                    ID        = $eventId
                    StartTime = $startTime
                } -MaxEvents 50 -ErrorAction SilentlyContinue
                
                if ($events) {
                    $foundEvents += $events
                }
            } catch { }
        }
        
        if (-not $foundEvents -or $foundEvents.Count -eq 0) {
            Write-Output "✅ No se encontraron eventos críticos en las últimas 72 horas"
        } else {
            Write-Output ("⚠️ Se encontraron {0} eventos críticos:" -f $foundEvents.Count)
            Write-Output ""
            
            # Agrupar por tipo de evento
            $groupedEvents = $foundEvents | Group-Object -Property Id | Sort-Object Count -Descending
            
            foreach ($group in $groupedEvents) {
                $eventId = $group.Name
                $count = $group.Count
                $description = if ($criticalEventIds.ContainsKey([int]$eventId)) { 
                    $criticalEventIds[[int]$eventId] 
                } else { 
                    'Evento crítico' 
                }
                
                $severity = switch ($eventId) {
                    '41'   { 'Error' }
                    '1001' { 'Error' }
                    '6008' { 'Error' }
                    '7031' { 'Warning' }
                    '129'  { 'Error' }
                    '153'  { 'Error' }
                    default { 'Warning' }
                }
                
                # Mostrar resumen del grupo
                Write-Output ("📌 Evento ID {0}: {1} ({2} ocurrencias)" -f $eventId, $description, $count)
                
                # Mostrar últimos 3 eventos de este tipo
                $recentEvents = $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 3
                foreach ($evt in $recentEvents) {
                    $msg = ($evt.Message -replace "`r`n", ' ' -replace '\s+', ' ').Trim()
                    if ($msg.Length -gt 150) { $msg = $msg.Substring(0, 150) + '...' }
                    Write-Output ("   [{0}] {1}" -f $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $msg)
                }
                
                # Generar evento estructurado según el tipo
                $causes = @()
                $recommendations = @()
                
                switch ($eventId) {
                    '41' {
                        $causes = @(
                            'Pérdida repentina de energía eléctrica',
                            'Problema con la fuente de alimentación',
                            'Sobrecalentamiento causando apagado de protección',
                            'Botón de encendido presionado accidentalmente',
                            'Fallo de hardware crítico'
                        )
                        $recommendations = @(
                            'Conectar el equipo a un SAI/UPS para protección eléctrica',
                            'Verificar temperatura del sistema y limpieza de ventiladores',
                            'Revisar fuente de alimentación con un multímetro',
                            'Comprobar logs de hardware en BIOS/UEFI',
                            'Ejecutar diagnóstico de hardware del fabricante'
                        )
                    }
                    '1001' {
                        $causes = @(
                            'Driver defectuoso o incompatible',
                            'Problema de hardware (RAM, disco, etc.)',
                            'Sobrecalentamiento del procesador',
                            'Conflicto de software',
                            'Malware o rootkit'
                        )
                        $recommendations = @(
                            'Revisar archivo dump en C:\Windows\Minidump\ con BlueScreenView',
                            'Actualizar todos los drivers, especialmente gráficos y chipset',
                            'Ejecutar Windows Memory Diagnostic (mdsched.exe)',
                            'Verificar temperatura del CPU durante carga',
                            'Desinstalar software/drivers recientemente instalados',
                            'Ejecutar análisis completo de antivirus/antimalware'
                        )
                    }
                    '6008' {
                        $causes = @(
                            'Apagado forzado por el usuario',
                            'Pérdida de energía',
                            'Fallo crítico del sistema',
                            'Congelamiento que requirió reinicio forzado'
                        )
                        $recommendations = @(
                            'Verificar eventos previos al apagado inesperado',
                            'Revisar estabilidad del suministro eléctrico',
                            'Comprobar si hay un patrón temporal',
                            'Evaluar instalación de SAI/UPS'
                        )
                    }
                    '7031' {
                        $causes = @(
                            'Servicio crasheó debido a error interno',
                            'Dependencias no disponibles',
                            'Recursos insuficientes',
                            'Software defectuoso'
                        )
                        $recommendations = @(
                            'Revisar eventos del servicio específico en Event Viewer',
                            'Verificar configuración de recuperación del servicio',
                            'Actualizar el software asociado al servicio',
                            'Comprobar recursos del sistema (RAM, CPU)'
                        )
                    }
                    '129' {
                        $causes = @(
                            'Disco duro fallando o con sectores defectuosos',
                            'Cable SATA suelto o defectuoso',
                            'Controladora SATA con problemas',
                            'Sobrecalentamiento del disco',
                            'Firmware del disco desactualizado'
                        )
                        $recommendations = @(
                            'Ejecutar chkdsk /f /r en el disco afectado',
                            'Verificar SMART con CrystalDiskInfo',
                            'Revisar cables y conexiones del disco',
                            'Actualizar firmware del disco (con precaución)',
                            'REALIZAR BACKUP INMEDIATO DE DATOS CRÍTICOS',
                            'Considerar reemplazo del disco si SMART indica fallos'
                        )
                    }
                    '153' {
                        $causes = @(
                            'Disco extremadamente lento o fallando',
                            'Controladora con problemas',
                            'Excesiva carga de E/S del disco',
                            'Problemas de firmware'
                        )
                        $recommendations = @(
                            'Verificar rendimiento del disco con CrystalDiskMark',
                            'Revisar estado SMART del disco',
                            'Comprobar si hay procesos generando E/S excesiva',
                            'Actualizar drivers de controladora',
                            'Considerar migración a SSD si es HDD'
                        )
                    }
                }
                
                Write-DiagnosticEvent -Severity $severity `
                    -Component 'Stability' -Subcomponent ('CriticalEvent:{0}' -f $eventId) `
                    -Message ("⚠️ Detectados {0} eventos ID {1}: {2}" -f $count, $eventId, $description) `
                    -Causes $causes `
                    -Recommendations $recommendations `
                    -Data @{ EventID = $eventId; Count = $count; LastOccurrence = ($recentEvents[0].TimeCreated) }
                
                Write-Output ""
            }
        }
        
        Write-Output "✅ Análisis de eventos críticos completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'CriticalEvents' `
            -ContextMessage 'Error durante el análisis de eventos críticos.' `
            -Recommendations @(
                'Verificar permisos para acceder al Visor de eventos',
                'Comprobar que el servicio EventLog esté en ejecución'
            )
    }
}

# =================================================================================================
# Diagnóstico: Estado SMART de Discos (Mejorado)
# =================================================================================================

function Diagnostico-DiscoSMART {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando estado SMART de discos en: $equipo"
        
        # Intentar obtener información SMART
        $smartStatus = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
        $smartData = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictData -ErrorAction SilentlyContinue
        
        if (-not $smartStatus) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Stability' -Subcomponent 'SMART:NotAvailable' `
                -Message '⚠️ No se pudo obtener información SMART de los discos' `
                -Causes @(
                    'Discos no soportan SMART (poco común)',
                    'Drivers de controladora no exponen SMART',
                    'Discos conectados vía USB/externa sin passthrough SMART',
                    'Sistema virtualizado sin acceso al hardware físico'
                ) `
                -Recommendations @(
                    'Usar herramientas de terceros: CrystalDiskInfo, HD Tune',
                    'Actualizar drivers de la controladora SATA/NVMe',
                    'Si es disco externo, conectarlo internamente para verificar SMART',
                    'Consultar documentación del fabricante del disco'
                )
            return
        }
        
        $diskProblems = 0
        
        foreach ($disk in $smartStatus) {
            $instanceName = $disk.InstanceName
            $predictFailure = $disk.PredictFailure
            
            # Intentar obtener información adicional del disco
            $diskInfo = Get-PhysicalDisk -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DeviceId -eq ($disk.InstanceName -replace '_\d+$', '') } |
                        Select-Object -First 1
            
            if (-not $diskInfo) {
                $diskInfo = Get-Disk -ErrorAction SilentlyContinue | 
                            Select-Object -First 1
            }
            
            $diskName = if ($diskInfo.FriendlyName) { 
                $diskInfo.FriendlyName 
            } else { 
                "Disco: $instanceName" 
            }
            
            Write-Output ("💿 {0}" -f $diskName)
            
            if ($predictFailure) {
                $diskProblems++
                
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Stability' -Subcomponent 'SMART:FailurePredicted' `
                    -Message ("❌ SMART predice fallo inminente en: {0}" -f $diskName) `
                    -Causes @(
                        'El disco está fallando físicamente',
                        'Sectores defectuosos aumentando',
                        'Problemas mecánicos (si es HDD)',
                        'Celdas de memoria agotadas (si es SSD)',
                        'Tiempo de vida útil del disco cerca del final'
                    ) `
                    -Recommendations @(
                        '🚨 REALIZAR BACKUP COMPLETO INMEDIATAMENTE',
                        'Dejar de usar el disco para datos críticos',
                        'Planificar reemplazo del disco urgentemente',
                        'Usar CrystalDiskInfo para ver detalles SMART específicos',
                        'Verificar qué atributo SMART está fallando',
                        'Si está en garantía, contactar al fabricante',
                        'NO CONFIAR EN ESTE DISCO PARA ALMACENAMIENTO IMPORTANTE'
                    ) `
                    -Data @{ DiskName = $diskName; InstanceName = $instanceName }
            } else {
                Write-Output "   ✅ Estado SMART: OK (sin predicción de fallo)"
                
                # Información adicional si está disponible
                if ($diskInfo) {
                    if ($diskInfo.HealthStatus) {
                        Write-Output ("   • Estado de salud: {0}" -f $diskInfo.HealthStatus)
                    }
                    if ($diskInfo.OperationalStatus) {
                        Write-Output ("   • Estado operacional: {0}" -f $diskInfo.OperationalStatus)
                    }
                    if ($diskInfo.Size) {
                        $sizeGB = [math]::Round($diskInfo.Size / 1GB, 2)
                        Write-Output ("   • Capacidad: {0} GB" -f $sizeGB)
                    }
                }
            }
            Write-Output ""
        }
        
        if ($diskProblems -eq 0) {
            Write-Output "✅ Todos los discos reportan estado SMART saludable"
        } else {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Stability' -Subcomponent 'SMART:Summary' `
                -Message ("❌ Se detectaron {0} disco(s) con predicción de fallo" -f $diskProblems) `
                -Recommendations @(
                    'Priorizar backup de datos críticos INMEDIATAMENTE',
                    'Planificar reemplazo de discos afectados',
                    'No demorar la acción - el fallo puede ocurrir en cualquier momento'
                )
        }
        
        Write-Output "✅ Verificación SMART completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'SMART' `
            -ContextMessage 'Error durante la verificación SMART.' `
            -Recommendations @(
                'Verificar permisos administrativos',
                'Usar herramientas alternativas (CrystalDiskInfo)'
            )
    }
}

# =================================================================================================
# NUEVO: Análisis de Dumps de Memoria (BSOD)
# =================================================================================================

function Diagnostico-DumpsMemoria {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando dumps de memoria (BSOD) en: $equipo"
        
        # Rutas de dumps
        $minidumpPath = "$env:SystemRoot\Minidump"
        $memoryDmpPath = "$env:SystemRoot\MEMORY.DMP"
        
        $minidumps = @()
        if (Test-Path $minidumpPath) {
            $minidumps = Get-ChildItem -Path $minidumpPath -Filter *.dmp -ErrorAction SilentlyContinue |
                         Sort-Object LastWriteTime -Descending
        }
        
        $fullDump = $null
        if (Test-Path $memoryDmpPath) {
            $fullDump = Get-Item $memoryDmpPath -ErrorAction SilentlyContinue
        }
        
        if (-not $minidumps -and -not $fullDump) {
            Write-Output "✅ No se encontraron dumps de memoria recientes (sin BSODs)"
            return
        }
        
        Write-Output ("📊 Dumps encontrados: {0} minidumps" -f $minidumps.Count)
        if ($fullDump) {
            $fullDumpSizeMB = [math]::Round($fullDump.Length / 1MB, 2)
            Write-Output ("📊 Dump completo: MEMORY.DMP ({0} MB)" -f $fullDumpSizeMB)
        }
        Write-Output ""
        
        if ($minidumps) {
            Write-Output "📋 Minidumps recientes (últimos 10):"
            $recent = $minidumps | Select-Object -First 10
            
            foreach ($dump in $recent) {
                $sizeMB = [math]::Round($dump.Length / 1MB, 2)
                $age = ((Get-Date) - $dump.LastWriteTime).Days
                Write-Output ("   • {0} - {1} MB (hace {2} días)" -f $dump.Name, $sizeMB, $age)
            }
            Write-Output ""
            
            # Análisis temporal
            $lastWeek = $minidumps | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            $lastMonth = $minidumps | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-30) }
            
            Write-Output ("📈 Estadísticas:")
            Write-Output ("   • Última semana: {0} BSODs" -f $lastWeek.Count)
            Write-Output ("   • Último mes: {0} BSODs" -f $lastMonth.Count)
            Write-Output ("   • Total histórico: {0} BSODs" -f $minidumps.Count)
            Write-Output ""
            
            $severity = 'Info'
            if ($lastWeek.Count -gt 5) { $severity = 'Error' }
            elseif ($lastWeek.Count -gt 2) { $severity = 'Warning' }
            elseif ($lastMonth.Count -gt 0) { $severity = 'Warning' }
            
            if ($lastWeek.Count -gt 0 -or $lastMonth.Count -gt 0) {
                Write-DiagnosticEvent -Severity $severity `
                    -Component 'Stability' -Subcomponent 'BSOD:Dumps' `
                    -Message ("⚠️ Se detectaron {0} pantallas azules en la última semana" -f $lastWeek.Count) `
                    -Causes @(
                        'Driver defectuoso o incompatible (causa más común)',
                        'Problemas de hardware (RAM, disco, tarjeta gráfica)',
                        'Sobrecalentamiento del procesador',
                        'Malware o rootkit',
                        'Conflicto de software o servicios',
                        'Actualizaciones de Windows problemáticas'
                    ) `
                    -Recommendations @(
                        'Descargar BlueScreenView (Nirsoft) para analizar dumps',
                        'Identificar el driver o módulo que causa el crash',
                        'Actualizar drivers problemáticos (especialmente gráficos)',
                        'Ejecutar Windows Memory Diagnostic (mdsched.exe)',
                        'Verificar temperatura del CPU bajo carga',
                        'Desinstalar actualizaciones recientes si el problema empezó tras ellas',
                        'Ejecutar sfc /scannow y DISM para reparar sistema',
                        'Considerar restauración del sistema a punto anterior estable'
                    ) `
                    -Data @{ 
                        LastWeekCount = $lastWeek.Count
                        LastMonthCount = $lastMonth.Count
                        TotalCount = $minidumps.Count
                        MostRecentDump = $recent[0].Name
                    }
            }
        }
        
        Write-Output "✅ Análisis de dumps de memoria completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'Dumps' `
            -ContextMessage 'Error durante el análisis de dumps.' `
            -Recommendations @('Verificar permisos de acceso a carpetas del sistema')
    }
}

# =================================================================================================
# NUEVO: Verificación de Integridad del Sistema (SFC/DISM Mejorado)
# =================================================================================================

function Diagnostico-IntegridadSistema {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando integridad del sistema en: $equipo"
        Write-Output "⚠️ Este análisis puede tardar varios minutos..."
        Write-Output ""
        
        # ===== DISM CheckHealth (rápido) =====
        Write-Output "🔍 Ejecutando DISM /CheckHealth..."
        $dismCheckFile = Join-Path $env:TEMP "dism_checkhealth.txt"
        
        $dismCheckProcess = Start-Process -FilePath "dism.exe" `
            -ArgumentList "/Online", "/Cleanup-Image", "/CheckHealth" `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $dismCheckFile
        
        if (Wait-ForFile -FilePath $dismCheckFile -TimeoutSeconds 120) {
            $dismCheckResult = Get-Content $dismCheckFile -Raw -ErrorAction SilentlyContinue
            Remove-Item $dismCheckFile -Force -ErrorAction SilentlyContinue
            
            if ($dismCheckResult -match 'No component store corruption detected') {
                Write-Output "✅ DISM CheckHealth: Sin corrupción detectada"
            } else {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Stability' -Subcomponent 'DISM:CorruptionDetected' `
                    -Message '⚠️ DISM detectó posible corrupción en el almacén de componentes' `
                    -Causes @(
                        'Actualizaciones de Windows incompletas o fallidas',
                        'Apagado inesperado durante actualización',
                        'Problemas de disco',
                        'Malware que modificó archivos del sistema'
                    ) `
                    -Recommendations @(
                        'Ejecutar: DISM /Online /Cleanup-Image /RestoreHealth',
                        'Después ejecutar: sfc /scannow',
                        'Asegurar conexión estable a Internet (DISM descarga archivos)',
                        'El proceso puede tardar 15-30 minutos',
                        'Reiniciar después de la reparación'
                    )
            }
        } else {
            Write-Output "⚠️ DISM CheckHealth: Timeout o no se pudo leer resultado"
        }
        
        Write-Output ""
        
        # ===== SFC Scan =====
        Write-Output "🔍 Ejecutando SFC /ScanNow (puede tardar 10-15 minutos)..."
        $sfcFile = Join-Path $env:TEMP "sfc_scan.txt"
        
        $sfcProcess = Start-Process -FilePath "sfc.exe" `
            -ArgumentList "/scannow" `
            -NoNewWindow -Wait -PassThru -RedirectStandardOutput $sfcFile
        
        if (Wait-ForFile -FilePath $sfcFile -TimeoutSeconds 1200) {
            $sfcResult = Get-Content $sfcFile -Raw -ErrorAction SilentlyContinue
            Remove-Item $sfcFile -Force -ErrorAction SilentlyContinue
            
            if ($sfcResult -match 'did not find any integrity violations') {
                Write-Output "✅ SFC: Sin violaciones de integridad detectadas"
            }
            elseif ($sfcResult -match 'found corrupt files and successfully repaired them') {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Stability' -Subcomponent 'SFC:Repaired' `
                    -Message '⚠️ SFC encontró y reparó archivos corruptos' `
                    -Causes @(
                        'Archivos del sistema estaban dañados',
                        'Posible causa: actualizaciones, malware, o problemas de disco'
                    ) `
                    -Recommendations @(
                        'Revisar CBS.log para detalles: C:\Windows\Logs\CBS\CBS.log',
                        'Reiniciar el equipo',
                        'Ejecutar análisis antivirus completo',
                        'Verificar salud del disco con chkdsk /f',
                        'Monitorizar estabilidad del sistema'
                    )
            }
            elseif ($sfcResult -match 'found corrupt files but was unable to fix some of them') {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Stability' -Subcomponent 'SFC:UnableToRepair' `
                    -Message '❌ SFC encontró archivos corruptos que no pudo reparar' `
                    -Causes @(
                        'Corrupción severa de archivos del sistema',
                        'Archivos protegidos por otro proceso',
                        'Problema más profundo en el almacén de componentes'
                    ) `
                    -Recommendations @(
                        'Ejecutar: DISM /Online /Cleanup-Image /RestoreHealth',
                        'Después volver a ejecutar: sfc /scannow',
                        'Si persiste, ejecutar en Modo Seguro',
                        'Revisar CBS.log para identificar archivos específicos',
                        'Como último recurso, considerar reparación con medios de instalación',
                        'O realizar instalación limpia conservando archivos personales'
                    )
            } else {
                Write-Output "ℹ️ SFC: Resultado no concluyente o proceso no completado"
            }
        } else {
            Write-Output "⚠️ SFC: Timeout o no se pudo completar el análisis"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de integridad del sistema completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'SystemIntegrity' `
            -ContextMessage 'Error durante la verificación de integridad.' `
            -Recommendations @(
                'Ejecutar con permisos administrativos',
                'Asegurar que el disco tenga espacio suficiente',
                'Verificar que no hay procesos bloqueando archivos del sistema'
            )
    }
}

# =================================================================================================
# NUEVO: Historial de Reinicios y Apagados
# =================================================================================================

function Diagnostico-HistorialReinicios {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando historial de reinicios y apagados en: $equipo"
        
        # Eventos de arranque e inicio
        $eventIds = @{
            12 = 'Sistema operativo iniciado'
            13 = 'Sistema operativo apagándose'
            41 = 'Reinicio inesperado (pérdida de energía)'
            6005 = 'EventLog: Servicio de registro iniciado (arranque)'
            6006 = 'EventLog: Servicio de registro detenido (apagado limpio)'
            6008 = 'EventLog: Apagado inesperado previo'
        }
        
        $startTime = (Get-Date).AddDays(-30)
        Write-Output "📅 Analizando últimos 30 días..."
        Write-Output ""
        
        $allEvents = @()
        foreach ($id in $eventIds.Keys) {
            try {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ID = $id
                    StartTime = $startTime
                } -ErrorAction SilentlyContinue
                
                if ($events) { $allEvents += $events }
            } catch { }
        }
        
        if (-not $allEvents) {
            Write-Output "ℹ️ No se encontraron eventos de arranque/apagado en el período"
            return
        }
        
        $sorted = $allEvents | Sort-Object TimeCreated -Descending | Select-Object -First 30
        
        Write-Output "🗓️ Eventos recientes (últimos 30):"
        foreach ($evt in $sorted) {
            $desc = if ($eventIds.ContainsKey($evt.Id)) { $eventIds[$evt.Id] } else { "ID $($evt.Id)" }
            $icon = switch ($evt.Id) {
                {$_ -in @(12, 6005)} { '🟢' }
                {$_ -in @(13, 6006)} { '🔵' }
                {$_ -in @(41, 6008)} { '🔴' }
                default { '⚪' }
            }
            Write-Output ("{0} [{1}] {2}" -f $icon, $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $desc)
        }
        
        Write-Output ""
        
        # Análisis de patrones
        $unexpectedShutdowns = $allEvents | Where-Object { $_.Id -in @(41, 6008) }
        $cleanShutdowns = $allEvents | Where-Object { $_.Id -in @(13, 6006) }
        $boots = $allEvents | Where-Object { $_.Id -in @(12, 6005) }
        
        Write-Output "📊 Resumen del período:"
        Write-Output ("   • Total arranques: {0}" -f $boots.Count)
        Write-Output ("   • Apagados limpios: {0}" -f $cleanShutdowns.Count)
        Write-Output ("   • Apagados inesperados: {0}" -f $unexpectedShutdowns.Count)
        
        if ($unexpectedShutdowns.Count -gt 0) {
            $unexpectedPercent = [math]::Round(($unexpectedShutdowns.Count / $boots.Count) * 100, 1)
            
            $severity = if ($unexpectedPercent -gt 30) { 'Error' } elseif ($unexpectedPercent -gt 10) { 'Warning' } else { 'Info' }
            
            Write-DiagnosticEvent -Severity $severity `
                -Component 'Stability' -Subcomponent 'Shutdowns:Unexpected' `
                -Message ("⚠️ {0} apagados inesperados detectados ({1}% del total)" -f $unexpectedShutdowns.Count, $unexpectedPercent) `
                -Causes @(
                    'Cortes de energía',
                    'Sobrecalentamiento',
                    'Congelamiento del sistema',
                    'Presión accidental del botón de encendido',
                    'Problemas de hardware críticos'
                ) `
                -Recommendations @(
                    'Conectar el equipo a un SAI/UPS',
                    'Verificar temperatura del sistema',
                    'Revisar eventos específicos de cada apagado inesperado',
                    'Comprobar salud del hardware',
                    'Evitar apagados forzados (mantener botón presionado)'
                ) `
                -Data @{ 
                    UnexpectedCount = $unexpectedShutdowns.Count
                    UnexpectedPercent = $unexpectedPercent
                    TotalBoots = $boots.Count
                }
        } else {
            Write-Output ""
            Write-Output "✅ No se detectaron apagados inesperados en el período"
        }
        
        Write-Output ""
        Write-Output "✅ Análisis de historial de reinicios completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'ShutdownHistory' `
            -ContextMessage 'Error durante el análisis de reinicios.' `
            -Recommendations @('Verificar acceso al registro de eventos')
    }
}

# =================================================================================================
# NUEVO: Estado de Batería (Laptops)
# =================================================================================================

function Diagnostico-EstadoBateria {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando estado de batería en: $equipo"
        
        $batteries = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        
        if (-not $batteries) {
            Write-Output "ℹ️ No se detectó batería (equipo de escritorio o batería no accesible)"
            return
        }
        
        foreach ($battery in $batteries) {
            Write-Output ("🔋 Batería: {0}" -f $battery.Name)
            Write-Output ("   • Estado: {0}" -f $battery.Status)
            Write-Output ("   • Carga actual: {0}%" -f $battery.EstimatedChargeRemaining)
            
            # Tiempo estimado
            if ($battery.EstimatedRunTime -and $battery.EstimatedRunTime -ne 71582788) {
                $minutes = $battery.EstimatedRunTime
                $hours = [math]::Floor($minutes / 60)
                $mins = $minutes % 60
                Write-Output ("   • Tiempo estimado restante: {0}h {1}m" -f $hours, $mins)
            }
            
            # Estado de carga
            $chargingStatus = switch ($battery.BatteryStatus) {
                1 { "Descargando" }
                2 { "Conectado a AC" }
                3 { "Completamente cargada" }
                4 { "Baja" }
                5 { "Crítica" }
                6 { "Cargando" }
                7 { "Cargando y alta" }
                8 { "Cargando y baja" }
                9 { "Cargando y crítica" }
                10 { "Indefinido" }
                11 { "Parcialmente cargada" }
                default { "Desconocido" }
            }
            Write-Output ("   • Estado de carga: {0}" -f $chargingStatus)
            
            # Chemistry
            if ($battery.Chemistry) {
                $chemistry = switch ($battery.Chemistry) {
                    1 { "Otra" }
                    2 { "Desconocida" }
                    3 { "Plomo ácido" }
                    4 { "Níquel cadmio" }
                    5 { "Níquel metal hidruro" }
                    6 { "Iones de litio" }
                    7 { "Zinc" }
                    8 { "Alcalina" }
                    default { "N/D" }
                }
                Write-Output ("   • Tecnología: {0}" -f $chemistry)
            }
            
            # Verificar salud de la batería
            if ($battery.DesignCapacity -and $battery.FullChargeCapacity) {
                $designCap = $battery.DesignCapacity
                $fullCap = $battery.FullChargeCapacity
                $healthPercent = [math]::Round(($fullCap / $designCap) * 100, 1)
                
                Write-Output ("   • Capacidad de diseño: {0} mWh" -f $designCap)
                Write-Output ("   • Capacidad de carga completa: {0} mWh" -f $fullCap)
                Write-Output ("   • Salud de la batería: {0}%" -f $healthPercent)
                
                if ($healthPercent -lt 50) {
                    Write-DiagnosticEvent -Severity 'Error' `
                        -Component 'Stability' -Subcomponent 'Battery:Poor' `
                        -Message ("❌ Batería en mal estado: {0}% de capacidad original" -f $healthPercent) `
                        -Causes @(
                            'Desgaste normal por ciclos de carga/descarga',
                            'Batería envejecida',
                            'Exposición a temperaturas extremas',
                            'Prácticas de carga inadecuadas'
                        ) `
                        -Recommendations @(
                            'Considerar reemplazo de la batería',
                            'Usar el equipo conectado a AC cuando sea posible',
                            'Verificar garantía de la batería',
                            'Evitar descargas completas frecuentes',
                            'Mantener la batería en rango de temperatura óptimo'
                        ) `
                        -Data @{ BatteryHealth = $healthPercent }
                } elseif ($healthPercent -lt 70) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Stability' -Subcomponent 'Battery:Degraded' `
                        -Message ("⚠️ Batería degradada: {0}% de capacidad original" -f $healthPercent) `
                        -Causes @(
                            'Desgaste normal por uso',
                            'Edad de la batería'
                        ) `
                        -Recommendations @(
                            'Monitorizar la autonomía de la batería',
                            'Planificar reemplazo en el futuro cercano',
                            'Mantener buenas prácticas de carga'
                        ) `
                        -Data @{ BatteryHealth = $healthPercent }
                } else {
                    Write-Output "   ✅ Salud de la batería en buen estado"
                }
            }
            
            # Alertas de carga crítica
            if ($battery.BatteryStatus -in @(5, 9)) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Stability' -Subcomponent 'Battery:Critical' `
                    -Message '⚠️ Batería en nivel crítico' `
                    -Recommendations @(
                        'Conectar el cargador inmediatamente',
                        'Guardar el trabajo',
                        'El equipo se apagará pronto si no se conecta'
                    )
            }
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de batería completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Stability' -Subcomponent 'Battery' `
            -ContextMessage 'Error durante la verificación de batería.' `
            -Recommendations @('Verificar drivers de batería y ACPI')
    }
}