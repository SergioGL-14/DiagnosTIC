# Diagnósticos de rendimiento (local)
# Recopila métricas de CPU, memoria, procesos, servicios y disco para evaluación
# Author: Galvik
. "$PSScriptRoot\..\utils\Utils.ps1"

# =================================================================================================
# Diagnóstico: Rendimiento General (CPU/RAM)
# =================================================================================================

function Diagnostico-Rendimiento {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Iniciando diagnóstico de rendimiento para: $equipo"
        
        # === Información de CPU ===
        $cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $cpu = $cpuInfo.LoadPercentage
        
        Write-Output ("🧠 Procesador: {0}" -f $cpuInfo.Name)
        Write-Output ("   • Núcleos físicos: {0}  Núcleos lógicos: {1}" -f $cpuInfo.NumberOfCores, $cpuInfo.NumberOfLogicalProcessors)
        Write-Output ("   • Velocidad: {0} MHz (Max: {1} MHz)" -f $cpuInfo.CurrentClockSpeed, $cpuInfo.MaxClockSpeed)
        Write-Output ("   • Uso actual: {0}%" -f $cpu)
        
        # Clasificación del uso de CPU
        if ($cpu -ge 90) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Performance' -Subcomponent 'CPU:Usage' `
                -Message ("❌ Uso de CPU crítico: {0}%" -f $cpu) `
                -Causes @(
                    'Proceso o aplicación consumiendo recursos excesivos',
                    'Malware o software no deseado',
                    'Servicio del sistema en bucle infinito',
                    'Insuficiente capacidad de procesamiento para la carga actual'
                ) `
                -Recommendations @(
                    'Revisar procesos activos y finalizar los que consumen más recursos',
                    'Ejecutar análisis antivirus/antimalware',
                    'Comprobar servicios en ejecución y desactivar los innecesarios',
                    'Considerar actualización de hardware si la carga es legítima'
                )
        } elseif ($cpu -ge 70) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Performance' -Subcomponent 'CPU:Usage' `
                -Message ("⚠️ Uso de CPU elevado: {0}%" -f $cpu) `
                -Causes @(
                    'Múltiples aplicaciones ejecutándose simultáneamente',
                    'Proceso en segundo plano consumiendo recursos',
                    'Actualizaciones del sistema en curso'
                ) `
                -Recommendations @(
                    'Revisar aplicaciones en ejecución y cerrar las innecesarias',
                    'Verificar procesos en segundo plano (Windows Update, indexación)',
                    'Monitorizar el uso durante un período prolongado'
                )
        } else {
            Write-Output "✅ Uso de CPU normal"
        }
        
        # Muestreo adicional de CPU (5 segundos)
        Write-Output "⏱️ Muestreando uso de CPU durante 5 segundos..."
        $samples = @()
        for ($i = 0; $i -lt 5; $i++) {
            Start-Sleep -Seconds 1
            $sample = (Get-CimInstance -ClassName Win32_Processor).LoadPercentage
            $samples += $sample
        }
        $avgCpu = [math]::Round(($samples | Measure-Object -Average).Average, 1)
        $maxCpu = ($samples | Measure-Object -Maximum).Maximum
        $minCpu = ($samples | Measure-Object -Minimum).Minimum
        
        Write-Output ("   • CPU promedio (5s): {0}%  Min: {1}%  Max: {2}%" -f $avgCpu, $minCpu, $maxCpu)
        
        # === Información de RAM ===
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $memTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $memFree = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
        $memUsed = [math]::Round($memTotal - $memFree, 2)
        $memPct = [math]::Round(($memUsed / $memTotal) * 100, 1)
        
        Write-Output ""
        Write-Output ("💾 Memoria RAM: {0} GB de {1} GB en uso ({2}%)" -f $memUsed, $memTotal, $memPct)
        Write-Output ("   • Disponible: {0} GB" -f $memFree)
        
        # Clasificación del uso de RAM
        if ($memPct -ge 90) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Performance' -Subcomponent 'RAM:Usage' `
                -Message ("❌ Memoria RAM crítica: {0}% en uso" -f $memPct) `
                -Causes @(
                    'Aplicaciones consumiendo excesiva memoria',
                    'Fuga de memoria (memory leak) en algún proceso',
                    'Insuficiente RAM para la carga de trabajo actual',
                    'Demasiadas aplicaciones abiertas simultáneamente'
                ) `
                -Recommendations @(
                    'Cerrar aplicaciones innecesarias inmediatamente',
                    'Identificar procesos con consumo anómalo y finalizarlos',
                    'Reiniciar aplicaciones con posibles fugas de memoria',
                    'Considerar ampliar la memoria RAM del equipo',
                    'Revisar configuración de archivo de paginación'
                )
        } elseif ($memPct -ge 75) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Performance' -Subcomponent 'RAM:Usage' `
                -Message ("⚠️ Memoria RAM elevada: {0}% en uso" -f $memPct) `
                -Causes @(
                    'Carga de trabajo normal pero cercana al límite',
                    'Múltiples aplicaciones pesadas en ejecución',
                    'Caché del sistema ocupando espacio'
                ) `
                -Recommendations @(
                    'Monitorizar el uso de memoria regularmente',
                    'Cerrar aplicaciones no esenciales',
                    'Planificar ampliación de RAM si el uso es constante'
                )
        } else {
            Write-Output "✅ Uso de memoria RAM normal"
        }
        
        # Información adicional de memoria
        try {
            $memCache = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory - 
                        ($os.TotalVisibleMemorySize * 0.1)) / 1MB, 2)
            Write-Output ("   • Caché del sistema (estimado): ~{0} GB" -f $memCache)
        } catch { }
        
        # === Memoria virtual / Paginación ===
        try {
            $pageFile = Get-CimInstance -ClassName Win32_PageFileUsage
            if ($pageFile) {
                foreach ($pf in $pageFile) {
                    $pfUsed = [math]::Round($pf.CurrentUsage / 1024, 2)
                    $pfTotal = [math]::Round($pf.AllocatedBaseSize / 1024, 2)
                    $pfPct = if ($pfTotal -gt 0) { [math]::Round(($pfUsed / $pfTotal) * 100, 1) } else { 0 }
                    
                    Write-Output ""
                    Write-Output ("📄 Archivo de paginación: {0}" -f $pf.Name)
                    Write-Output ("   • Uso: {0} GB de {1} GB ({2}%)" -f $pfUsed, $pfTotal, $pfPct)
                    
                    if ($pfPct -ge 80) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Performance' -Subcomponent 'PageFile:Usage' `
                            -Message ("⚠️ Archivo de paginación con uso elevado: {0}%" -f $pfPct) `
                            -Causes @(
                                'Memoria RAM insuficiente, sistema usando disco como memoria',
                                'Aplicaciones requiriendo más memoria de la disponible físicamente',
                                'Archivo de paginación mal dimensionado'
                            ) `
                            -Recommendations @(
                                'Ampliar la memoria RAM del sistema',
                                'Aumentar el tamaño del archivo de paginación',
                                'Cerrar aplicaciones que no se estén usando',
                                'Considerar mover el archivo de paginación a un disco más rápido (SSD)'
                            )
                    }
                }
            }
        } catch {
            Write-Output "ℹ️ No se pudo obtener información del archivo de paginación"
        }
        
        # === Velocidad del procesador ===
        $speedDiff = $cpuInfo.MaxClockSpeed - $cpuInfo.CurrentClockSpeed
        if ($speedDiff -gt ($cpuInfo.MaxClockSpeed * 0.3)) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Performance' -Subcomponent 'CPU:ClockSpeed' `
                -Message "⚠️ CPU funcionando por debajo de su velocidad máxima" `
                -Causes @(
                    'Gestión de energía activa (modo ahorro de energía)',
                    'Thermal throttling por sobrecalentamiento',
                    'Configuración de BIOS/UEFI limitando velocidad',
                    'Problema con drivers de chipset'
                ) `
                -Recommendations @(
                    'Verificar plan de energía (configurar como Alto rendimiento si procede)',
                    'Comprobar temperatura del procesador',
                    'Revisar configuración de BIOS/UEFI',
                    'Actualizar drivers de chipset'
                )
        }
        
        Write-Output ""
        Write-Output "✅ Diagnóstico de rendimiento completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'General' `
            -ContextMessage 'Error durante el diagnóstico de rendimiento.' `
            -Recommendations @(
                'Verificar permisos de ejecución',
                'Comprobar que WMI/CIM esté funcionando correctamente'
            )
    }
}

# =================================================================================================
# Diagnóstico: Procesos Activos (Mejorado)
# =================================================================================================

function Diagnostico-ProcesosActivos {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando procesos activos en: $equipo"
        
        # Obtener todos los procesos con información extendida
        $allProcs = Get-Process | Where-Object { $_.WorkingSet -gt 0 }
        $totalProcs = $allProcs.Count
        $totalRAM = ($allProcs | Measure-Object -Property WorkingSet -Sum).Sum / 1MB
        
        Write-Output ("📊 Procesos totales en ejecución: {0}" -f $totalProcs)
        Write-Output ("📊 RAM total consumida por procesos: {0:N2} MB" -f $totalRAM)
        Write-Output ""
        Write-Output "🔝 Top 20 procesos por consumo de RAM:"
        Write-Output ""
        
        $procs = $allProcs | Sort-Object WorkingSet -Descending | Select-Object -First 20
        
        foreach ($p in $procs) {
            $ramMB = [math]::Round($p.WorkingSet / 1MB, 1)
            $cpuTime = if ($p.TotalProcessorTime) { 
                [math]::Round($p.TotalProcessorTime.TotalSeconds, 1) 
            } else { 0 }
            
            $handles = if ($p.HandleCount) { $p.HandleCount } else { 0 }
            $threads = if ($p.Threads) { $p.Threads.Count } else { 0 }
            
            Write-Output ("{0,-30} PID:{1,6} | RAM:{2,8}MB | CPU:{3,6}s | Handles:{4,5} | Threads:{5,3}" -f `
                $p.ProcessName.Substring(0, [Math]::Min(30, $p.ProcessName.Length)), 
                $p.Id, 
                $ramMB, 
                $cpuTime,
                $handles,
                $threads)
            
            # Alertas por consumo excesivo
            if ($ramMB -gt 2048) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'Process:HighRAM' `
                    -Message ("⚠️ Proceso con consumo muy alto de RAM: {0} ({1} MB)" -f $p.ProcessName, $ramMB) `
                    -Causes @(
                        'Aplicación con carga de trabajo intensiva',
                        'Posible fuga de memoria (memory leak)',
                        'Aplicación mal optimizada',
                        'Procesamiento de archivos grandes'
                    ) `
                    -Recommendations @(
                        "Verificar si el proceso '{0}' es necesario" -f $p.ProcessName,
                        'Considerar reiniciar la aplicación si el consumo es anómalo',
                        'Buscar actualizaciones de la aplicación',
                        'Contactar al fabricante si el problema persiste'
                    ) `
                    -Data @{ ProcessName = $p.ProcessName; PID = $p.Id; RAMUsageMB = $ramMB }
            }
            
            if ($handles -gt 10000) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'Process:HighHandles' `
                    -Message ("⚠️ Proceso con excesivos handles: {0} ({1} handles)" -f $p.ProcessName, $handles) `
                    -Causes @(
                        'Posible fuga de handles (handle leak)',
                        'Aplicación no liberando recursos correctamente',
                        'Problema de programación en la aplicación'
                    ) `
                    -Recommendations @(
                        'Reiniciar la aplicación afectada',
                        'Reportar el problema al desarrollador',
                        'Actualizar la aplicación a la última versión'
                    ) `
                    -Data @{ ProcessName = $p.ProcessName; PID = $p.Id; Handles = $handles }
            }
        }
        
        # Procesos duplicados
        Write-Output ""
        Write-Output "🔍 Buscando procesos duplicados..."
        $duplicates = $allProcs | Group-Object -Property ProcessName | Where-Object { $_.Count -gt 3 }
        
        if ($duplicates) {
            foreach ($dup in $duplicates) {
                $totalDupRAM = ($dup.Group | Measure-Object -Property WorkingSet -Sum).Sum / 1MB
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Performance' -Subcomponent 'Process:Duplicates' `
                    -Message ("ℹ️ Múltiples instancias detectadas: {0} ({1} instancias, {2:N1} MB total)" -f `
                        $dup.Name, $dup.Count, $totalDupRAM) `
                    -Causes @(
                        'Aplicación diseñada para ejecutarse en múltiples instancias',
                        'Usuario abrió la aplicación varias veces',
                        'Procesos huérfanos que no se cerraron correctamente'
                    ) `
                    -Recommendations @(
                        'Verificar si todas las instancias son necesarias',
                        'Cerrar instancias duplicadas innecesarias',
                        'Configurar la aplicación para usar una sola instancia si procede'
                    )
            }
        } else {
            Write-Output "✅ No se detectaron procesos excesivamente duplicados"
        }
        
        # Procesos sin respuesta
        Write-Output ""
        Write-Output "🔍 Buscando procesos sin respuesta..."
        $notResponding = $allProcs | Where-Object { $_.Responding -eq $false }
        
        if ($notResponding) {
            foreach ($nr in $notResponding) {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Performance' -Subcomponent 'Process:NotResponding' `
                    -Message ("❌ Proceso sin respuesta: {0} (PID: {1})" -f $nr.ProcessName, $nr.Id) `
                    -Causes @(
                        'Aplicación bloqueada esperando una operación',
                        'Aplicación en estado de error',
                        'Deadlock o bucle infinito en la aplicación',
                        'Recursos del sistema insuficientes'
                    ) `
                    -Recommendations @(
                        "Finalizar el proceso '{0}' desde el Administrador de tareas" -f $nr.ProcessName,
                        'Intentar cerrar la aplicación normalmente primero',
                        'Reiniciar el equipo si el problema persiste',
                        'Reportar el problema al desarrollador de la aplicación'
                    ) `
                    -Data @{ ProcessName = $nr.ProcessName; PID = $nr.Id }
            }
        } else {
            Write-Output "✅ Todos los procesos responden correctamente"
        }
        
        Write-Output ""
        Write-Output "✅ Análisis de procesos completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Process' `
            -ContextMessage 'Error durante el análisis de procesos.' `
            -Recommendations @('Verificar permisos de acceso a información de procesos')
    }
}

# =================================================================================================
# Diagnóstico: Espacio en Disco (Mejorado)
# =================================================================================================

function Diagnostico-EspacioDisco {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando espacio en disco para: $equipo"
        
        $discos = Get-CimInstance -Class Win32_LogicalDisk -Filter "DriveType=3"
        
        if (-not $discos) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Performance' -Subcomponent 'Disk:Discovery' `
                -Message '❌ No se encontraron discos locales.' `
                -Causes @('Error de consulta WMI', 'Discos no accesibles') `
                -Recommendations @('Verificar configuración del sistema', 'Revisar estado de discos en Administrador de discos')
            return
        }
        
        foreach ($d in $discos) {
            $unidad = $d.DeviceID
            $totalGB = [math]::Round($d.Size / 1GB, 2)
            $libreGB = [math]::Round($d.FreeSpace / 1GB, 2)
            $usadoGB = [math]::Round($totalGB - $libreGB, 2)
            $porc = if ($totalGB -gt 0) { [math]::Round(($libreGB / $totalGB) * 100, 1) } else { 0 }
            $porcUsado = 100 - $porc
            
            $volName = if ($d.VolumeName) { $d.VolumeName } else { "Sin nombre" }
            $fsType = if ($d.FileSystem) { $d.FileSystem } else { "N/D" }
            
            Write-Output ""
            Write-Output ("💿 Unidad {0}: [{1}] - Sistema de archivos: {2}" -f $unidad, $volName, $fsType)
            Write-Output ("   • Capacidad total: {0} GB" -f $totalGB)
            Write-Output ("   • Espacio usado: {0} GB ({1}%)" -f $usadoGB, $porcUsado)
            Write-Output ("   • Espacio libre: {0} GB ({1}%)" -f $libreGB, $porc)
            
            # Clasificación del espacio disponible
            if ($porc -lt 5) {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Performance' -Subcomponent ('Disk:Space:{0}' -f $unidad) `
                    -Message ("❌ Espacio crítico en {0}: solo {1} GB libres ({2}%)" -f $unidad, $libreGB, $porc) `
                    -Causes @(
                        'Acumulación excesiva de archivos temporales',
                        'Archivos de gran tamaño (ISOs, vídeos, backups)',
                        'Logs del sistema sin rotación',
                        'Papelera de reciclaje no vaciada',
                        'Hibernación/archivo de paginación muy grande',
                        'Actualizaciones de Windows acumuladas'
                    ) `
                    -Recommendations @(
                        'Ejecutar Liberador de espacio en disco (cleanmgr.exe)',
                        'Eliminar archivos temporales manualmente (%TEMP%, C:\Windows\Temp)',
                        'Vaciar papelera de reciclaje',
                        'Desinstalar aplicaciones no utilizadas',
                        'Mover archivos grandes a otro disco o almacenamiento externo',
                        'Ejecutar Análisis de disco para identificar archivos grandes',
                        'Considerar desactivar hibernación si no se usa (powercfg /h off)',
                        'Limpiar carpeta WinSxS con DISM /Online /Cleanup-Image /StartComponentCleanup'
                    ) `
                    -Data @{ Drive = $unidad; FreeGB = $libreGB; FreePercent = $porc }
            } elseif ($porc -lt 15) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent ('Disk:Space:{0}' -f $unidad) `
                    -Message ("⚠️ Espacio bajo en {0}: {1} GB libres ({2}%)" -f $unidad, $libreGB, $porc) `
                    -Causes @(
                        'Uso normal del disco acercándose al límite',
                        'Archivos temporales acumulándose',
                        'Backups o descargas ocupando espacio'
                    ) `
                    -Recommendations @(
                        'Planificar limpieza de archivos innecesarios',
                        'Revisar carpeta de Descargas y eliminar archivos no necesarios',
                        'Considerar mover datos a otro disco',
                        'Ejecutar Liberador de espacio en disco',
                        'Configurar Storage Sense para limpieza automática'
                    ) `
                    -Data @{ Drive = $unidad; FreeGB = $libreGB; FreePercent = $porc }
            } else {
                Write-Output ("   ✅ Espacio disponible suficiente")
            }
            
            # Análisis de archivos grandes (solo en C:)
            if ($unidad -eq 'C:') {
                Write-Output ""
                Write-Output "🔍 Buscando archivos grandes en $unidad (>1 GB, máx 10)..."
                try {
                    $largeFiles = Get-ChildItem -Path "$unidad\" -Recurse -File -ErrorAction SilentlyContinue |
                        Where-Object { $_.Length -gt 1GB } |
                        Sort-Object Length -Descending |
                        Select-Object -First 10
                    
                    if ($largeFiles) {
                        foreach ($file in $largeFiles) {
                            $sizeGB = [math]::Round($file.Length / 1GB, 2)
                            Write-Output ("   📄 {0} - {1} GB" -f $file.FullName, $sizeGB)
                        }
                        
                        Write-DiagnosticEvent -Severity 'Info' `
                            -Component 'Performance' -Subcomponent ('Disk:LargeFiles:{0}' -f $unidad) `
                            -Message ("ℹ️ Se encontraron {0} archivos mayores a 1 GB en {1}" -f $largeFiles.Count, $unidad) `
                            -Recommendations @(
                                'Revisar si los archivos grandes son necesarios',
                                'Considerar mover archivos multimedia a otro disco',
                                'Eliminar archivos de instalación (.iso, .exe) ya no necesarios',
                                'Comprimir archivos si es posible'
                            )
                    } else {
                        Write-Output "   ✅ No se encontraron archivos individuales mayores a 1 GB"
                    }
                } catch {
                    Write-Output "   ℹ️ No se pudo completar el análisis de archivos grandes (permisos insuficientes)"
                }
            }
        }
        
        Write-Output ""
        Write-Output "✅ Análisis de espacio en disco completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Disk' `
            -ContextMessage 'Error durante el análisis de espacio en disco.' `
            -Recommendations @('Verificar permisos de acceso a discos')
    }
}

# =================================================================================================
# NUEVO: Diagnóstico de Servicios Críticos
# =================================================================================================

function Diagnostico-ServiciosCriticos {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando servicios críticos del sistema en: $equipo"
        
        # Lista de servicios críticos que deberían estar corriendo
        $serviciosCriticos = @(
            @{Name='Dhcp'; DisplayName='Cliente DHCP'},
            @{Name='Dnscache'; DisplayName='Cliente DNS'},
            @{Name='EventLog'; DisplayName='Registro de eventos de Windows'},
            @{Name='PlugPlay'; DisplayName='Plug and Play'},
            @{Name='RpcSs'; DisplayName='Llamada a procedimiento remoto (RPC)'},
            @{Name='LanmanWorkstation'; DisplayName='Estación de trabajo'},
            @{Name='LanmanServer'; DisplayName='Servidor'},
            @{Name='Themes'; DisplayName='Temas'},
            @{Name='AudioSrv'; DisplayName='Audio de Windows'},
            @{Name='WSearch'; DisplayName='Windows Search'},
            @{Name='Winmgmt'; DisplayName='Instrumental de administración de Windows'}
        )
        
        $problemCount = 0
        
        foreach ($svc in $serviciosCriticos) {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            
            if (-not $service) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'Services:Missing' `
                    -Message ("⚠️ Servicio no encontrado: {0}" -f $svc.DisplayName) `
                    -Causes @(
                        'Servicio desinstalado o deshabilitado',
                        'Componente del sistema no instalado',
                        'Corrupción del sistema'
                    ) `
                    -Recommendations @(
                        'Verificar si el servicio es necesario para este sistema',
                        'Reinstalar el componente si es crítico',
                        'Ejecutar sfc /scannow para reparar archivos del sistema'
                    ) `
                    -Data @{ ServiceName = $svc.Name }
                $problemCount++
                continue
            }
            
            if ($service.Status -ne 'Running') {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Performance' -Subcomponent 'Services:Stopped' `
                    -Message ("❌ Servicio crítico detenido: {0}" -f $svc.DisplayName) `
                    -Causes @(
                        'Servicio falló al iniciar',
                        'Dependencias no disponibles',
                        'Servicio deshabilitado manualmente',
                        'Error de configuración'
                    ) `
                    -Recommendations @(
                        ("Intentar iniciar el servicio: Start-Service {0}" -f $svc.Name),
                        'Verificar el Visor de eventos para errores relacionados',
                        'Comprobar que el tipo de inicio sea Automático',
                        'Verificar dependencias del servicio',
                        'Considerar reiniciar el equipo'
                    ) `
                    -Data @{ ServiceName = $svc.Name; Status = $service.Status }
                $problemCount++
            } else {
                Write-Output ("✅ {0}: En ejecución" -f $svc.DisplayName)
            }
        }
        
        if ($problemCount -eq 0) {
            Write-Output ""
            Write-Output "✅ Todos los servicios críticos están funcionando correctamente"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de servicios completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Services' `
            -ContextMessage 'Error durante la verificación de servicios.' `
            -Recommendations @('Verificar permisos para consultar servicios')
    }
}

# =================================================================================================
# NUEVO: Diagnóstico de Arranque y Tiempo de Inicio
# =================================================================================================

function Diagnostico-TiempoArranque {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando tiempos de arranque en: $equipo"
        
        # Último tiempo de arranque
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $lastBoot = $os.LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
        
        Write-Output ("🕐 Último arranque: {0}" -f $lastBoot)
        Write-Output ("⏱️ Tiempo de actividad: {0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes)
        
        # Programas de inicio
        Write-Output ""
        Write-Output "🚀 Analizando programas de inicio..."
        
        $startupProgs = Get-CimInstance -ClassName Win32_StartupCommand
        $startupCount = ($startupProgs | Measure-Object).Count
        
        Write-Output ("📊 Programas configurados para inicio automático: {0}" -f $startupCount)
        
        if ($startupCount -gt 15) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Performance' -Subcomponent 'Startup:TooMany' `
                -Message ("⚠️ Demasiados programas de inicio: {0}" -f $startupCount) `
                -Causes @(
                    'Aplicaciones configurándose para inicio automático',
                    'Acumulación de software instalado',
                    'Posible presencia de software no deseado'
                ) `
                -Recommendations @(
                    'Abrir Administrador de tareas > pestaña Inicio',
                    'Deshabilitar programas innecesarios del inicio',
                    'Desinstalar software que no se utiliza',
                    'Mantener solo programas esenciales en el inicio'
                ) `
                -Data @{ StartupProgramsCount = $startupCount }
        }
        
        foreach ($prog in $startupProgs) {
            $name = if ($prog.Caption) { $prog.Caption } else { $prog.Command }
            Write-Output ("   • {0}" -f $name)
        }
        
        # Verificar si Windows Fast Startup está habilitado
        try {
            $fastBoot = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
            if ($fastBoot -eq 1) {
                Write-Output ""
                Write-Output "✅ Inicio rápido de Windows está habilitado"
            } else {
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Performance' -Subcomponent 'Startup:FastBoot' `
                    -Message "ℹ️ Inicio rápido de Windows está deshabilitado" `
                    -Recommendations @(
                        'Considerar habilitar el inicio rápido para mejorar tiempos de arranque',
                        'Panel de control > Opciones de energía > Elegir comportamiento botones inicio',
                        'Nota: Puede causar problemas en dual-boot o con actualizaciones'
                    )
            }
        } catch { }
        
        Write-Output ""
        Write-Output "✅ Análisis de arranque completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Startup' `
            -ContextMessage 'Error durante el análisis de arranque.' `
            -Recommendations @('Verificar acceso al registro y WMI')
    }
}

function Diagnostico-Temperatura {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Intentando obtener información de temperatura en: $equipo"
        
        $tempFound = $false
        
        # Intentar obtener temperatura vía WMI (algunos fabricantes la exponen)
        try {
            $temps = Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
            
            if ($temps) {
                foreach ($temp in $temps) {
                    $kelvin = $temp.CurrentTemperature / 10
                    $celsius = $kelvin - 273.15
                    $zoneName = $temp.InstanceName
                    
                    Write-Output ("🌡️ Zona térmica: {0}" -f $zoneName)
                    Write-Output ("   • Temperatura: {0:N1}°C" -f $celsius)
                    
                    if ($celsius -gt 85) {
                        Write-DiagnosticEvent -Severity 'Error' `
                            -Component 'Performance' -Subcomponent 'Temperature:Critical' `
                            -Message ("❌ Temperatura crítica detectada: {0:N1}°C" -f $celsius) `
                            -Causes @(
                                'Sistema de refrigeración insuficiente o con fallos',
                                'Ventiladores obstruidos o no funcionando',
                                'Pasta térmica degradada',
                                'Ambiente con temperatura elevada',
                                'Carga de trabajo muy intensiva'
                            ) `
                            -Recommendations @(
                                'Apagar el equipo inmediatamente para prevenir daños',
                                'Limpiar ventiladores y rejillas de ventilación',
                                'Verificar que todos los ventiladores funcionen',
                                'Considerar reemplazar pasta térmica del procesador',
                                'Mejorar ventilación del área donde está el equipo',
                                'Reducir carga de trabajo o mejorar refrigeración'
                            ) `
                            -Data @{ TemperatureCelsius = $celsius; Zone = $zoneName }
                    } elseif ($celsius -gt 70) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Performance' -Subcomponent 'Temperature:High' `
                            -Message ("⚠️ Temperatura elevada: {0:N1}°C" -f $celsius) `
                            -Causes @(
                                'Carga de trabajo intensiva normal',
                                'Ventilación parcialmente obstruida',
                                'Necesidad de limpieza'
                            ) `
                            -Recommendations @(
                                'Monitorizar temperatura regularmente',
                                'Limpiar ventiladores si no se ha hecho recientemente',
                                'Verificar correcta ventilación del equipo',
                                'Considerar mejorar sistema de refrigeración'
                            ) `
                            -Data @{ TemperatureCelsius = $celsius; Zone = $zoneName }
                    } else {
                        Write-Output "   ✅ Temperatura dentro de rangos normales"
                    }
                    
                    $tempFound = $true
                }
            }
        } catch { }
        
        if (-not $tempFound) {
            Write-DiagnosticEvent -Severity 'Info' `
                -Component 'Performance' -Subcomponent 'Temperature:NotAvailable' `
                -Message "ℹ️ Información de temperatura no disponible vía WMI" `
                -Causes @(
                    'Hardware no expone sensores de temperatura vía WMI',
                    'Drivers de chipset no instalados o desactualizados',
                    'Necesidad de software específico del fabricante'
                ) `
                -Recommendations @(
                    'Instalar software de monitorización del fabricante (Dell Command, HP Support Assistant, etc.)',
                    'Usar herramientas de terceros (HWiNFO, Core Temp, Open Hardware Monitor)',
                    'Actualizar drivers de chipset desde el sitio del fabricante',
                    'Verificar temperatura desde BIOS/UEFI'
                )
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de temperatura completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Temperature' `
            -ContextMessage 'Error durante la verificación de temperatura.' `
            -Recommendations @('Verificar soporte de hardware para monitorización')
    }
}

# =================================================================================================
# Diagnóstico: Drivers y Actualizaciones
# =================================================================================================

function Diagnostico-DriversActualizaciones {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando estado de drivers en: $equipo"
        
        # Dispositivos con problemas
        $devices = Get-CimInstance -ClassName Win32_PNPEntity | Where-Object {
            $_.ConfigManagerErrorCode -ne 0
        }
        
        if ($devices) {
            Write-Output ("⚠️ Se encontraron {0} dispositivos con problemas:" -f $devices.Count)
            
            foreach ($dev in $devices) {
                $errorCode = $dev.ConfigManagerErrorCode
                $errorDesc = switch ($errorCode) {
                    1 { "Configuración incorrecta" }
                    10 { "No puede iniciarse" }
                    12 { "Recursos insuficientes" }
                    22 { "Deshabilitado" }
                    28 { "Drivers no instalados" }
                    31 { "No funciona correctamente" }
                    default { "Error código $errorCode" }
                }
                
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'Drivers:ProblemDevice' `
                    -Message ("⚠️ Dispositivo con problemas: {0}" -f $dev.Name) `
                    -Causes @(
                        ('Error: {0}' -f $errorDesc),
                        'Driver no compatible o corrupto',
                        'Conflicto de recursos',
                        'Hardware defectuoso'
                    ) `
                    -Recommendations @(
                        'Abrir Administrador de dispositivos y revisar el dispositivo',
                        'Actualizar el driver desde el sitio del fabricante',
                        'Desinstalar y reinstalar el dispositivo',
                        'Verificar si hay actualizaciones de Windows pendientes'
                    ) `
                    -Data @{ DeviceName = $dev.Name; ErrorCode = $errorCode; DeviceID = $dev.DeviceID }
            }
        } else {
            Write-Output "✅ Todos los dispositivos funcionan correctamente"
        }
        
        # Verificar actualizaciones pendientes de Windows
        Write-Output ""
        Write-Output "🔍 Verificando estado de Windows Update..."
        
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            $updates = $searchResult.Updates
            
            if ($updates.Count -gt 0) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'Updates:Pending' `
                    -Message ("⚠️ Hay {0} actualizaciones de Windows pendientes" -f $updates.Count) `
                    -Causes @(
                        'Actualizaciones automáticas deshabilitadas',
                        'Problemas con Windows Update',
                        'Actualizaciones requieren reinicio pendiente'
                    ) `
                    -Recommendations @(
                        'Abrir Configuración > Actualización y seguridad',
                        'Instalar todas las actualizaciones pendientes',
                        'Reiniciar el equipo después de instalar actualizaciones',
                        'Habilitar actualizaciones automáticas si están desactivadas'
                    ) `
                    -Data @{ PendingUpdatesCount = $updates.Count }
                
                Write-Output ("   Actualizaciones disponibles (primeras 5):")
                $updates | Select-Object -First 5 | ForEach-Object {
                    Write-Output ("   • {0}" -f $_.Title)
                }
            } else {
                Write-Output "✅ Windows Update está al día"
            }
        } catch {
            Write-Output "ℹ️ No se pudo verificar Windows Update (puede requerir permisos administrativos)"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de drivers completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'Drivers' `
            -ContextMessage 'Error durante la verificación de drivers.' `
            -Recommendations @('Ejecutar con permisos administrativos')
    }
}

# =================================================================================================
# Diagnóstico: Índice de Rendimiento de Windows
# =================================================================================================

function Diagnostico-IndiceRendimiento {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Obteniendo índice de rendimiento de Windows en: $equipo"
        
        # En Windows 10/11, WinSAT ya no muestra el índice gráfico, pero los datos siguen disponibles
        $xmlPath = "$env:windir\Performance\WinSAT\DataStore\*Formal.Assessment*.xml"
        $latestXml = Get-ChildItem -Path $xmlPath -ErrorAction SilentlyContinue | 
                     Sort-Object LastWriteTime -Descending | 
                     Select-Object -First 1
        
        if ($latestXml) {
            [xml]$xml = Get-Content $latestXml.FullName
            
            $scores = @{
                Processor = [math]::Round([double]$xml.WinSAT.CpuScore, 1)
                Memory = [math]::Round([double]$xml.WinSAT.MemoryScore, 1)
                Graphics = [math]::Round([double]$xml.WinSAT.GraphicsScore, 1)
                Gaming = [math]::Round([double]$xml.WinSAT.GamingScore, 1)
                Disk = [math]::Round([double]$xml.WinSAT.DiskScore, 1)
            }
            
            $baseScore = ($scores.Values | Measure-Object -Minimum).Minimum
            
            Write-Output ("📊 Índice de rendimiento de Windows (WinSAT)")
            Write-Output ("   Fecha de evaluación: {0}" -f $latestXml.LastWriteTime)
            Write-Output ""
            Write-Output ("   • Procesador: {0}" -f $scores.Processor)
            Write-Output ("   • Memoria RAM: {0}" -f $scores.Memory)
            Write-Output ("   • Gráficos: {0}" -f $scores.Graphics)
            Write-Output ("   • Gráficos de juegos: {0}" -f $scores.Gaming)
            Write-Output ("   • Disco principal: {0}" -f $scores.Disk)
            Write-Output ""
            Write-Output ("   📈 Puntuación base del sistema: {0}" -f $baseScore)
            
            # Componente más débil
            $weakest = $scores.GetEnumerator() | Sort-Object Value | Select-Object -First 1
            
            if ($baseScore -lt 5.0) {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Performance' -Subcomponent 'WinSAT:LowScore' `
                    -Message ("⚠️ Puntuación de rendimiento baja: {0}" -f $baseScore) `
                    -Causes @(
                        ('Componente más débil: {0} ({1})' -f $weakest.Key, $weakest.Value),
                        'Hardware desactualizado',
                        'Configuración no optimizada'
                    ) `
                    -Recommendations @(
                        ('Considerar actualizar: {0}' -f $weakest.Key),
                        'Optimizar configuración del sistema',
                        'Verificar drivers actualizados',
                        'Si es un disco HDD, considerar migrar a SSD'
                    ) `
                    -Data @{ BaseScore = $baseScore; WeakestComponent = $weakest.Key }
            }
            
            # Sugerencias específicas por componente débil
            if ($scores.Disk -lt 5.0) {
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Performance' -Subcomponent 'WinSAT:DiskSlow' `
                    -Message ("ℹ️ Puntuación de disco baja: {0}" -f $scores.Disk) `
                    -Recommendations @(
                        'Migrar a un SSD para mejorar significativamente el rendimiento',
                        'Desfragmentar disco si es HDD',
                        'Verificar salud del disco con CrystalDiskInfo',
                        'Asegurar que AHCI esté habilitado en BIOS'
                    )
            }
            
        } else {
            Write-DiagnosticEvent -Severity 'Info' `
                -Component 'Performance' -Subcomponent 'WinSAT:NotRun' `
                -Message "ℹ️ No se encontró evaluación de rendimiento reciente" `
                -Recommendations @(
                    'Ejecutar evaluación: winsat formal -restart clean',
                    'Nota: La evaluación puede tardar varios minutos',
                    'Se requieren permisos administrativos'
                )
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de índice de rendimiento completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Performance' -Subcomponent 'WinSAT' `
            -ContextMessage 'Error al obtener índice de rendimiento.' `
            -Recommendations @('Verificar permisos de acceso')
    }
}