
# Diagnósticos de red (local)
# Provee comprobaciones de conectividad, puerta de enlace, resolución DNS y estado de adaptadores.
# Emite trazas con `Write-Output` y resultados enriquecidos mediante `DiagnosticEvent` (ver `utils/Utils.ps1`).
#
# Diseño:
# - Las funciones públicas siguen la convención `Diagnostico-<Nombre>` y se ejecutan desde `main.ps1`.
# - Para hallazgos relevantes se recomienda usar `Write-DiagnosticEvent`/`New-DiagnosticEvent`.
#
# Author: Galvik
. "$PSScriptRoot\..\utils\Utils.ps1"

# -------------------------------------------------------------------------------------------------
# Utilidades internas para el módulo `Network`
# Funciones auxiliares no expuestas directamente por la UI.
# -------------------------------------------------------------------------------------------------

function ConvertTo-StringList {
    [CmdletBinding()]
    param(
        [Parameter()]
        $Value
    )
    if ($null -eq $Value) { return @() }

    if ($Value -is [System.Array]) {
        return @($Value | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }

    return @([string]$Value)
}

function Get-PrimaryGatewayIPv4 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Adapters,

        [Parameter(Mandatory = $true)]
        [bool]$UseNetCmds
    )

    if (-not $Adapters) { return $null }

    try {
        if ($UseNetCmds) {
            $primary = $Adapters |
                Where-Object { $_.IPv4Address -and $_.IPv4DefaultGateway } |
                Select-Object -First 1

            if (-not $primary) { return $null }
            return $primary.IPv4DefaultGateway.NextHop
        } else {
            $primary = $Adapters |
                Where-Object { $_.DefaultIPGateway } |
                Select-Object -First 1

            if (-not $primary) { return $null }
            return $primary.DefaultIPGateway[0]
        }
    } catch {
        return $null
    }
}

function Test-GatewayReachability {
    <#
      Devuelve $true/$false si se alcanza gateway; en caso de error de cmdlets, lanza excepción.
      Intenta usar parámetros de interfaz/origen cuando estén disponibles.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GatewayIPv4,

        [Parameter()]
        [string]$InterfaceAlias,

        [Parameter()]
        [string]$SourceIPv4
    )

    $tncCmd = Get-Command -Name Test-NetConnection -ErrorAction SilentlyContinue
    $tcCmd  = Get-Command -Name Test-Connection  -ErrorAction SilentlyContinue

    $tncHasIface = $false
    $tcHasSource = $false

    if ($tncCmd -and $tncCmd.Parameters) { $tncHasIface = $tncCmd.Parameters.ContainsKey('InterfaceAlias') }
    if ($tcCmd  -and $tcCmd.Parameters)  { $tcHasSource = $tcCmd.Parameters.ContainsKey('Source') }

    # Prioridad: Test-NetConnection con InterfaceAlias > Test-Connection con Source > ping -S > ping normal
    if ($tncCmd -and $tncHasIface -and $InterfaceAlias) {
        $tnc = Test-NetConnection -ComputerName $GatewayIPv4 -InterfaceAlias $InterfaceAlias -WarningAction SilentlyContinue
        if ($tnc -and ($tnc.PingSucceeded -or $tnc.TcpTestSucceeded)) { return $true }
        return $false
    }

    if ($tcCmd -and $tcHasSource -and $SourceIPv4) {
        return (Test-Connection -ComputerName $GatewayIPv4 -Source $SourceIPv4 -Count 2 -Quiet -ErrorAction SilentlyContinue)
    }

    if ($SourceIPv4) {
        $null = & cmd.exe /c "ping -n 2 -S $SourceIPv4 $GatewayIPv4" 2>$null
        return ($LASTEXITCODE -eq 0)
    }

    return (Test-Connection -ComputerName $GatewayIPv4 -Count 2 -Quiet -ErrorAction SilentlyContinue)
}

# -------------------------------------------------------------------------------------------------
# Diagnóstico: Conectividad
# -------------------------------------------------------------------------------------------------

function Diagnostico-Conectividad {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$equipo
    )

    try {
        Write-Output ("🔎 Iniciando diagnóstico de conectividad para: {0}" -f $equipo)

        $useNetCmds = (Get-Command -Name Get-NetIPConfiguration -ErrorAction SilentlyContinue) -ne $null

        if ($useNetCmds) {
            $adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address -or $_.IPv6Address }
        } else {
            $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
        }

        if (-not $adapters) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Network' -Subcomponent 'Connectivity:IPConfiguration' `
                -Message '❌ No se encontró configuración de red válida (sin IP activa).' `
                -Causes @(
                    'No hay adaptadores con IP configurada',
                    'Adaptador deshabilitado o sin conectividad',
                    'Fallo del stack de red o servicios relacionados'
                ) `
                -Recommendations @(
                    'Verificar que el adaptador esté habilitado y conectado',
                    'Comprobar configuración IP (DHCP/estática) y estado del enlace',
                    'Reiniciar servicios de red o el equipo si persiste'
                )
            return
        }

        foreach ($a in $adapters) {
            if ($useNetCmds) {
                $name = $a.InterfaceAlias

                $ips = @()
                $ips += ($a.IPv4Address | ForEach-Object { $_.IPAddress })
                $ips += ($a.IPv6Address | ForEach-Object { $_.IPAddress })

                $gw = (@($a.IPv4DefaultGateway, $a.Ipv6DefaultGateway) |
                        Where-Object { $_ } |
                        ForEach-Object { $_.NextHop } |
                        Where-Object { $_ }) -join ', '

                $mac = (Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue).MacAddress
            } else {
                $name = $a.Description
                $ips  = ConvertTo-StringList $a.IPAddress
                $gw   = (ConvertTo-StringList $a.DefaultIPGateway | Where-Object { $_ }) -join ', '
                $mac  = $a.MACAddress
            }

            Write-Output ("📡 Adaptador: {0}" -f $name)
            Write-Output ("   • IP(s): {0}" -f ([string]::Join(', ', ($ips | Where-Object { $_ }))))
            Write-Output ("   • MAC: {0}" -f $mac)
            Write-Output ("   • Puerta de enlace: {0}" -f $gw)
        }

        $gwIp = Get-PrimaryGatewayIPv4 -Adapters $adapters -UseNetCmds:$useNetCmds

        if (-not $gwIp) {
            Write-DiagnosticEvent -Severity 'Warning' `
                -Component 'Network' -Subcomponent 'Connectivity:DefaultGateway' `
                -Message '⚠️ No se detectó adaptador con puerta de enlace por defecto (IPv4).' `
                -Causes @(
                    'Conexión no enrutable (solo red local o sin gateway)',
                    'Configuración IP incompleta (DHCP fallido o estática parcial)',
                    'Tabla de rutas incompleta o corrompida'
                ) `
                -Recommendations @(
                    'Comprobar configuración IP/DHCP del adaptador',
                    'Revisar la puerta de enlace configurada y la tabla de rutas',
                    'Si procede, renovar DHCP (ipconfig /renew)'
                )
        } else {
            Write-Output ("⏱️ Ping a la puerta de enlace ({0})..." -f $gwIp)
            $gwOk = Test-Connection -ComputerName $gwIp -Count 3 -Quiet -ErrorAction SilentlyContinue

            if ($gwOk) {
                Write-Output "✅ Puerta de enlace responde."
            } else {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Network' -Subcomponent 'Connectivity:GatewayPing' `
                    -Message ("❌ Sin respuesta desde la puerta de enlace ({0})." -f $gwIp) `
                    -Causes @(
                        'Fallo de conectividad física (cable/Wi-Fi)',
                        'Gateway caído o inaccesible',
                        'ICMP bloqueado por firewall o políticas'
                    ) `
                    -Recommendations @(
                        'Verificar enlace del adaptador y conectividad a la red',
                        'Probar la puerta de enlace desde otro equipo',
                        'Revisar firewall/políticas de seguridad en el gateway y el cliente'
                    )
            }

            Write-Output "⏱️ Ping a 8.8.8.8 (ICMP)..."
            $ext = Test-Connection -ComputerName 8.8.8.8 -Count 4 -Quiet -ErrorAction SilentlyContinue
            if ($ext) {
                Write-Output "✅ Conectividad externa (ICMP) OK."
            } else {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Network' -Subcomponent 'Connectivity:ExternalICMP' `
                    -Message '⚠️ No se alcanzó 8.8.8.8 por ICMP.' `
                    -Causes @(
                        'ICMP bloqueado por firewall o ISP',
                        'Salida a Internet restringida o sin NAT',
                        'Problema de rutas hacia el exterior'
                    ) `
                    -Recommendations @(
                        'Validar navegación/HTTP y pruebas TCP (puerto 443)',
                        'Revisar políticas firewall corporativas/ISP',
                        'Comprobar ruta por defecto y resolución DNS'
                    )
            }

            Write-Output "🔌 Prueba TCP a 8.8.8.8:53 y 1.1.1.1:443..."
            if (Get-Command -Name Test-NetConnection -ErrorAction SilentlyContinue) {
                try {
                    $t1 = Test-NetConnection -ComputerName 8.8.8.8 -Port 53 -WarningAction SilentlyContinue -InformationLevel Detailed
                    if ($t1.TcpTestSucceeded) { Write-Output "✅ TCP 8.8.8.8:53 OK." } else { Write-Output "⚠️ TCP 8.8.8.8:53 falló." }
                } catch {
                    Write-DiagnosticEvent -Severity 'Info' `
                        -Component 'Network' -Subcomponent 'Connectivity:TCP53' `
                        -Message 'ℹ️ No fue posible ejecutar Test-NetConnection hacia 8.8.8.8:53.' `
                        -Causes @(
                            'Cmdlet no disponible o restringido',
                            'Permisos insuficientes para pruebas de red',
                            'Entorno con políticas de ejecución o módulos limitados'
                        ) `
                        -Recommendations @(
                            'Ejecutar el diagnóstico con permisos adecuados',
                            'Validar disponibilidad de Test-NetConnection',
                            'Probar conectividad TCP con herramientas alternativas (telnet/nc) si aplica'
                        )
                }

                try {
                    $t2 = Test-NetConnection -ComputerName 1.1.1.1 -Port 443 -WarningAction SilentlyContinue -InformationLevel Detailed
                    if ($t2.TcpTestSucceeded) { Write-Output "✅ TCP 1.1.1.1:443 OK." } else { Write-Output "⚠️ TCP 1.1.1.1:443 falló." }
                } catch {
                    Write-DiagnosticEvent -Severity 'Info' `
                        -Component 'Network' -Subcomponent 'Connectivity:TCP443' `
                        -Message 'ℹ️ No fue posible ejecutar Test-NetConnection hacia 1.1.1.1:443.' `
                        -Causes @(
                            'Cmdlet no disponible o restringido',
                            'Permisos insuficientes',
                            'Políticas de seguridad limitando pruebas'
                        ) `
                        -Recommendations @(
                            'Ejecutar como administrador si procede',
                            'Verificar cmdlets disponibles en el entorno',
                            'Validar salida a Internet mediante navegación HTTPS'
                        )
                }
            } else {
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Network' -Subcomponent 'Connectivity:TestNetConnection' `
                    -Message 'ℹ️ Test-NetConnection no está disponible en este equipo.' `
                    -Causes @(
                        'Versión de Windows/PowerShell sin el cmdlet',
                        'Módulos de red no presentes'
                    ) `
                    -Recommendations @(
                        'Usar Test-Connection y herramientas del sistema (ping/tracert)',
                        'Actualizar componentes/versión si se requiere esta funcionalidad'
                    )
            }

            Write-Output "🗺️ Trazado de ruta a 8.8.8.8 (tracert, primeras líneas)..."
            try {
                tracert -d -h 10 8.8.8.8 2>$null |
                    Select-Object -First 6 |
                    ForEach-Object { Write-Output ("    {0}" -f $_) }
            } catch {
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Network' -Subcomponent 'Connectivity:Tracert' `
                    -Message 'ℹ️ No se pudo ejecutar tracert en este entorno.' `
                    -Causes @('Herramienta no disponible o ejecución restringida') `
                    -Recommendations @('Probar manualmente tracert desde CMD o revisar políticas de ejecución')
            }
        }

        try {
            $def = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
            if ($def) {
                Write-Output ("📍 Ruta por defecto: NextHop={0} InterfaceIndex={1}" -f $def.NextHop, $def.InterfaceIndex)
            }
        } catch { }

        try { arp -a | Select-Object -First 6 | ForEach-Object { Write-Output ("🔁 {0}" -f $_) } } catch { }

        try {
            $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            if ($fw) {
                foreach ($p in $fw) {
                    Write-Output ("🔒 Firewall ({0}): Enabled={1} Inbound={2} Outbound={3}" -f $p.Name, $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction)
                }
            }
        } catch { }

        Write-Output "✅ Diagnóstico de conectividad completado."
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Network' -Subcomponent 'Connectivity:Unhandled' `
            -ContextMessage 'Error no controlado durante el diagnóstico de conectividad.' `
            -Causes @('Excepción inesperada en cmdlets de red o acceso a información del sistema') `
            -Recommendations @('Revisar permisos, logs del sistema y disponibilidad de cmdlets en el equipo')
    }
}

# -------------------------------------------------------------------------------------------------
# Diagnóstico: DHCP
# -------------------------------------------------------------------------------------------------

function Diagnostico-DHCP {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$equipo
    )

    try {
        Write-Output ("🔎 Iniciando comprobaciones DHCP para: {0}" -f $equipo)

        $configs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        if (-not $configs) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Network' -Subcomponent 'DHCP:Adapters' `
                -Message '❌ No se encontró ningún adaptador con IP habilitada.' `
                -Causes @(
                    'Adaptadores deshabilitados',
                    'Stack de red no inicializado',
                    'Restricción de WMI/CIM o permisos insuficientes'
                ) `
                -Recommendations @(
                    'Verificar estado del adaptador en el sistema',
                    'Ejecutar el diagnóstico con permisos administrativos',
                    'Revisar servicios WMI y de red'
                )
            return
        }

        foreach ($c in $configs) {
            $name = $c.Description
            $dhcpEnabled = if ($c.DHCPEnabled) { 'Sí' } else { 'No' }
            $dhcpServer  = $c.DHCPServer
            $ip          = (ConvertTo-StringList $c.IPAddress) -join ', '

            Write-Output ("📡 Adaptador: {0}" -f $name)
            Write-Output ("   • IP: {0}" -f $ip)
            Write-Output ("   • DHCP habilitado: {0}" -f $dhcpEnabled)

            if ($c.DHCPEnabled) {
                Write-Output ("   • Servidor DHCP: {0}" -f $dhcpServer)

                if ($dhcpServer) {
                    $dhcpPing = Test-Connection -ComputerName $dhcpServer -Count 2 -Quiet -ErrorAction SilentlyContinue
                    if ($dhcpPing) {
                        Write-Output ("   ✅ Servidor DHCP ({0}) responde a ping." -f $dhcpServer)
                    } else {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Network' -Subcomponent ("DHCP:Server:{0}" -f $name) `
                            -Message ("⚠️ No se alcanzó el servidor DHCP ({0})." -f $dhcpServer) `
                            -Causes @(
                                'Servidor DHCP inaccesible o caído',
                                'Segmentación/VLAN o rutas impiden acceso',
                                'Firewall bloquea ICMP o tráfico necesario'
                            ) `
                            -Recommendations @(
                                'Validar conectividad L2/L3 al servidor DHCP',
                                'Revisar VLAN, rutas y reglas de firewall',
                                'Comprobar en el servidor logs/estado del servicio DHCP'
                            )
                    }
                } else {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Network' -Subcomponent ("DHCP:Server:{0}" -f $name) `
                        -Message '⚠️ El adaptador reporta DHCP habilitado pero no informa servidor DHCP.' `
                        -Causes @(
                            'Lease no obtenido o expirado',
                            'Fallo en negociación DHCP (Discover/Offer/Request/Ack)',
                            'Problemas de broadcast/DHCP relay'
                        ) `
                        -Recommendations @(
                            'Renovar DHCP (ipconfig /release & ipconfig /renew)',
                            'Comprobar presencia de DHCP relay si hay VLANs',
                            'Revisar eventos del sistema relacionados con DHCP'
                        )
                }

                if ($c.DHCPLeaseExpires -and $c.DHCPLeaseObtained) {
                    Write-Output ("   • Lease obtenido: {0}  |  Expira: {1}" -f $c.DHCPLeaseObtained, $c.DHCPLeaseExpires)
                } else {
                    Write-Output "   • Información de lease no disponible."
                }

                try {
                    $svc = Get-Service -Name Dhcp -ErrorAction SilentlyContinue
                    if ($svc) {
                        Write-Output ("   • Servicio DHCP cliente: {0}" -f $svc.Status)
                        if ($svc.Status -ne 'Running') {
                            Write-DiagnosticEvent -Severity 'Warning' `
                                -Component 'Network' -Subcomponent ("DHCP:Service:{0}" -f $name) `
                                -Message '⚠️ El servicio "Dhcp" (cliente DHCP) no se está ejecutando.' `
                                -Causes @(
                                    'Servicio detenido por política o error',
                                    'Dependencias no disponibles',
                                    'Restricción de administración del equipo'
                                ) `
                                -Recommendations @(
                                    'Iniciar el servicio DHCP Client y establecer inicio automático',
                                    'Revisar dependencias (Network Store Interface, etc.)',
                                    'Consultar el Visor de eventos del sistema para causas del fallo'
                                )
                        }
                    } else {
                        Write-DiagnosticEvent -Severity 'Info' `
                            -Component 'Network' -Subcomponent ("DHCP:Service:{0}" -f $name) `
                            -Message 'ℹ️ Servicio DHCP cliente no encontrado en este equipo.' `
                            -Causes @('Edición/rol del sistema o componentes no instalados') `
                            -Recommendations @('Verificar versión/edición de Windows y servicios disponibles')
                    }
                } catch { }

                try {
                    $ev = Get-WinEvent -FilterHashtable @{
                        LogName      = 'System'
                        ProviderName = 'Dhcp'
                        StartTime    = (Get-Date).AddDays(-1)
                    } -MaxEvents 10 -ErrorAction SilentlyContinue

                    if ($ev) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Network' -Subcomponent ("DHCP:Events:{0}" -f $name) `
                            -Message '⚠️ Se detectaron eventos recientes del cliente DHCP (últimas 24h).' `
                            -Causes @(
                                'Pérdida de lease o renovación fallida',
                                'Conectividad intermitente hacia el servidor DHCP',
                                'Conflictos de IP o problemas de broadcast'
                            ) `
                            -Recommendations @(
                                'Revisar detalles de eventos DHCP en el Visor de eventos (System)',
                                'Validar estabilidad de enlace y configuración de red',
                                'Verificar si hay conflictos de IP en la red'
                            ) `
                            -Data @{ SampleEventId = ($ev | Select-Object -First 1).Id }

                        foreach ($e in ($ev | Select-Object -First 5)) {
                            $m = ($e.Message -replace "`r`n", ' ')
                            Write-Output ("       ID {0} [{1}]: {2}" -f $e.Id, $e.TimeCreated, $m)
                        }
                    } else {
                        Write-Output "   ✅ Sin eventos críticos del cliente DHCP en las últimas 24h."
                    }
                } catch {
                    Write-DiagnosticEvent -Severity 'Info' `
                        -Component 'Network' -Subcomponent ("DHCP:Events:{0}" -f $name) `
                        -Message 'ℹ️ No se pudieron leer eventos DHCP en este entorno.' `
                        -Causes @('Permisos insuficientes o logging restringido') `
                        -Recommendations @('Ejecutar con permisos adecuados o revisar configuración del Visor de eventos')
                }
            } else {
                if ($ip -match '^169\.254\.') {
                    Write-DiagnosticEvent -Severity 'Error' `
                        -Component 'Network' -Subcomponent ("DHCP:APIPA:{0}" -f $name) `
                        -Message '❌ IP autoconfigurada (169.254.x.x) — probable fallo de DHCP.' `
                        -Causes @(
                            'Servidor DHCP no responde',
                            'Problema de conectividad L2 (cable/puerto/VLAN)',
                            'Bloqueo de broadcast DHCP o ausencia de relay'
                        ) `
                        -Recommendations @(
                            'Comprobar enlace del adaptador y pertenencia a VLAN correcta',
                            'Verificar servidor DHCP o relay',
                            'Renovar DHCP y revisar eventos del sistema'
                        )
                } else {
                    Write-Output "   ℹ️ DHCP deshabilitado; IP estática configurada."
                }
            }
        }

        Write-Output "✅ Comprobaciones DHCP completadas."
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Network' -Subcomponent 'DHCP:Unhandled' `
            -ContextMessage 'Error no controlado durante comprobaciones DHCP.' `
            -Causes @('Excepción inesperada leyendo CIM/WMI o eventos del sistema') `
            -Recommendations @('Revisar permisos y disponibilidad de WMI/EventLog en el equipo')
    }
}

# -------------------------------------------------------------------------------------------------
# Diagnóstico: Adaptador de red
# -------------------------------------------------------------------------------------------------

function Diagnostico-AdaptadorRed {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$equipo
    )

    try {
        Write-Output ("🔎 Inspección detallada de adaptadores de red para: {0}" -f $equipo)

        $useNetCmds = (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) -ne $null

        if ($useNetCmds) {
            $adpts = Get-NetAdapter -Physical | Sort-Object -Property InterfaceDescription
        } else {
            $adpts = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetEnabled -eq $true }
        }

        if (-not $adpts) {
            Write-DiagnosticEvent -Severity 'Error' `
                -Component 'Network' -Subcomponent 'Adapter:Discovery' `
                -Message '❌ No se encontraron adaptadores de red activos.' `
                -Causes @(
                    'Adaptadores deshabilitados',
                    'Drivers no instalados o en fallo',
                    'Restricciones de consulta (WMI/CIM) o permisos'
                ) `
                -Recommendations @(
                    'Verificar adaptadores en Administrador de dispositivos',
                    'Reinstalar/actualizar drivers del adaptador',
                    'Ejecutar el diagnóstico con privilegios administrativos'
                )
            return
        }

        foreach ($ad in $adpts) {

            # ---------------------------
            # Recogida de información base
            # ---------------------------
            $alias   = $null
            $status  = $null
            $link    = $null
            $ifIndex = $null
            $desc    = $null
            $mac     = $null
            $mtu     = $null
            $stats   = $null
            $ipconf  = $null

            if ($useNetCmds) {
                $alias   = $ad.InterfaceAlias
                $status  = $ad.Status
                $link    = $ad.LinkSpeed
                $ifIndex = $ad.IfIndex
                $desc    = $ad.InterfaceDescription
                $mac     = $ad.MacAddress

                $stats  = Get-NetAdapterStatistics -Name $alias -ErrorAction SilentlyContinue
                $ipconf = Get-NetIPConfiguration -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue

                $mtu = (Get-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty NlMtu -First 1)
                if (-not $mtu) {
                    $mtu = (Get-NetIPInterface -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty NlMtu -First 1)
                }
                if (-not $mtu) { $mtu = 'N/D' }
            } else {
                $alias  = $ad.Name
                $status = if ($ad.NetEnabled) { 'Up' } else { 'Down' }
                $desc   = $ad.Description
                $mac    = $ad.MACAddress
                $link   = 'N/D'
                $mtu    = 'N/D'

                $ipconf = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "Index=$($ad.Index)" -ErrorAction SilentlyContinue
            }

            Write-Output ("📡 Adaptador: {0}  — {1}" -f $alias, $desc)
            Write-Output ("   • Estado: {0}  • LinkSpeed: {1}  • MAC: {2}  • MTU: {3}" -f $status, $link, $mac, $mtu)

            # ---------------------------
            # IP / Gateway / DNS
            # ---------------------------
            $ips = @()
            $gw  = ''
            $dns = ''

            if ($ipconf) {
                if ($useNetCmds) {
                    $ips += ($ipconf.IPv4Address | ForEach-Object { $_.IPAddress })
                    $ips += ($ipconf.IPv6Address | ForEach-Object { $_.IPAddress })

                    $gw = (@($ipconf.IPv4DefaultGateway, $ipconf.IPv6DefaultGateway) |
                           Where-Object { $_ } |
                           ForEach-Object { $_.NextHop } |
                           Where-Object { $_ }) -join ', '

                    $dns = ($ipconf.DnsServer.ServerAddresses -join ', ')
                } else {
                    $ips += ConvertTo-StringList $ipconf.IPAddress
                    $gw  = (ConvertTo-StringList $ipconf.DefaultIPGateway) -join ', '
                    $dns = (ConvertTo-StringList $ipconf.DNSServerSearchOrder) -join ', '
                }

                Write-Output ("   • IP(s): {0}" -f ([string]::Join(', ', ($ips | Where-Object { $_ }))))
                Write-Output ("   • Gateway: {0}" -f $gw)
                Write-Output ("   • DNS: {0}" -f $dns)
            }

            # ---------------------------
            # Estadísticas de adaptador (paquetes y errores)
            # ---------------------------
            if ($stats) {
                $rxU = Get-ObjectPropertyValue $stats 'ReceivedUnicastPackets'
                if ($null -eq $rxU) { $rxU = Get-ObjectPropertyValue $stats 'InboundUnicastPackets' }

                $rxB = Get-ObjectPropertyValue $stats 'ReceivedBroadcastPackets'
                if ($null -eq $rxB) { $rxB = Get-ObjectPropertyValue $stats 'InboundBroadcastPackets' }

                $rxM = Get-ObjectPropertyValue $stats 'ReceivedMulticastPackets'
                if ($null -eq $rxM) { $rxM = Get-ObjectPropertyValue $stats 'InboundMulticastPackets' }

                $rxList = @($rxU, $rxB, $rxM) | Where-Object { $_ -ne $null }
                $rx = if ($rxList.Count -gt 0) { ($rxList | Measure-Object -Sum).Sum } else { $null }

                $txU = Get-ObjectPropertyValue $stats 'OutboundUnicastPackets'
                if ($null -eq $txU) { $txU = Get-ObjectPropertyValue $stats 'SentUnicastPackets' }

                $txB = Get-ObjectPropertyValue $stats 'OutboundBroadcastPackets'
                if ($null -eq $txB) { $txB = Get-ObjectPropertyValue $stats 'SentBroadcastPackets' }

                $txM = Get-ObjectPropertyValue $stats 'OutboundMulticastPackets'
                if ($null -eq $txM) { $txM = Get-ObjectPropertyValue $stats 'SentMulticastPackets' }

                $txList = @($txU, $txB, $txM) | Where-Object { $_ -ne $null }
                $tx = if ($txList.Count -gt 0) { ($txList | Measure-Object -Sum).Sum } else { $null }

                $rxErr = Get-ObjectPropertyValue $stats 'InboundErrors'
                if ($null -eq $rxErr) { $rxErr = Get-ObjectPropertyValue $stats 'ReceivedErrors' }

                $txErr = Get-ObjectPropertyValue $stats 'OutboundErrors'
                if ($null -eq $txErr) { $txErr = Get-ObjectPropertyValue $stats 'SentErrors' }

                $txDisplay     = if ($tx -ne $null) { $tx } else { 'N/D' }
                $rxDisplay     = if ($rx -ne $null) { $rx } else { 'N/D' }
                $rxErrDisplay  = if ($rxErr -ne $null) { $rxErr } else { 'N/D' }
                $txErrDisplay  = if ($txErr -ne $null) { $txErr } else { 'N/D' }

                Write-Output ("   • Paquetes enviados: {0}  Recibidos: {1}" -f $txDisplay, $rxDisplay)

                # Si faltan errores, emitir evento enriquecido (para pintar causas/sugerencias debajo)
                if ($null -eq $rxErr -or $null -eq $txErr) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Network' -Subcomponent ("AdapterStats:{0}" -f $alias) `
                        -Message "• Errores de recepción: N/D  Errores de envío: N/D" `
                        -Causes @(
                            'El controlador NIC no expone contadores de error',
                            'La API (Get-NetAdapterStatistics) no devuelve dichas métricas en esta versión',
                            'Permisos insuficientes para consultar estadísticas del adaptador'
                        ) `
                        -Recommendations @(
                            'Actualizar el controlador (driver) de la tarjeta de red',
                            'Ejecutar el diagnóstico con privilegios administrativos',
                            'Verificar compatibilidad de cmdlets en la versión de Windows/PowerShell'
                        )
                } else {
                    Write-Output ("   • Errores de recepción: {0}  Errores de envío: {1}" -f $rxErrDisplay, $txErrDisplay)
                }
            } else {
                Write-Output "   • Paquetes enviados: N/D  Recibidos: N/D"
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Network' -Subcomponent ("AdapterStats:{0}" -f $alias) `
                    -Message "• Errores de recepción: N/D  Errores de envío: N/D" `
                    -Causes @(
                        'Estadísticas no disponibles desde la API del adaptador',
                        'Controlador o sistema no expone contadores',
                        'Restricciones de acceso (permisos/políticas)'
                    ) `
                    -Recommendations @(
                        'Actualizar controlador NIC',
                        'Actualizar Windows/PowerShell si aplica',
                        'Ejecutar el diagnóstico con permisos administrativos'
                    )
            }

            # ---------------------------
            # Propiedades avanzadas relevantes
            # ---------------------------
            try {
                if ($useNetCmds) {
                    $adv = Get-NetAdapterAdvancedProperty -Name $alias -ErrorAction SilentlyContinue
                    if ($adv) {
                        $interesting = $adv | Where-Object { $_.DisplayName -match 'Large Send Offload|Checksum|Vlan|RSS|Receive Side Scaling|Wake on|Prioridad|VLAN' }
                        if ($interesting) {
                            Write-Output "   • Propiedades avanzadas relevantes:"
                            foreach ($p in $interesting) {
                                Write-Output ("       - {0}: {1}" -f $p.DisplayName, $p.DisplayValue)
                            }
                        }
                    }
                }
            } catch { }

            # ---------------------------
            # Prueba de gateway desde el adaptador
            # ---------------------------
            try {
                $gwFirst = $null
                if ($gw) { $gwFirst = ($gw -split ',')[0].Trim() }

                $srcV4 = ($ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)

                if ($gwFirst -and $srcV4) {
                    Write-Output "   ⏱️ Ping a gateway desde adaptador..."
                    $ok = Test-GatewayReachability -GatewayIPv4 $gwFirst -InterfaceAlias $alias -SourceIPv4 $srcV4

                    if ($ok) {
                        Write-Output ("   ✅ Gateway accesible desde {0}" -f $alias)
                    } else {
                        Write-DiagnosticEvent -Severity 'Error' `
                            -Component 'Network' -Subcomponent ("Gateway:{0}" -f $alias) `
                            -Message ("❌ No se pudo alcanzar gateway desde {0}" -f $alias) `
                            -Causes @(
                                'Gateway inaccesible (cable/desconexión/VLAN)',
                                'ICMP bloqueado por firewall o políticas',
                                'Problemas de rutas o configuración IP en el adaptador'
                            ) `
                            -Recommendations @(
                                'Verificar enlace físico y estado del adaptador',
                                'Revisar firewall/políticas (cliente y red)',
                                'Comprobar configuración IP, máscara, gateway y tabla de rutas'
                            )
                    }
                }
            } catch {
                # Emitir evento enriquecido anclado a este punto (sin duplicar texto)
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Network' -Subcomponent ("Gateway:{0}" -f $alias) `
                    -Message 'ℹ️ Prueba de gateway: error inesperado. Se intentará ping simple.' `
                    -Causes @(
                        'Falta de permisos para pruebas avanzadas de conectividad',
                        'El cmdlet Test-NetConnection no soporta parámetros por interfaz en esta versión',
                        'IP origen o alias de interfaz no válido',
                        'Reglas de firewall o políticas bloqueando ICMP/TCP'
                    ) `
                    -Recommendations @(
                        'Ejecutar el diagnóstico como administrador',
                        'Probar manualmente: ping -S <ip_origen> <gateway>',
                        'Revisar reglas de firewall y políticas de seguridad',
                        'Verificar configuración IP/alias y tabla de rutas'
                    )

                # Fallback simple (texto normal) para decidir si hay conectividad mínima
                try {
                    $gwFirst2 = $null
                    if ($gw) { $gwFirst2 = ($gw -split ',')[0].Trim() }
                    if ($gwFirst2) {
                        $ok2 = Test-Connection -ComputerName $gwFirst2 -Count 2 -Quiet -ErrorAction SilentlyContinue
                        if ($ok2) {
                            Write-Output ("   ✅ Gateway accesible desde {0}" -f $alias)
                        } else {
                            Write-DiagnosticEvent -Severity 'Error' `
                                -Component 'Network' -Subcomponent ("Gateway:{0}:Fallback" -f $alias) `
                                -Message ("❌ No se pudo alcanzar gateway desde {0} (fallback)" -f $alias) `
                                -Causes @(
                                    'Gateway incorrecto o en conflicto',
                                    'Bloqueo de salida por firewall/políticas',
                                    'Problemas de enrutamiento'
                                ) `
                                -Recommendations @(
                                    'Verificar IP de gateway y probar desde otro equipo',
                                    'Revisar reglas de seguridad y firewall',
                                    'Comprobar tabla de rutas y configuración del adaptador'
                                )
                        }
                    }
                } catch { }
            }

            # ---------------------------
            # Vecinos ARP (breve)
            # ---------------------------
            try {
                if ($useNetCmds -and $ifIndex) {
                    $neigh = Get-NetNeighbor -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
                             Where-Object { $_.IPAddress -and $_.LinkLayerAddress } |
                             Select-Object -First 5
                    if ($neigh) {
                        Write-Output "   • Vecinos ARP (breve):"
                        foreach ($n in $neigh) {
                            Write-Output ("       {0,-18}  {1,-17}  {2}" -f $n.IPAddress, $n.LinkLayerAddress, $n.State)
                        }
                    }
                } else {
                    $srcIp = ($ips | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' } | Select-Object -First 1)
                    if ($srcIp) {
                        $arp = arp -a 2>$null
                        $inBlock = $false
                        $count = 0
                        Write-Output "   • Vecinos ARP (breve):"
                        foreach ($line in $arp) {
                            if ($line -match "^Interfaz:\s+$([Regex]::Escape($srcIp))\s+---") { $inBlock = $true; continue }
                            if ($inBlock -and $line -match "^Interfaz:\s+") { break }
                            if ($inBlock -and $line -match "^\s*\d") {
                                Write-Output ("       {0}" -f $line)
                                $count++
                                if ($count -ge 5) { break }
                            }
                        }
                    }
                }
            } catch { }

            # ---------------------------
            # Proxy WinHTTP
            # ---------------------------
            try {
                $proxy = & netsh winhttp show proxy 2>$null
                if ($proxy) {
                    Write-Output "   • Proxy WinHTTP:"
                    foreach ($l in $proxy) { Write-Output ("       {0}" -f $l) }
                }
            } catch { }

            # ---------------------------
            # Versión del driver (si se puede correlacionar)
            # ---------------------------
            try {
                $drv = Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                       Where-Object { $_.DeviceName -eq $desc } |
                       Select-Object -First 1
                if ($drv) {
                    Write-Output ("   • Driver: {0}  ({1})" -f $drv.DriverVersion, $drv.DriverDate)
                }
            } catch { }

            # ---------------------------
            # Rutas principales por interfaz
            # ---------------------------
            try {
                if ($useNetCmds -and $ifIndex) {
                    $routes = Get-NetRoute -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
                              Sort-Object -Property RouteMetric |
                              Select-Object -First 5
                    if ($routes) {
                        Write-Output "   • Rutas (top 5 por métrica):"
                        foreach ($r in $routes) {
                            $nh = if ($r.NextHop) { $r.NextHop } else { '(direct)' }
                            Write-Output ("       {0,-18} via {1,-15} metric {2}" -f $r.DestinationPrefix, $nh, $r.RouteMetric)
                        }
                    }
                }
            } catch { }

            Write-Output "--------------------------------------------------"
        }

        Write-Output "✅ Inspección de adaptadores completada."
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Network' -Subcomponent 'Adapter:Unhandled' `
            -ContextMessage 'Error no controlado durante la inspección de adaptadores de red.' `
            -Causes @('Excepción inesperada consultando cmdlets de red o CIM/WMI') `
            -Recommendations @('Revisar permisos, estado de servicios de red y drivers del adaptador')
    }
}

        # -------------------------------------------------------------------------------------------------
        # Diagnóstico: DNS (integrado en Network)
        # -------------------------------------------------------------------------------------------------

        function Diagnostico-DNS {
            [CmdletBinding()]
            param(
                [Parameter()]
                [string]$equipo
            )

            try {
                Write-Output ("🔎 Iniciando diagnóstico DNS para: {0}" -f $equipo)

                # Obtener servidores DNS configurados por interfaz
                $dnsServers = @()
                if (Get-Command -Name Get-NetIPConfiguration -ErrorAction SilentlyContinue) {
                    $dnsServers = (Get-NetIPConfiguration | ForEach-Object { $_.DnsServer.ServerAddresses } | Where-Object { $_ } | Select-Object -Unique)
                } else {
                    $cfgs = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
                    $dnsServers = ($cfgs | ForEach-Object { $_.DNSServerSearchOrder } | Where-Object { $_ } | ForEach-Object { $_ }) | Select-Object -Unique
                }

                if (-not $dnsServers -or $dnsServers.Count -eq 0) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Network' -Subcomponent 'DNS:Discovery' `
                        -Message '⚠️ No se detectaron servidores DNS configurados en el equipo.' `
                        -Causes @('No hay servidores DNS configurados', 'Adaptador sin IP o configuración incompleta') `
                        -Recommendations @('Verificar configuración de adaptadores y servidores DNS')
                    return
                }

                # Nombres de prueba (configurable)
                $namesToTest = @('example.com','microsoft.com')

                $results = @()

                foreach ($server in $dnsServers) {
                    foreach ($name in $namesToTest) {
                        $item = [ordered]@{
                            Server = $server
                            Name   = $name
                            Method = ''
                            Status = 'Unknown'
                            RTTms  = $null
                            Records = @()
                            Raw    = ''
                        }

                        $sw = [Diagnostics.Stopwatch]::StartNew()
                        try {
                            if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                                $item.Method = 'Resolve-DnsName'
                                $r = Resolve-DnsName -Name $name -Server $server -ErrorAction Stop
                                $sw.Stop()
                                $item.RTTms = [int]$sw.ElapsedMilliseconds
                                $item.Status = 'OK'
                                $item.Records = $r | ForEach-Object { $_.NameHost + ' ' + $_.IPAddress } 
                                $item.Raw = ($r | Out-String)
                            } else {
                                # nslookup fallback
                                $item.Method = 'nslookup'
                                $out = & nslookup $name $server 2>&1
                                $sw.Stop()
                                $item.RTTms = [int]$sw.ElapsedMilliseconds
                                $item.Raw = ($out -join "`n")
                                if ($out -match 'Address:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})') { $item.Status = 'OK' ; $item.Records = @($Matches[1]) } else { $item.Status = 'Fail' }
                            }
                        } catch {
                            $sw.Stop()
                            $item.RTTms = [int]$sw.ElapsedMilliseconds
                            $item.Status = 'Fail'
                            $item.Raw = $_.Exception.Message
                        }

                        $results += (New-Object PSObject -Property $item)
                        Write-Output ("DNS Test -> Server: {0}  Name: {1}  Status: {2}  RTT: {3}ms" -f $server, $name, $item.Status, ($item.RTTms -as [string]))
                    }
                }

                # Consistencia entre servidores (por nombre)
                foreach ($name in $namesToTest) {
                    $byName = $results | Where-Object { $_.Name -eq $name -and $_.Status -eq 'OK' }
                    $ips = ($byName | ForEach-Object { $_.Records } | ForEach-Object { $_ }) | Select-Object -Unique
                    if ($ips.Count -gt 1) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Network' -Subcomponent ('DNS:Consistency:{0}' -f $name) `
                            -Message ("⚠️ Respuestas inconsistentes para {0} entre servidores: {1}" -f $name, ($ips -join ', ')) `
                            -Causes @('Replicación DNS incompleta', 'Registros distintos en servidores primario/secundario') `
                            -Recommendations @('Revisar sincronización entre servidores DNS', 'Verificar la configuración de la zona en servidores autoritativos')
                    }
                }

                # Reverse lookup de IPs obtenidas
                $ipsFound = ($results | Where-Object { $_.Records } | ForEach-Object { $_.Records } | ForEach-Object { $_ }) | ForEach-Object {
                    if ($_ -match '([0-9]{1,3}(?:\.[0-9]{1,3}){3})') { $Matches[1] } else { $_ }
                } | Select-Object -Unique

                foreach ($ip in $ipsFound) {
                    try {
                        if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                            $rptr = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
                            Write-Output ("PTR for {0}: {1}" -f $ip, ($rptr.NameHost -join ', '))
                        } else {
                            $out = & nslookup $ip 2>&1
                            Write-Output ("PTR (nslookup) for {0}: {1}" -f $ip, ($out -join ' | '))
                        }
                    } catch {
                        Write-DiagnosticEvent -Severity 'Info' `
                            -Component 'Network' -Subcomponent ('DNS:PTR:{0}' -f $ip) `
                            -Message ("ℹ️ No se obtuvo PTR para {0}: {1}" -f $ip, $_.Exception.Message) `
                            -Recommendations @('Verificar zona inversa y delegaciones PTR si procede')
                    }
                }

                # Resumen simple
                $failCount = ($results | Where-Object { $_.Status -ne 'OK' }).Count
                if ($failCount -gt 0) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Network' -Subcomponent 'DNS:Summary' `
                        -Message ("⚠️ Se detectaron {0} pruebas DNS con fallos o inconsistencias." -f $failCount) `
                        -Recommendations @('Revisar servidores DNS configurados y conectividad', 'Ejecutar pruebas detalladas con -Verbose')
                } else {
                    Write-DiagnosticEvent -Severity 'OK' `
                        -Component 'Network' -Subcomponent 'DNS:Summary' `
                        -Message '✅ Comprobaciones DNS básicas completadas sin incidencias.'
                }

                Write-Output "✅ Diagnóstico DNS completado."
            } catch {
                Write-DiagnosticException -Exception $_.Exception `
                    -Severity 'Error' -Component 'Network' -Subcomponent 'DNS:Unhandled' `
                    -ContextMessage 'Error no controlado durante el diagnóstico DNS.' `
                    -Recommendations @('Revisar permisos y disponibilidad de cmdlets de resolución DNS')
            }
        }

        # ---------------------------
        # Pruebas adicionales: UDP reachability, EDNS, DNSSEC, AXFR
        # ---------------------------

        function Build-DnsQueryBytes {
            param([string]$Name, [int]$Type = 1, [int]$TxId = $null, [bool]$WithOpt = $false)
            if ($null -eq $TxId) { $TxId = Get-Random -Minimum 0 -Maximum 65535 }

            $bytes = New-Object System.Collections.Generic.List[byte]
            # Transaction ID
            $bytes.AddRange([BitConverter]::GetBytes([uint16]$TxId))
            # Flags: standard query 0x0100 (recursion desired)
            $bytes.Add(0x01); $bytes.Add(0x00)
            # QDCOUNT (1)
            $bytes.Add(0x00); $bytes.Add(0x01)
            # ANCOUNT (0)
            $bytes.Add(0x00); $bytes.Add(0x00)
            # NSCOUNT (0)
            $bytes.Add(0x00); $bytes.Add(0x00)
            # ARCOUNT (1 if WithOpt)
            if ($WithOpt) { $bytes.Add(0x00); $bytes.Add(0x01) } else { $bytes.Add(0x00); $bytes.Add(0x00) }

            # Question section (QNAME)
            foreach ($label in ($Name -split '\.')) {
                $len = [byte]$label.Length
                $bytes.Add($len)
                $bytes.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
            }
            $bytes.Add(0x00) # term
            # QTYPE
            $bytes.AddRange([byte[]]([BitConverter]::GetBytes([uint16]([System.Net.IPAddress]::HostToNetworkOrder([int16]$Type)))))
            # QCLASS IN (1)
            $bytes.Add(0x00); $bytes.Add(0x01)

            if ($WithOpt) {
                # OPT record (simplified): NAME=0, TYPE=41, UDP payload size 4096, EXT RCODE 0, VERSION 0, Z 0, RDLEN 0
                $bytes.Add(0x00) # root
                $bytes.Add(0x00); $bytes.Add(0x29) # TYPE 41
                $bytes.Add(0x10); $bytes.Add(0x00) # UDP payload size 4096 (0x1000) -> big-endian
                $bytes.Add(0x00); $bytes.Add(0x00) # EXT RCODE + VERSION
                $bytes.Add(0x00); $bytes.Add(0x00) # Z
                $bytes.Add(0x00); $bytes.Add(0x00) # RDLEN 0
            }

            return ,$bytes.ToArray()
        }

        function Test-DnsUdpReachability {
            param([string]$Server, [string]$Name = 'example.com', [int]$TimeoutMs = 2000)
            $udp = New-Object System.Net.Sockets.UdpClient
            $addr = [System.Net.IPAddress]::Parse($Server)
            $ep = New-Object System.Net.IPEndPoint $addr, 53

            try {
                $q = Build-DnsQueryBytes -Name $Name -Type 1 -WithOpt:$false
                $null = $udp.Send($q, $q.Length, $ep)
                $async = $udp.BeginReceive($null, $null)
                if ($async.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                    $res = $udp.EndReceive($async, [ref]$ep)
                    return @{ Ok = $true; Len = $res.Length; Data = $res }
                } else {
                    return @{ Ok = $false; Len = 0; Data = $null }
                }
            } catch {
                return @{ Ok = $false; Len = 0; Data = $_.Exception.Message }
            } finally { $udp.Close() }
        }

        foreach ($server in $dnsServers) {
            # UDP reachability
            $udpRes = Test-DnsUdpReachability -Server $server -Name $namesToTest[0]
            if ($udpRes.Ok) {
                Write-Output ("UDP DNS reachable {0} (bytes={1})" -f $server, $udpRes.Len)
            } else {
                Write-DiagnosticEvent -Severity 'Warning' `
                    -Component 'Network' -Subcomponent ('DNS:UDPReach:{0}' -f $server) `
                    -Message ("⚠️ No se recibió respuesta UDP desde {0}." -f $server) `
                    -Causes @('Servidor no responde UDP/53','Firewall bloqueando UDP','Problema de red entre cliente y servidor') `
                    -Recommendations @('Verificar firewall/ACLs','Probar consulta DNS manual con nslookup/Resolve-DnsName')
            }

            # EDNS probe (send query with OPT)
            try {
                $udp = New-Object System.Net.Sockets.UdpClient
                $addr = [System.Net.IPAddress]::Parse($server)
                $ep = New-Object System.Net.IPEndPoint $addr, 53
                $qOpt = Build-DnsQueryBytes -Name $namesToTest[0] -Type 1 -WithOpt:$true
                $null = $udp.Send($qOpt, $qOpt.Length, $ep)
                $async = $udp.BeginReceive($null, $null)
                if ($async.AsyncWaitHandle.WaitOne(2000)) {
                    $res = $udp.EndReceive($async, [ref]$ep)
                    $len = $res.Length
                    if ($len -gt 512) {
                        Write-Output ("EDNS likely supported by {0} (resp bytes={1})" -f $server, $len)
                    } else {
                        Write-Output ("EDNS probe returned {0} bytes from {1}" -f $len, $server)
                    }
                } else {
                    Write-Output ("EDNS probe timed out for {0}" -f $server)
                }
                $udp.Close()
            } catch {
                Write-Output ("EDNS probe error for {0}: {1}" -f $server, $_.Exception.Message)
            }

            # DNSSEC: try to request RRSIG/DNSKEY or use Resolve-DnsName -DnssecOk
            try {
                if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
                    $dnssecOk = $false
                    try {
                        $r = Resolve-DnsName -Name $namesToTest[0] -Server $server -DnssecOk -ErrorAction Stop
                        if ($r) { $dnssecOk = $true }
                    } catch { }

                    if ($dnssecOk) {
                        Write-Output ("DNSSEC: server {0} returned DNSSEC-OK responses." -f $server)
                    } else {
                        # fallback: request RRSIG type
                        try {
                            $rr = Resolve-DnsName -Name $namesToTest[0] -Type RRSIG -Server $server -ErrorAction Stop
                            if ($rr) { Write-Output ("DNSSEC: RRSIG present for {0} on {1}." -f $namesToTest[0], $server) }
                        } catch { Write-Output ("DNSSEC: no evidence for DNSSEC on {0} via {1}." -f $namesToTest[0], $server) }
                    }
                } else {
                    Write-Output 'DNSSEC: Resolve-DnsName not available to check DNSSEC.'
                }
            } catch { }

            # AXFR (zone transfer) attempt - non-intrusive; only detect if server allows AXFR publicly
            try {
                $dom = $namesToTest[0]
                $out = & nslookup -type=AXFR $dom $server 2>&1
                $joined = ($out -join "`n")
                if ($joined -match 'Transfer failed|connection refused|no transfer') {
                    Write-Output ("AXFR refused or failed against {0} for zone {1}" -f $server, $dom)
                } elseif ($joined -match 'Name:\s') {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Network' -Subcomponent ('DNS:AXFR:{0}' -f $server) `
                        -Message ("⚠️ Servidor {0} permite AXFR para la zona {1}." -f $server, $dom) `
                        -Causes @('Servidor DNS mal configurado permite transferencia de zona pública') `
                        -Recommendations @('Restringir AXFR a servidores autorizados', 'Verificar configuración del servidor DNS')
                } else {
                    Write-Output ("AXFR: no público en {0} para {1}" -f $server, $dom)
                }
            } catch {
                Write-Output ("AXFR check error for {0}: {1}" -f $server, $_.Exception.Message)
            }
        }
