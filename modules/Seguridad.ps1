# Diagnósticos de seguridad del sistema (local)
# Verificaciones: antivirus, firewall, cuentas y actualizaciones.
# Author: Galvik
. "$PSScriptRoot\..\utils\Utils.ps1"

# =================================================================================================
# Diagnóstico: Windows Defender y Antivirus
# =================================================================================================

function Diagnostico-WindowsDefender {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando estado de Windows Defender en: $equipo"
        
        # Estado de Windows Defender
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            
            if ($defenderStatus) {
                Write-Output ("🛡️ Windows Defender:")
                Write-Output ("   • Antivirus habilitado: {0}" -f $defenderStatus.AntivirusEnabled)
                Write-Output ("   • Protección en tiempo real: {0}" -f $defenderStatus.RealTimeProtectionEnabled)
                Write-Output ("   • Protección en la nube: {0}" -f $defenderStatus.CloudProtectionEnabled)
                Write-Output ("   • Protección contra manipulación: {0}" -f $defenderStatus.IsTamperProtected)
                
                # Verificar si está deshabilitado
                if (-not $defenderStatus.AntivirusEnabled) {
                    Write-DiagnosticEvent -Severity 'Error' `
                        -Component 'Security' -Subcomponent 'Defender:Disabled' `
                        -Message '❌ Windows Defender está deshabilitado' `
                        -Causes @(
                            'Deshabilitado manualmente por el usuario',
                            'Deshabilitado por política de grupo',
                            'Otro antivirus instalado tomó el control',
                            'Malware deshabilitó la protección'
                        ) `
                        -Recommendations @(
                            'Habilitar Windows Defender si no hay otro antivirus',
                            'Verificar que haya protección antivirus activa',
                            'Si fue deshabilitado por malware, ejecutar análisis offline',
                            'Comprobar políticas de grupo (gpedit.msc)'
                        )
                }
                
                if ($defenderStatus.AntivirusEnabled -and -not $defenderStatus.RealTimeProtectionEnabled) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Security' -Subcomponent 'Defender:NoRealTime' `
                        -Message '⚠️ Protección en tiempo real deshabilitada' `
                        -Causes @(
                            'Deshabilitada temporalmente por el usuario',
                            'Conflicto con otro software de seguridad',
                            'Requisitos de rendimiento'
                        ) `
                        -Recommendations @(
                            'Habilitar protección en tiempo real para máxima seguridad',
                            'Configuración > Actualización y seguridad > Seguridad de Windows',
                            'Verificar que no hay otro antivirus causando conflicto'
                        )
                }
                
                # Información de definiciones
                Write-Output ""
                Write-Output "📦 Definiciones de virus:"
                Write-Output ("   • Versión antivirus: {0}" -f $defenderStatus.AntivirusSignatureVersion)
                Write-Output ("   • Última actualización: {0}" -f $defenderStatus.AntivirusSignatureLastUpdated)
                
                # Verificar antigüedad de definiciones
                if ($defenderStatus.AntivirusSignatureLastUpdated) {
                    $daysSinceUpdate = ((Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated).Days
                    Write-Output ("   • Antigüedad: {0} días" -f $daysSinceUpdate)
                    
                    if ($daysSinceUpdate -gt 7) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Security' -Subcomponent 'Defender:OutdatedDefinitions' `
                            -Message ("⚠️ Definiciones de virus desactualizadas ({0} días)" -f $daysSinceUpdate) `
                            -Causes @(
                                'Actualizaciones automáticas deshabilitadas',
                                'Problemas de conectividad a Internet',
                                'Servicios de Windows Update no funcionando',
                                'Bloqueado por firewall o proxy'
                            ) `
                            -Recommendations @(
                                'Actualizar manualmente: Update-MpSignature',
                                'Verificar conectividad a Internet',
                                'Comprobar que Windows Update funciona',
                                'Habilitar actualizaciones automáticas de definiciones'
                            ) `
                            -Data @{ DaysSinceUpdate = $daysSinceUpdate }
                    } else {
                        Write-Output "   ✅ Definiciones actualizadas"
                    }
                }
                
                # Último análisis
                Write-Output ""
                Write-Output "🔍 Historial de análisis:"
                Write-Output ("   • Último análisis rápido: {0}" -f $defenderStatus.QuickScanEndTime)
                Write-Output ("   • Último análisis completo: {0}" -f $defenderStatus.FullScanEndTime)
                
                if ($defenderStatus.FullScanEndTime) {
                    $daysSinceFullScan = ((Get-Date) - $defenderStatus.FullScanEndTime).Days
                    
                    if ($daysSinceFullScan -gt 30) {
                        Write-DiagnosticEvent -Severity 'Info' `
                            -Component 'Security' -Subcomponent 'Defender:NoRecentFullScan' `
                            -Message ("ℹ️ No se ha realizado un análisis completo en {0} días" -f $daysSinceFullScan) `
                            -Recommendations @(
                                'Programar un análisis completo cuando el equipo esté inactivo',
                                'Ejecutar manualmente: Start-MpScan -ScanType FullScan',
                                'Los análisis completos ayudan a detectar amenazas ocultas'
                            )
                    }
                }
                
            } else {
                Write-Output "ℹ️ No se pudo obtener estado de Windows Defender (puede no estar disponible)"
            }
        } catch {
            Write-Output "⚠️ Error al consultar Windows Defender"
        }
        
        # Verificar otros antivirus instalados
        Write-Output ""
        Write-Output "🔍 Buscando otros productos antivirus..."
        
        try {
            $antivirusProducts = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
            
            if ($antivirusProducts) {
                foreach ($av in $antivirusProducts) {
                    Write-Output ("   • {0}" -f $av.displayName)
                    
                    # Interpretar estado del producto
                    $hexState = [Convert]::ToString($av.productState, 16).PadLeft(6, '0')
                    $enabled = ($hexState.Substring(2, 2) -eq '10')
                    $updated = ($hexState.Substring(4, 2) -eq '00')
                    
                    Write-Output ("     - Habilitado: {0}" -f $enabled)
                    Write-Output ("     - Actualizado: {0}" -f $updated)
                    
                    if (-not $enabled) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Security' -Subcomponent 'Antivirus:Disabled' `
                            -Message ("⚠️ Antivirus deshabilitado: {0}" -f $av.displayName) `
                            -Recommendations @(
                                'Habilitar el antivirus inmediatamente',
                                'Verificar licencia del producto',
                                'Considerar usar Windows Defender si no tiene otro antivirus'
                            )
                    }
                    
                    if (-not $updated) {
                        Write-DiagnosticEvent -Severity 'Warning' `
                            -Component 'Security' -Subcomponent 'Antivirus:Outdated' `
                            -Message ("⚠️ Antivirus desactualizado: {0}" -f $av.displayName) `
                            -Recommendations @(
                                'Actualizar definiciones del antivirus',
                                'Verificar conectividad a servidores de actualización',
                                'Comprobar que la licencia esté activa'
                            )
                    }
                }
            } else {
                Write-Output "   ℹ️ No se detectaron otros productos antivirus"
            }
        } catch {
            Write-Output "   ⚠️ No se pudo consultar SecurityCenter2"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de antivirus completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Security' -Subcomponent 'Defender' `
            -ContextMessage 'Error durante la verificación de Windows Defender.' `
            -Recommendations @('Verificar permisos y disponibilidad del servicio')
    }
}

# =================================================================================================
# Diagnóstico: Firewall de Windows
# =================================================================================================

function Diagnostico-Firewall {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando estado del Firewall de Windows en: $equipo"
        
        try {
            $firewallProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
            
            if ($firewallProfiles) {
                foreach ($profile in $firewallProfiles) {
                    Write-Output ("🔥 Perfil: {0}" -f $profile.Name)
                    Write-Output ("   • Habilitado: {0}" -f $profile.Enabled)
                    Write-Output ("   • Acción de entrada predeterminada: {0}" -f $profile.DefaultInboundAction)
                    Write-Output ("   • Acción de salida predeterminada: {0}" -f $profile.DefaultOutboundAction)
                    Write-Output ""
                    
                    if (-not $profile.Enabled) {
                        Write-DiagnosticEvent -Severity 'Error' `
                            -Component 'Security' -Subcomponent ('Firewall:Disabled:{0}' -f $profile.Name) `
                            -Message ("❌ Firewall deshabilitado en perfil: {0}" -f $profile.Name) `
                            -Causes @(
                                'Deshabilitado manualmente por el usuario o administrador',
                                'Política de grupo deshabilitó el firewall',
                                'Malware o herramientas maliciosas',
                                'Software de terceros que requiere firewall deshabilitado'
                            ) `
                            -Recommendations @(
                                'Habilitar el firewall inmediatamente para protección básica',
                                'Set-NetFirewallProfile -Profile {0} -Enabled True' -f $profile.Name,
                                'Si el software requiere excepciones, crear reglas específicas en lugar de deshabilitar',
                                'Verificar con herramientas de seguridad si fue deshabilitado por malware'
                            )
                    }
                }
                
                # Contar reglas de firewall
                $inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue
                $outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True -ErrorAction SilentlyContinue
                
                Write-Output ("📊 Reglas activas:")
                Write-Output ("   • Entrada: {0} reglas" -f $inboundRules.Count)
                Write-Output ("   • Salida: {0} reglas" -f $outboundRules.Count)
                
                # Reglas sospechosas (permitir todo el tráfico)
                $suspiciousRules = $inboundRules | Where-Object { 
                    $_.Action -eq 'Allow' -and 
                    (-not $_.RemoteAddress -or $_.RemoteAddress -eq 'Any') -and
                    (-not $_.RemotePort -or $_.RemotePort -eq 'Any')
                }
                
                if ($suspiciousRules) {
                    Write-Output ""
                    Write-Output ("⚠️ Reglas permisivas detectadas: {0}" -f $suspiciousRules.Count)
                    foreach ($rule in ($suspiciousRules | Select-Object -First 5)) {
                        Write-Output ("   • {0}" -f $rule.DisplayName)
                    }
                    
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Security' -Subcomponent 'Firewall:PermissiveRules' `
                        -Message ("⚠️ Se detectaron {0} reglas de firewall muy permisivas" -f $suspiciousRules.Count) `
                        -Causes @(
                            'Reglas creadas por software sin restricciones adecuadas',
                            'Configuración manual incorrecta',
                            'Requisitos de software legacy'
                        ) `
                        -Recommendations @(
                            'Revisar reglas en: Firewall de Windows Defender con seguridad avanzada',
                            'Restringir reglas a IPs/puertos específicos cuando sea posible',
                            'Eliminar reglas innecesarias o demasiado permisivas',
                            'Aplicar principio de menor privilegio'
                        ) `
                        -Data @{ PermissiveRulesCount = $suspiciousRules.Count }
                }
                
            } else {
                Write-Output "⚠️ No se pudo obtener información de perfiles de firewall"
            }
        } catch {
            Write-Output "⚠️ Error al consultar firewall"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de firewall completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Security' -Subcomponent 'Firewall' `
            -ContextMessage 'Error durante la verificación del firewall.' `
            -Recommendations @('Verificar que el servicio de firewall esté activo')
    }
}

# =================================================================================================
# Diagnóstico: Cuentas de Usuario y Políticas
# =================================================================================================

function Diagnostico-CuentasUsuario {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Analizando cuentas de usuario en: $equipo"
        
        # Cuentas locales
        $localUsers = Get-LocalUser -ErrorAction SilentlyContinue
        
        if ($localUsers) {
            Write-Output ("👥 Cuentas de usuario locales: {0}" -f $localUsers.Count)
            Write-Output ""
            
            foreach ($user in $localUsers) {
                $icon = if ($user.Enabled) { '✅' } else { '❌' }
                Write-Output ("{0} {1}" -f $icon, $user.Name)
                Write-Output ("   • Descripción: {0}" -f $user.Description)
                Write-Output ("   • Habilitada: {0}" -f $user.Enabled)
                Write-Output ("   • Último inicio de sesión: {0}" -f $user.LastLogon)
                Write-Output ("   • Contraseña expira: {0}" -f (-not $user.PasswordNeverExpires))
                
                # Detectar cuentas problemáticas
                if ($user.Name -match '^(Admin|Administrator)$' -and $user.Enabled) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Security' -Subcomponent 'Users:AdministratorEnabled' `
                        -Message '⚠️ Cuenta Administrator habilitada' `
                        -Causes @(
                            'Configuración predeterminada en algunas instalaciones',
                            'Habilitada por administrador para tareas específicas'
                        ) `
                        -Recommendations @(
                            'Deshabilitar cuenta Administrator si no se usa',
                            'Usar cuenta de administrador con nombre personalizado',
                            'Aplicar contraseña fuerte si debe permanecer habilitada',
                            'Monitorizar el uso de esta cuenta'
                        )
                }
                
                if ($user.PasswordNeverExpires -and $user.Enabled) {
                    Write-DiagnosticEvent -Severity 'Info' `
                        -Component 'Security' -Subcomponent 'Users:PasswordNeverExpires' `
                        -Message ("ℹ️ Usuario con contraseña que nunca expira: {0}" -f $user.Name) `
                        -Recommendations @(
                            'Considerar política de expiración de contraseñas',
                            'Asegurar que la contraseña sea fuerte',
                            'Habilitar autenticación de dos factores si es posible'
                        )
                }
                
                Write-Output ""
            }
            
            # Cuentas huérfanas (sin login reciente)
            $threshold = (Get-Date).AddDays(-90)
            $inactiveUsers = $localUsers | Where-Object { 
                $_.Enabled -and 
                $_.LastLogon -and 
                $_.LastLogon -lt $threshold 
            }
            
            if ($inactiveUsers) {
                Write-DiagnosticEvent -Severity 'Info' `
                    -Component 'Security' -Subcomponent 'Users:Inactive' `
                    -Message ("ℹ️ {0} cuenta(s) sin actividad en 90+ días" -f $inactiveUsers.Count) `
                    -Recommendations @(
                        'Revisar si las cuentas inactivas siguen siendo necesarias',
                        'Deshabilitar o eliminar cuentas que no se usan',
                        'Reducir superficie de ataque limitando cuentas activas'
                    )
                
                foreach ($inactive in $inactiveUsers) {
                    Write-Output ("   ⏸️ Inactiva: {0} (último login: {1})" -f $inactive.Name, $inactive.LastLogon)
                }
            }
        }
        
        # Grupos de administradores
        Write-Output ""
        Write-Output "👑 Miembros del grupo Administradores:"
        try {
            $adminGroup = Get-LocalGroupMember -Group "Administradores" -ErrorAction SilentlyContinue
            if (-not $adminGroup) {
                $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            }
            
            if ($adminGroup) {
                foreach ($member in $adminGroup) {
                    Write-Output ("   • {0} ({1})" -f $member.Name, $member.ObjectClass)
                }
                
                if ($adminGroup.Count -gt 3) {
                    Write-DiagnosticEvent -Severity 'Warning' `
                        -Component 'Security' -Subcomponent 'Users:TooManyAdmins' `
                        -Message ("⚠️ Muchos usuarios en grupo Administradores: {0}" -f $adminGroup.Count) `
                        -Causes @(
                            'Exceso de privilegios otorgados',
                            'Falta de segregación de tareas',
                            'Configuración poco segura'
                        ) `
                        -Recommendations @(
                            'Aplicar principio de menor privilegio',
                            'Usar cuentas estándar para uso diario',
                            'Limitar administradores solo a personal autorizado',
                            'Considerar usar UAC para elevación temporal'
                        ) `
                        -Data @{ AdminCount = $adminGroup.Count }
                }
            }
        } catch {
            Write-Output "   ⚠️ No se pudo enumerar grupo de administradores"
        }
        
        Write-Output ""
        Write-Output "✅ Análisis de cuentas completado"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Security' -Subcomponent 'Users' `
            -ContextMessage 'Error durante el análisis de cuentas.' `
            -Recommendations @('Verificar permisos para consultar cuentas locales')
    }
}

# =================================================================================================
# Diagnóstico: Actualizaciones de Seguridad
# =================================================================================================

function Diagnostico-ActualizacionesSeguridad {
    [CmdletBinding()]
    param([string]$equipo)
    
    try {
        Write-Output "🔎 Verificando actualizaciones de seguridad en: $equipo"
        
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            
            Write-Output "🔍 Buscando actualizaciones de seguridad pendientes..."
            $searchResult = $searcher.Search("IsInstalled=0 and Type='Software'")
            
            $securityUpdates = $searchResult.Updates | Where-Object { 
                $_.Categories | Where-Object { $_.Name -match 'Security|Críticas|Critical' }
            }
            
            if ($securityUpdates.Count -gt 0) {
                Write-DiagnosticEvent -Severity 'Error' `
                    -Component 'Security' -Subcomponent 'Updates:SecurityPending' `
                    -Message ("❌ Hay {0} actualizaciones de seguridad pendientes" -f $securityUpdates.Count) `
                    -Causes @(
                        'Windows Update deshabilitado o con problemas',
                        'Usuario postponiendo actualizaciones',
                        'Problemas de conectividad',
                        'Espacio insuficiente en disco'
                    ) `
                    -Recommendations @(
                        'Instalar actualizaciones de seguridad INMEDIATAMENTE',
                        'Configuración > Actualización y seguridad > Windows Update',
                        'Reiniciar el equipo después de instalar',
                        'Habilitar actualizaciones automáticas',
                        'Las actualizaciones de seguridad protegen contra vulnerabilidades conocidas'
                    ) `
                    -Data @{ SecurityUpdatesCount = $securityUpdates.Count }
                
                Write-Output ""
                Write-Output "🚨 Actualizaciones de seguridad críticas:"
                foreach ($update in ($securityUpdates | Select-Object -First 10)) {
                    Write-Output ("   • {0}" -f $update.Title)
                }
            } else {
                Write-Output "✅ No hay actualizaciones de seguridad pendientes"
            }
            
        } catch {
            Write-Output "⚠️ No se pudo verificar Windows Update (puede requerir permisos administrativos)"
        }
        
        Write-Output ""
        Write-Output "✅ Verificación de actualizaciones de seguridad completada"
        
    } catch {
        Write-DiagnosticException -Exception $_.Exception `
            -Severity 'Error' -Component 'Security' -Subcomponent 'SecurityUpdates' `
            -ContextMessage 'Error durante la verificación de actualizaciones de seguridad.' `
            -Recommendations @('Ejecutar con permisos administrativos')
    }
}