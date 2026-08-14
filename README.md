# DiagnosTIC_UI — Interfaz WPF en PowerShell

Resumen
-------
DiagnosTIC_UI es una aplicación WPF implementada en Windows PowerShell 5.1 destinada a orquestar y presentar diagnósticos locales del sistema. Ejecuta módulos independientes en procesos aislados (jobs), captura su salida (texto y eventos estructurados) y presenta resultados con recomendaciones y causas. El modo remoto solo informa de que no está implementado; no abre sesiones ni ejecuta módulos locales contra otro equipo.

Características principales
-------------------------
- Ejecuta módulos independientes desde la carpeta `modules/`.
- Aislamiento de ejecución mediante jobs para mantener la UI responsiva.
- Salida estructurada (`DiagnosticEvent`) para hallazgos enriquecidos (severidad, causas, recomendaciones).
- Panel de resultados en tiempo real y log técnico.

Requisitos
----------
- Windows con PowerShell 5.1.
- .NET PresentationFramework (se carga por `main.ps1`).
- Privilegios administrativos para ciertas comprobaciones (DISM y acceso a registro). Las reparaciones se invocan aparte y no forman parte del diagnóstico por defecto.

Estructura del repositorio
--------------------------
- `main.ps1` — Punto de entrada: carga XAML, construye la UI, gestiona la cola de análisis, inicia jobs y procesa su salida.
- `ui/main.xaml` — Definición de la interfaz WPF.
- `utils/Utils.ps1` — Utilidades comunes: construcción y emisión de `DiagnosticEvent`, helpers I/O y manejo de excepciones.
- `modules/` — Módulos de diagnóstico (cada script exporta funciones `Diagnostico-<Nombre>`).
- `docs/README.md` — Documentación (este archivo).

Cómo funciona
-------------
1. La UI (`main.ps1`) carga `ui/main.xaml` y enlaza controles a variables PowerShell.
2. El usuario selecciona análisis y lanza la ejecución; cada análisis se encola y se ejecuta en un job aislado.
3. Los módulos emiten trazas (`Write-Output`) y/o objetos `DiagnosticEvent` (usando `New-DiagnosticEvent` / `Write-DiagnosticEvent`).
4. La UI consume la salida de los jobs de forma incremental y actualiza paneles, estadísticas y log.

Destinos externos
-----------------
Las comprobaciones de red usan estos valores predeterminados, configurables mediante variables de entorno: `DIAGNOSTIC_EXTERNAL_ICMP`, `DIAGNOSTIC_EXTERNAL_DNS_TCP` y `DIAGNOSTIC_EXTERNAL_HTTPS_TCP`.

Reparaciones
------------
`Diagnostico-IntegridadSistema` solo comprueba DISM y no ejecuta SFC. `Reparacion-IntegridadSistema` es una operación separada, modificadora y protegida por `ShouldProcess`; no se llama desde la UI.

Formato recomendado: `DiagnosticEvent`
----------------------------------
Se recomienda que los módulos emitan objetos `DiagnosticEvent` con la siguiente estructura mínima:
- `Type`: 'DiagnosticEvent'
- `Severity`: 'Info' | 'OK' | 'Warning' | 'Error'
- `Message`: texto principal
- `Causes`: array de cadenas (opcional)
- `Recommendations`: array de cadenas (opcional)

Ejemplo mínimo
--------------
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

Buenas prácticas para módulos
----------------------------
- No interactuar directamente con la UI desde los módulos.
- Emitir `DiagnosticEvent` para hallazgos relevantes y `Write-Output` para trazas.
- Manejar errores con `try/catch` y usar `Write-DiagnosticException` para emitir errores estructurados.
- Evitar operaciones interactivas (Read-Host) en módulos que se ejecutan en jobs.
- Mantener las comprobaciones sin efectos modificadores; las reparaciones deben exponerse como funciones separadas y solicitar confirmación.

Añadir nuevos análisis
----------------------
1. Añadir un archivo `.ps1` en `modules/`.
2. Definir la función pública `Diagnostico-<Nombre>` con `[CmdletBinding()]`.
3. Preferir `DiagnosticEvent` para resultados y `Write-Output` para logs.

Ejecución
---------
Desde la carpeta raíz del proyecto, abrir PowerShell 5.1 y ejecutar:
```powershell
.\main.ps1
```
Si necesita permitir ejecución temporalmente:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\main.ps1
```

Notas operativas
----------------
- Ejecutar como Administrador para comprobaciones que lo requieran.
- Seleccionar `Remoto` no consulta el equipo indicado: el soporte de transporte remoto no existe todavía.
- Revisar módulos antes de ejecutar en entornos de producción.
- Los jobs ofrecen aislamiento pero incrementan el uso de recursos si se lanzan muchos simultáneamente.

Extensibilidad
--------------
- Posibles mejoras: soporte para PowerShell 7+, exportación de resultados (JSON/HTML) y motor de plugins para módulos firmados.

Contacto y licencia
-------------------
SergioGL.
