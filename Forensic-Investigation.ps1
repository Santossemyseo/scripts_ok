#Requires -Version 5.1
<#
.SYNOPSIS
  Forensic-Investigation.ps1
  Recoleccion forense segura para archivo/carpeta con foco en DRP, Hyper-V y Azure.
 
.DESCRIPTION
  Version mejorada de V1.6.1. Mantiene ejecucion de solo lectura sobre el objetivo y agrega:
  - FEATURE: Inventario forense de archivos .zip bajo C:\DRP y/o la ruta del objetivo.
    Nuevas funciones Get-ZipFileEntry y Get-ZipInventory reportan por cada ZIP:
      * Existencia, tamano, fechas de creacion y modificacion.
      * Hash SHA256 para cadena de custodia.
      * Indice interno completo (lista de entradas del zip sin extraer ningun archivo),
        incluyendo nombre de entrada, tamano comprimido/original y fecha de modificacion.
      * Estado de bloqueo y errores de lectura del indice.
    El inventario se exporta a csv\zip_inventory_<timestamp>.csv e incluye una fila por
    cada entrada interna (no una fila por zip), lo que permite verificar archivo a archivo
    si el contenido esperado del DRP esta presente dentro de cada paquete.
  - Correcciones de estabilidad heredadas de V1.6.1 (FIX#1 al FIX#4).
 
.NOTES
  Requiere permisos de Administrador para varias validaciones.
  No modifica auditorias, politicas ni archivos del objetivo.
#>
 
[CmdletBinding()]
param(
    [string]$TargetPath,
    [string]$BasePath = 'C:\DRP\reporte',
    [ValidateSet('NDJSON','CSV','BOTH')][string]$LogFormat = 'BOTH',
    [string]$LogPath = '',
    [switch]$RotateLogs,
    [int]$MaxLogSizeMB = 50,
    [int]$MaxSecurityEventsToScan = 5000,
    [int]$MaxSecurityMatches = 100,
    [int]$EventLookbackYears = 2,
    [switch]$NoSelfElevate,
    [switch]$NonInteractive,
    [switch]$Force
)
 
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
 
function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    Write-Host 'Funcion Test-IsAdministrator ejecutada'
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
 
function Start-SelfElevation {
    if ($NoSelfElevate -or (Test-IsAdministrator)) { return }
 
    Write-Host 'Elevando permisos...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($TargetPath) { $argList += @('-TargetPath', "`"$TargetPath`"") }
    if ($BasePath) { $argList += @('-BasePath', "`"$BasePath`"") }
    $argList += @('-MaxSecurityEventsToScan', $MaxSecurityEventsToScan)
    $argList += @('-MaxSecurityMatches', $MaxSecurityMatches)
    $argList += @('-EventLookbackYears', $EventLookbackYears)
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    exit
}
 
function Initialize-ReportFolders {
    param([Parameter(Mandatory=$true)][string]$RootPath)
 
    foreach ($subFolder in @('logs', 'evidencia', 'csv', 'json', 'resumen', 'manifest')) {
        $path = Join-Path $RootPath $subFolder
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    Write-Host 'Funcion Initialize-ReportFolders ejecutada'
}
 
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 60) -ForegroundColor Cyan
    Write-Host (' {0}' -f $Title) -ForegroundColor Cyan
    Write-Host ('=' * 60) -ForegroundColor Cyan
}
 
function Invoke-Log {
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level = 'INFO',
        [string]$EventId = 'GENERIC',
        [string]$Message = '',
        [object]$Details = $null
    )
 
    try {
        if ($LogFormat -eq 'CSV') { return }
        $entry = [ordered]@{
            timestampUtc = (Get-Date).ToUniversalTime().ToString('o')
            level = $Level
            eventId = $EventId
            actor = "$env:USERNAME"
            targetPath = $TargetPath
            message = $Message
            details = $Details
            runId = $RunId
            stepId = $global:StepId
        }
        $global:StepId = $global:StepId + 1
        $jsonLine = $entry | ConvertTo-Json -Depth 8 -Compress
        Add-Content -Path $ndjsonPath -Value $jsonLine -Encoding UTF8
        Write-Host "${Level}: $EventId - $Message"
    } catch {
        # Best-effort logging; do not break main flow
    }
}
 
function Write-ErrorLog {
    param(
        [Parameter(Mandatory=$true)][System.Exception]$Exception,
        [string]$Context = ''
    )
    Write-Host 'Funcion Write-ErrorLog ejecutada'
    try {
        $time = (Get-Date).ToString('o')
        $text = "[$time] CONTEXT=$Context MESSAGE=$($Exception.Message) STACK=$($Exception.StackTrace)"
        Add-Content -Path $errorLogPath -Value $text -Encoding UTF8
        Invoke-Log -Level 'ERROR' -EventId 'EXCEPTION' -Message $Exception.Message -Details @{ Context = $Context; Stack = $Exception.StackTrace }
    } catch {
        # swallow
    }
}
 
function Get-SafePathInfo {
    param([Parameter(Mandatory=$true)][string]$InputPath)
    Write-Host 'Funcion Get-SafePathInfo ejecutada'
    try {
        $resolved = Resolve-Path -LiteralPath $InputPath -ErrorAction Stop
        return Get-Item -LiteralPath $resolved.Path -Force -ErrorAction Stop
    } catch {
        return $null
    }
}
 
function ConvertTo-NormalizedPath {
    param([string]$InputPath)
    Write-Host 'Funcion ConvertTo-NormalizedPath ejecutada'
    if ([string]::IsNullOrWhiteSpace($InputPath)) { return $null }
 
    try {
        return [IO.Path]::GetFullPath($InputPath).TrimEnd('\').ToUpperInvariant()
    } catch {
        return $InputPath.TrimEnd('\').ToUpperInvariant()
    }
}
 
function Get-ReadableFileSystemAclAudit {
    param([Parameter(Mandatory=$true)][string]$InputPath)
    Write-Host 'Funcion Get-ReadableFileSystemAclAudit ejecutada'
    try {
        $audit = (Get-Acl -LiteralPath $InputPath).Audit
        if ($null -eq $audit) { return @() }
        return @($audit)
    } catch {
        return @()
    }
}
 
function Get-FileHashSafe {
    param([Parameter(Mandatory=$true)][string]$InputPath)
    Write-Host 'Funcion Get-FileHashSafe ejecutada'
    try {
        if (Test-IsFileLocked -Path $InputPath) {
            Invoke-Log -Level 'WARN' -EventId 'FILE_LOCKED' -Message 'File locked, skipping hash' -Details @{ Path = $InputPath }
            return $null
        }
        return (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        Invoke-Log -Level 'ERROR' -EventId 'HASH_ERROR' -Message $_.Exception.Message -Details @{ Path = $InputPath }
        return $null
    }
}
 
function Test-IsFileLocked {
    param([Parameter(Mandatory=$true)][string]$Path)
    Write-Host 'Funcion Test-IsFileLocked ejecutada'
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
        if ($stream) { $stream.Close(); $stream.Dispose() }
        return $false
    } catch {
        return $true
    }
}
 
function Get-AuditPolicyText {
    Write-Host 'Funcion Get-AuditPolicyText ejecutada'
    try {
        $output = & auditpol.exe /get /category:* 2>&1
 
        if ($LASTEXITCODE -ne 0) {
            return "ERROR auditpol exit code: $LASTEXITCODE"
        }
 
        return ($output | Out-String)
    } catch {
        return 'No disponible'
    }
}
 
function Get-USNStatus {
    try {
        fsutil usn queryjournal C: *> $null
        if ($LASTEXITCODE -eq 0) { return 'ACTIVO' }
        return 'NO DISPONIBLE'
    } catch {
        return 'ERROR'
    }
}
 
function Get-SysmonStatus {
    try {
        $svc = Get-Service -Name *sysmon* -ErrorAction SilentlyContinue
        if ($svc) { return 'INSTALADO' }
        return 'NO INSTALADO'
    } catch {
        return 'ERROR'
    }
}
 
function Get-LimitedSecurityEvents {
    param(
        [Parameter(Mandatory=$true)][string]$InputPath,
        [int]$MaxEventsToScan = 5000,
        [int]$MaxMatches = 100
    )
    Write-Host 'Funcion Get-LimitedSecurityEvents ejecutada'
 
    $leaf = Split-Path -Path $InputPath -Leaf
    if ([string]::IsNullOrWhiteSpace($leaf)) { return @() }
 
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(4656,4660,4663) } -MaxEvents $MaxEventsToScan -ErrorAction SilentlyContinue
        return @($events |
            Where-Object { $_.Message -like "*$leaf*" -or $_.Message -like "*$InputPath*" } |
            Select-Object -First $MaxMatches TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    } catch {
        return @()
    }
}
 
function Get-HyperVModuleAvailable {
    Write-Host 'Funcion Get-HyperVModuleAvailable ejecutada'
    try { return [bool](Get-Module -ListAvailable -Name Hyper-V) }
    catch { return $false }
}
 
function Get-HyperVVMMSEvents {
    param(
        [Parameter(Mandatory=$true)][string[]]$SearchTerms,
        [int]$LookbackYears = 2
    )
 
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Hyper-V-VMMS-Admin'
            StartTime = (Get-Date).AddYears(-1 * $LookbackYears)
        } -ErrorAction SilentlyContinue
 
        return @($events | Where-Object {
            $message = $_.Message
            @($SearchTerms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $message -match [regex]::Escape($_) }).Count -gt 0
        })
    } catch {
        return @()
    }
}
 
function Get-TargetHyperVInfo {
    param(
        [Parameter(Mandatory=$true)][string]$InputPath,
        [Parameter(Mandatory=$true)][object]$Item,
        [Parameter(Mandatory=$true)][string]$ReportRoot,
        [Parameter(Mandatory=$true)][string]$TimeStamp,
        [int]$LookbackYears = 2
    )
    Write-Host 'Funcion Get-TargetHyperVInfo ejecutada'
 
    $result = [ordered]@{
        TargetIsHyperV = $false; HyperV_DiskPath = $null; HyperV_VhdType = $null; HyperV_FileSizeGB = $null
        HyperV_MaxSizeGB = $null; HyperV_ParentPath = $null; HyperV_Fragmentation = $null; HyperV_VMName = $null
        HyperV_VMState = $null; HyperV_VMCreationTime = $null; HyperV_CheckpointType = $null; HyperV_SnapshotCount = $null
        HyperV_Exports = 0; HyperV_MergeStart = 0; HyperV_MergeEnd = 0; HyperV_Checkpoints = 0
        HyperV_CheckpointDeletes = 0; HyperV_AVHDXCount = 0; HyperV_TimelineFile = $null; HyperV_Error = $null
        HyperV_DynamicToFixedSignal = $null
    }
 
    if ($Item.Extension -notin @('.vhd', '.vhdx', '.avhdx')) { return [pscustomobject]$result }
    if (-not (Get-HyperVModuleAvailable)) {
        $result.HyperV_Error = 'Modulo Hyper-V no disponible'
        return [pscustomobject]$result
    }
 
    try {
        Import-Module Hyper-V -ErrorAction SilentlyContinue | Out-Null
        $vhd = Get-VHD -Path $InputPath -ErrorAction Stop
        $result.TargetIsHyperV = $true
        $result.HyperV_DiskPath = $vhd.Path
        $result.HyperV_VhdType = $vhd.VhdType
        $result.HyperV_FileSizeGB = [math]::Round(($vhd.FileSize / 1GB), 2)
        $result.HyperV_MaxSizeGB = [math]::Round(($vhd.Size / 1GB), 2)
        $result.HyperV_ParentPath = $vhd.ParentPath
        $result.HyperV_Fragmentation = $vhd.FragmentationPercentage
 
        if ($vhd.VhdType -eq 'Dynamic') { $result.HyperV_DynamicToFixedSignal = 'ORIGEN_DYNAMIC' }
        elseif ($vhd.VhdType -eq 'Fixed') { $result.HyperV_DynamicToFixedSignal = 'DESTINO_FIXED' }
 
        $normalizedTarget = ConvertTo-NormalizedPath -InputPath $InputPath
 
        $vmMatch = @(Get-VMHardDiskDrive -ErrorAction SilentlyContinue | Where-Object {
            try {
                $vmPath = ConvertTo-NormalizedPath $_.Path
                return $vmPath -eq $normalizedTarget
            } catch {
                return $false
            }
        } | Select-Object -First 1)
 
        if ($vmMatch.Count -gt 0) {
            $vmName = $vmMatch[0].VMName
            $result.HyperV_VMName = $vmName
 
            try {
                $vm = Get-VM -Name $vmName -ErrorAction Stop
                $result.HyperV_VMState = $vm.State.ToString()
                $result.HyperV_VMCreationTime = $vm.CreationTime
                $result.HyperV_CheckpointType = $vm.CheckpointType.ToString()
            } catch { }
 
            $snapshots = @(Get-VMSnapshot -VMName $vmName -ErrorAction SilentlyContinue)
            $result.HyperV_SnapshotCount = $snapshots.Count
 
            $vmmsEvents = Get-HyperVVMMSEvents -SearchTerms @($vmName, [IO.Path]::GetFileName($InputPath)) -LookbackYears $LookbackYears
            $result.HyperV_Exports = @($vmmsEvents | Where-Object { $_.Id -eq 18303 }).Count
            $result.HyperV_MergeStart = @($vmmsEvents | Where-Object { $_.Id -eq 19070 }).Count
            $result.HyperV_MergeEnd = @($vmmsEvents | Where-Object { $_.Id -eq 19080 }).Count
            $result.HyperV_Checkpoints = @($vmmsEvents | Where-Object { $_.Id -in 14050,14070,14075,14076 }).Count
            $result.HyperV_CheckpointDeletes = @($vmmsEvents | Where-Object { $_.Id -in 14051,14071,14077 }).Count
 
            if ($vmmsEvents.Count -gt 0) {
                $timelineFile = Join-Path $ReportRoot ("csv\HyperVTimeline_{0}.csv" -f $TimeStamp)
                $vmmsEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message | Sort-Object TimeCreated |
                    Export-Csv -Path $timelineFile -NoTypeInformation -Encoding UTF8
                $result.HyperV_TimelineFile = $timelineFile
            }
        }
 
        $folder = Split-Path -Path $InputPath -Parent
        if (Test-Path -LiteralPath $folder) {
            $result.HyperV_AVHDXCount = @(Get-ChildItem -LiteralPath $folder -Recurse -File -Filter *.avhdx -ErrorAction SilentlyContinue).Count
        }
    } catch {
        $result.HyperV_Error = $_.Exception.Message
    }
 
    return [pscustomobject]$result
}
 
function Get-DRPScriptInventory {
    param([Parameter(Mandatory=$true)][string]$RootPath)
    Write-Host 'Funcion Get-DRPScriptInventory ejecutada'
 
    $items = @()
    foreach ($pattern in @('crea*.ps1', 'conver*.ps1', 'cargue*.ps1', 'orquestador*.ps1', '*drp*.ps1', '*azcopy*.ps1')) {
        $items += @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue)
    }
    return @($items | Sort-Object FullName -Unique)
}
 
function Get-AzCopyLogInventory {
    Write-Host 'Funcion Get-AzCopyLogInventory ejecutada'
 
    $roots = @()
    if ($env:USERPROFILE) { $roots += (Join-Path $env:USERPROFILE '.azcopy') }
    if ($env:ProgramData) { $roots += (Join-Path $env:ProgramData 'AzCopy') }
 
    $results = @()
    foreach ($root in ($roots | Sort-Object -Unique)) {
        if (Test-Path -LiteralPath $root) {
            $results += @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue)
        }
    }
    return @($results | Sort-Object FullName -Unique)
}
 
function Get-VHDMetadataSafe {
    <#
    Obtiene metadata de un VHD/VHDX usando el cmdlet Get-VHD (Hyper-V), si el módulo está disponible.
    Si falla o no está disponible, retorna un objeto con campos en $null y registra el error en el log.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
 
    $result = [pscustomobject]@{
        VhdType       = $null
        SizeBytes     = $null
        FileSizeBytes = $null
        ParentPath    = $null
        Fragmentation = $null
    }
 
    if (-not (Get-HyperVModuleAvailable)) {
        return $result
    }
 
    try {
        Import-Module Hyper-V -ErrorAction SilentlyContinue | Out-Null
        $v = Get-VHD -Path $Path -ErrorAction Stop
 
        $result.VhdType       = $v.VhdType
        $result.SizeBytes     = $v.Size
        $result.FileSizeBytes = $v.FileSize
        $result.ParentPath    = $v.ParentPath
        $result.Fragmentation = $v.FragmentationPercentage
    } catch {
        Write-Host "Error al obtener metadata para: $Path"
        Invoke-Log -Level 'WARN' -EventId 'VHD_METADATA_ERROR' -Message $_.Exception.Message -Details @{ Path = $Path }
    }
 
    Write-Host "Funcion Get-VHDMetadataSafe ejecutada y resultado obtenido para $Path"
 
    return $result
}
 
function Get-VHDFileEntry {
    <#
    Construye el objeto de inventario para un único archivo VHD/VHDX: combina metadata de Hyper-V
    y el hash SHA256 (si el archivo no está bloqueado). Registra en el log cualquier error de hash.
    #>
    param([Parameter(Mandatory=$true)][System.IO.FileInfo]$File)
 
    Write-Host 'Funcion Get-VHDFileEntry ejecutada'
 
    $metadata = Get-VHDMetadataSafe -Path $File.FullName
 
    Write-Host "Metadata obtenida para: $($File.FullName)"
 
    $sha256     = $null
    $fileLocked = $false
 
    try {
        $sha256 = Get-FileHashSafe -InputPath $File.FullName
        if ($null -eq $sha256) {
            $fileLocked = $true
        }
    } catch {
        Invoke-Log -Level 'ERROR' -EventId 'VHD_HASH_ERROR' -Message $_.Exception.Message -Details @{ Path = $File.FullName }
        $sha256     = $null
        $fileLocked = $true
    }
 
    [pscustomobject]@{
        FullName        = $File.FullName
        Name            = $File.Name
        Length          = $File.Length
        CreationTime    = $File.CreationTime
        LastWriteTime   = $File.LastWriteTime
        VhdType         = $metadata.VhdType
        SizeBytes       = $metadata.SizeBytes
        FileSizeBytes   = $metadata.FileSizeBytes
        ParentPath      = $metadata.ParentPath
        Fragmentation   = $metadata.Fragmentation
        StorageType     = $metadata.VhdType
        SHA256          = $sha256
        FileLocked      = $fileLocked
    }
}
 
function Get-VHDInventory {
    <#
    Busca recursivamente archivos .vhd, .vhdx y .avhdx bajo $RootPath, elimina duplicados
    y genera el inventario completo (metadata + hash) llamando a Get-VHDFileEntry por cada archivo.
    #>
    param([Parameter(Mandatory=$true)][string]$RootPath)
 
    Write-Host 'Funcion Get-VHDInventory ejecutada'
 
    $files = foreach ($pattern in @('*.vhd', '*.vhdx', '*.avhdx')) {
        Get-ChildItem -LiteralPath $RootPath -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue
    }
 
    $uniqueFiles = $files | Sort-Object FullName -Unique
 
    return @($uniqueFiles | ForEach-Object { Get-VHDFileEntry -File $_ })
}
 
function Get-ZipFileEntry {
    <#
    Construye el objeto de inventario para un unico archivo .zip:
      - Metadata del archivo en disco (tamano, fechas, hash SHA256).
      - Indice interno del zip usando System.IO.Compression.ZipFile (solo lectura,
        sin extraer ningun archivo), con una fila por cada entrada interna.
    Si el zip esta corrupto o bloqueado, registra el error y retorna una fila
    de error en vez de propagar la excepcion.
    #>
    param([Parameter(Mandatory=$true)][System.IO.FileInfo]$File)
 
    Write-Host "Funcion Get-ZipFileEntry ejecutada para: $($File.FullName)"
 
    # Hash del archivo ZIP completo para cadena de custodia
    $sha256     = $null
    $fileLocked = $false
    $indexError = $null
 
    try {
        $sha256 = Get-FileHashSafe -InputPath $File.FullName
        if ($null -eq $sha256) { $fileLocked = $true }
    } catch {
        Invoke-Log -Level 'ERROR' -EventId 'ZIP_HASH_ERROR' -Message $_.Exception.Message -Details @{ Path = $File.FullName }
        $fileLocked = $true
    }
 
    # Leer el indice interno sin extraer nada
    $entries = @()
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $zip = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)
        try {
            foreach ($entry in $zip.Entries) {
                $entries += [pscustomobject]@{
                    ZipFullName          = $File.FullName
                    ZipName              = $File.Name
                    ZipSizeBytes         = $File.Length
                    ZipCreationTime      = $File.CreationTime
                    ZipLastWriteTime     = $File.LastWriteTime
                    ZipSHA256            = $sha256
                    ZipFileLocked        = $fileLocked
                    EntryFullName        = $entry.FullName
                    EntryName            = $entry.Name
                    EntryCompressedBytes = $entry.CompressedLength
                    EntryOriginalBytes   = $entry.Length
                    EntryLastWriteTime   = $entry.LastWriteTime.DateTime
                    EntryIsFolder        = ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\'))
                    IndexError           = $null
                }
            }
        } finally {
            $zip.Dispose()
        }
    } catch {
        $indexError = $_.Exception.Message
        Invoke-Log -Level 'WARN' -EventId 'ZIP_INDEX_ERROR' -Message $indexError -Details @{ Path = $File.FullName }
    }
 
    # Si no hay entradas (zip vacio o error de indice), igual retornamos una fila
    # representando el archivo con IndexError informativo
    if ($entries.Count -eq 0) {
        return @([pscustomobject]@{
            ZipFullName          = $File.FullName
            ZipName              = $File.Name
            ZipSizeBytes         = $File.Length
            ZipCreationTime      = $File.CreationTime
            ZipLastWriteTime     = $File.LastWriteTime
            ZipSHA256            = $sha256
            ZipFileLocked        = $fileLocked
            EntryFullName        = $null
            EntryName            = $null
            EntryCompressedBytes = $null
            EntryOriginalBytes   = $null
            EntryLastWriteTime   = $null
            EntryIsFolder        = $null
            IndexError           = if ($indexError) { $indexError } else { 'ZIP_VACIO' }
        })
    }
 
    return $entries
}
 
function Get-ZipInventory {
    <#
    Busca recursivamente archivos .zip bajo $RootPath y genera el inventario
    completo (metadata + hash + indice interno) llamando a Get-ZipFileEntry
    por cada archivo encontrado. Retorna una coleccion plana: una fila por
    entrada interna de cada zip, lo que permite filtrar en Excel/CSV directamente
    por nombre de archivo dentro del paquete.
    #>
    param([Parameter(Mandatory=$true)][string]$RootPath)
 
    Write-Host 'Funcion Get-ZipInventory ejecutada'
 
    $files = Get-ChildItem -LiteralPath $RootPath -Recurse -File -Filter '*.zip' -ErrorAction SilentlyContinue |
             Sort-Object FullName -Unique
 
    if (-not $files) { return @() }
 
    $allEntries = foreach ($file in $files) {
        Get-ZipFileEntry -File $file
    }
 
    return @($allEntries)
}
 
function Get-ForensicScore {
    param([Parameter(Mandatory=$true)][object]$Result)
    Write-Host 'Funcion Get-ForensicScore ejecutada'
 
    $score = 10
    if ($Result.USNJournal -eq 'ACTIVO') { $score += 15 }
    if ($Result.Sysmon -eq 'INSTALADO') { $score += 30 }
    if ($Result.NTFSAudit -eq 'CONFIGURADA') { $score += 25 }
    if ($Result.SecurityEventsFound -gt 0) { $score += 20 }
 
    $capability = if ($score -lt 30) { 'BAJA' } elseif ($score -lt 70) { 'MEDIA' } else { 'ALTA' }
    return [pscustomobject]@{ Score = $score; Capability = $capability }
}
 
function Get-ManagerSummary {
    param([Parameter(Mandatory=$true)][object]$Result)
    Write-Host 'Funcion Get-ManagerSummary ejecutada'
 
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('=================================================')
    $lines.Add('RESUMEN EJECUTIVO')
    $lines.Add('=================================================')
    $lines.Add('')
    foreach ($name in @('TargetPath', 'TargetType', 'Name', 'CreationTime', 'LastWriteTime', 'LastAccessTime', 'USNJournal', 'Sysmon', 'AuditPolicyState', 'NTFSAudit', 'SecurityEventsFound', 'ForensicScore', 'Capability')) {
        $lines.Add(('{0}: {1}' -f $name, $Result.$name))
    }
    if ($Result.TargetType -eq 'File') {
        $lines.Add("SHA256: $($Result.SHA256)")
        $lines.Add("Tamano bytes: $($Result.SizeBytes)")
    }
    if ($Result.TargetIsHyperV) {
        $lines.Add('')
        $lines.Add('ANALISIS HYPER-V')
        foreach ($name in @('HyperV_VMName', 'HyperV_VMState', 'HyperV_VhdType', 'HyperV_MaxSizeGB', 'HyperV_FileSizeGB', 'HyperV_ParentPath', 'HyperV_SnapshotCount', 'HyperV_AVHDXCount', 'HyperV_Exports', 'HyperV_MergeStart', 'HyperV_MergeEnd', 'HyperV_DynamicToFixedSignal', 'HyperV_TimelineFile')) {
            $lines.Add(('{0}: {1}' -f $name, $Result.$name))
        }
    }
    $lines.Add('')
    $lines.Add('INVENTARIO ZIP')
    $lines.Add(('ZipInventoryCount: {0}' -f $Result.ZipInventoryCount))
    $lines.Add(('ZipTotalEntries: {0}' -f $Result.ZipTotalEntries))
    $lines.Add('')
    $lines.Add('CONCLUSION')
    $lines.Add('Reporte de solo lectura basado en evidencia disponible al momento de ejecucion.')
    return ($lines -join [Environment]::NewLine)
}
 
function Export-Manifest {
    param(
        [Parameter(Mandatory=$true)][string[]]$Files,
        [Parameter(Mandatory=$true)][string]$ManifestPath
    )
    Write-Host 'Funcion Export-Manifest ejecutada'
 
    $manifest = foreach ($file in $Files) {
        if (Test-Path -LiteralPath $file) {
            [pscustomobject]@{
                Path = $file
                SHA256 = Get-FileHashSafe -InputPath $file
                Length = (Get-Item -LiteralPath $file).Length
                CreatedUtc = (Get-Item -LiteralPath $file).CreationTimeUtc
            }
        }
    }
    $manifest | Export-Csv -Path $ManifestPath -NoTypeInformation -Encoding UTF8
}
 
Start-SelfElevation
Initialize-ReportFolders -RootPath $BasePath
 
$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$TranscriptFile = Join-Path $BasePath ("logs\forensic_{0}.log" -f $TimeStamp)
Start-Transcript -Path $TranscriptFile -Force | Out-Null
 
# Initialize logging paths and run identifiers
$LogPath = if ([string]::IsNullOrWhiteSpace($LogPath)) { Join-Path $BasePath 'logs' } else { $LogPath }
$ndjsonPath = Join-Path $LogPath ("operation_{0}.ndjson" -f $TimeStamp)
$errorLogPath = Join-Path $LogPath ("errors_{0}.log" -f $TimeStamp)
$RunId = $TimeStamp
$global:StepId = 100
 
# Ensure log files exist
if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
if (-not (Test-Path -LiteralPath $ndjsonPath)) { New-Item -ItemType File -Path $ndjsonPath -Force | Out-Null }
if (-not (Test-Path -LiteralPath $errorLogPath)) { New-Item -ItemType File -Path $errorLogPath -Force | Out-Null }
 
Invoke-Log -Level 'INFO' -EventId 'RUN_START' -Message 'Run started' -Details @{ BasePath = $BasePath; TargetPath = $TargetPath }
 
# FIX#1: inicializar SIEMPRE las variables de rutas CSV opcionales antes del try principal.
# Bajo Set-StrictMode -Version 2.0, referenciar una variable nunca asignada lanza excepcion;
# como estas tres solo se asignaban dentro de un "if ($x.Count -gt 0) {...}", el caso comun
# (sin VHDs / sin logs de AzCopy / sin scripts DRP) hacia fallar el script completo al llegar
# a "Test-Path -LiteralPath $drpCsv" mas abajo.
$drpCsv = $null
$azCsv  = $null
$vhdCsv = $null
$zipCsv = $null
 
try {
    Clear-Host
    Write-Section -Title 'FORENSIC FILE INVESTIGATION V1.6.2'
    Write-Host 'Lectura segura. Evidencia minima suficiente. Impacto minimo en produccion.' -ForegroundColor DarkGray
 
    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        $TargetPath = Read-Host 'Ingrese ruta de archivo o carpeta'
    }
    if ([string]::IsNullOrWhiteSpace($TargetPath)) { throw 'No se ingreso una ruta.' }
 
    $item = Get-SafePathInfo -InputPath $TargetPath
    if (-not $item) { throw "Ruta no encontrada o no accesible: $TargetPath" }
 
    $targetType = if ($item.PSIsContainer) { 'Folder' } else { 'File' }
    $auditPolicy = Get-AuditPolicyText
    $auditPolicyState = if ($auditPolicy -match 'Sin auditor|No Auditing') { 'NO CONFIGURADA' } elseif ($auditPolicy -match 'Correcto y Error|Success and Failure') { 'CONFIGURADA' } elseif ($auditPolicy -match 'Correcto|Success') { 'PARCIAL' } else { 'DESCONOCIDA' }
 
    $result = [ordered]@{
        ExecutionDate = Get-Date; ComputerName = $env:COMPUTERNAME; User = $env:USERNAME; PowerShell = $PSVersionTable.PSVersion.ToString()
        TargetPath = $item.FullName; TargetType = $targetType; Name = $item.Name; FullName = $item.FullName
        CreationTime = $item.CreationTime; LastWriteTime = $item.LastWriteTime; LastAccessTime = $item.LastAccessTime
        SizeBytes = $null; SHA256 = $null; AuditPolicy = $auditPolicy; AuditPolicyState = $auditPolicyState
        NTFSAudit = 'NO DISPONIBLE'; USNJournal = Get-USNStatus; Sysmon = Get-SysmonStatus; SecurityEventsFound = 0
        TargetIsHyperV = $false; HyperV_DiskPath = $null; HyperV_VhdType = $null; HyperV_FileSizeGB = $null; HyperV_MaxSizeGB = $null
        HyperV_ParentPath = $null; HyperV_Fragmentation = $null; HyperV_VMName = $null; HyperV_VMState = $null; HyperV_VMCreationTime = $null
        HyperV_CheckpointType = $null; HyperV_SnapshotCount = $null; HyperV_Exports = 0; HyperV_MergeStart = 0; HyperV_MergeEnd = 0
        HyperV_Checkpoints = 0; HyperV_CheckpointDeletes = 0; HyperV_AVHDXCount = 0; HyperV_TimelineFile = $null; HyperV_Error = $null
        HyperV_DynamicToFixedSignal = $null; DRP_ScriptCount = 0; AzCopyLogCount = 0; HistoricalVhdCount = 0
        HyperVRelatedExportCount = 0; HyperVRelatedMergeCount = 0; FixedVhdCount = 0; DynamicVhdCount = 0
        ForensicScore = 0; Capability = 'DESCONOCIDA'; OutputFiles = @(); Notes = @()
        ZipInventoryCount = 0; ZipTotalEntries = 0
    }
 
    if ($targetType -eq 'File') {
        $result.SizeBytes = $item.Length
        $result.FileLocked = $false
        $hash = Get-FileHashSafe -InputPath $item.FullName
        if ($null -eq $hash) {
            $result.SHA256 = $null
            $result.FileLocked = $true
        } else {
            $result.SHA256 = $hash
        }
    }
 
    $auditEntries = Get-ReadableFileSystemAclAudit -InputPath $item.FullName
    $result.NTFSAudit = if (@($auditEntries).Count -gt 0) { 'CONFIGURADA' } else { 'NO CONFIGURADA' }
 
    $securityEvents = Get-LimitedSecurityEvents -InputPath $item.FullName -MaxEventsToScan $MaxSecurityEventsToScan -MaxMatches $MaxSecurityMatches
    $result.SecurityEventsFound = @($securityEvents).Count
 
    $hypervInfo = Get-TargetHyperVInfo -InputPath $item.FullName -Item $item -ReportRoot $BasePath -TimeStamp $TimeStamp -LookbackYears $EventLookbackYears
    foreach ($prop in $hypervInfo.PSObject.Properties) { $result[$prop.Name] = $prop.Value }
 
    $rootForInventory = if ($item.PSIsContainer) {
        $item.FullName
    } else {
        Split-Path -Path $item.FullName -Parent
    }
 
    # Usar únicamente la ruta proporcionada por el usuario
    $inventoryRoot = $rootForInventory
    $drpScripts = @(); $azcopyLogs = @(); $vhdInventory = @(); $zipInventory = @()
    if (Test-Path -LiteralPath $inventoryRoot) {
        $drpScripts   = Get-DRPScriptInventory -RootPath $inventoryRoot
        $vhdInventory = Get-VHDInventory        -RootPath $inventoryRoot
        $zipInventory = Get-ZipInventory        -RootPath $inventoryRoot
    }
 
 
    $azcopyLogs = Get-AzCopyLogInventory
 
    $result.DRP_ScriptCount    = @($drpScripts).Count
    $result.AzCopyLogCount     = @($azcopyLogs).Count
    $result.HistoricalVhdCount = @($vhdInventory).Count
    $result.FixedVhdCount      = @($vhdInventory | Where-Object { $_.StorageType -eq 'Fixed' }).Count
    $result.DynamicVhdCount    = @($vhdInventory | Where-Object { $_.StorageType -eq 'Dynamic' }).Count
    $result.ZipInventoryCount  = @($zipInventory | Select-Object ZipFullName -Unique).Count
    $result.ZipTotalEntries    = @($zipInventory | Where-Object { $null -ne $_.EntryFullName }).Count
 
    if ($result.DynamicVhdCount -gt 0 -and $result.FixedVhdCount -gt 0) { $result.HyperV_DynamicToFixedSignal = 'POSIBLE_CONVERSION_EN_ENTORNO' }
 
    $scoreObj = Get-ForensicScore -Result ([pscustomobject]$result)
    $result.ForensicScore = $scoreObj.Score
    $result.Capability = $scoreObj.Capability
 
    Write-Section -Title 'EXPORTACION DE EVIDENCIA'
    $txtFile = Join-Path $BasePath ("evidencia\evidencia_{0}.txt" -f $TimeStamp)
    $jsonFile = Join-Path $BasePath ("json\resultado_{0}.json" -f $TimeStamp)
    $csvFile = Join-Path $BasePath ("csv\eventos_{0}.csv" -f $TimeStamp)
    $summaryFile = Join-Path $BasePath ("resumen\resumen_ejecutivo_{0}.txt" -f $TimeStamp)
    $manifestFile = Join-Path $BasePath ("manifest\manifest_{0}.csv" -f $TimeStamp)
 
    $tech = [ordered]@{
        Result = [pscustomobject]$result
        SecurityEvents = $securityEvents
        AuditEntries = $auditEntries
        DRPScripts = $drpScripts | Select-Object FullName, Length, CreationTime, LastWriteTime
        AzCopyLogs = $azcopyLogs | Select-Object FullName, Length, CreationTime, LastWriteTime
        VHDInventory = $vhdInventory
        ZipInventory = $zipInventory
    }
    ($tech | ConvertTo-Json -Depth 8) | Out-File -FilePath $txtFile -Encoding UTF8
    Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'Evidence TXT created' -Details @{ Path = $txtFile }
 
    $result | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonFile -Encoding UTF8
    Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'Result JSON created' -Details @{ Path = $jsonFile }
 
    if (@($securityEvents).Count -gt 0) {
        $securityEvents | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'Security events CSV created' -Details @{ Path = $csvFile }
    }
    if (@($drpScripts).Count -gt 0) {
        $drpCsv = Join-Path $BasePath ("csv\drp_scripts_{0}.csv" -f $TimeStamp)
        $drpScripts | Select-Object FullName, Length, CreationTime, LastWriteTime | Export-Csv -Path $drpCsv -NoTypeInformation -Encoding UTF8
        Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'DRP scripts CSV created' -Details @{ Path = $drpCsv }
    }
    if (@($azcopyLogs).Count -gt 0) {
        $azCsv = Join-Path $BasePath ("csv\azcopy_logs_{0}.csv" -f $TimeStamp)
        $azcopyLogs | Select-Object FullName, Length, CreationTime, LastWriteTime | Export-Csv -Path $azCsv -NoTypeInformation -Encoding UTF8
        Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'AzCopy logs CSV created' -Details @{ Path = $azCsv }
    }
    if (@($vhdInventory).Count -gt 0) {
        $vhdCsv = Join-Path $BasePath ("csv\vhd_inventory_{0}.csv" -f $TimeStamp)
        $vhdInventory | Export-Csv -Path $vhdCsv -NoTypeInformation -Encoding UTF8
        Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'VHD inventory CSV created' -Details @{ Path = $vhdCsv }
    }
    if (@($zipInventory).Count -gt 0) {
        $zipCsv = Join-Path $BasePath ("csv\zip_inventory_{0}.csv" -f $TimeStamp)
        $zipInventory | Export-Csv -Path $zipCsv -NoTypeInformation -Encoding UTF8
        Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'ZIP inventory CSV created' -Details @{
            Path       = $zipCsv
            ZipCount   = $result.ZipInventoryCount
            EntryCount = $result.ZipTotalEntries
        }
    }
 
    Get-ManagerSummary -Result ([pscustomobject]$result) | Out-File -FilePath $summaryFile -Encoding UTF8
    Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'Summary created' -Details @{ Path = $summaryFile }
 
    # Build manifest file list and include logs.
    # FIX#1 (cont.): cada chequeo de $drpCsv/$azCsv/$vhdCsv ahora valida primero que la
    # variable tenga contenido (no $null) antes de llamar Test-Path, porque Test-Path
    # -LiteralPath $null tambien lanza error bajo StrictMode.
    $manifestFiles = @($txtFile, $jsonFile, $summaryFile, $TranscriptFile)
    if (Test-Path -LiteralPath $csvFile) { $manifestFiles += $csvFile }
    if ($vhdCsv -and (Test-Path -LiteralPath $vhdCsv)) { $manifestFiles += $vhdCsv }
    if ($zipCsv -and (Test-Path -LiteralPath $zipCsv)) { $manifestFiles += $zipCsv }
    if ($drpCsv -and (Test-Path -LiteralPath $drpCsv)) { $manifestFiles += $drpCsv }
    if ($azCsv -and (Test-Path -LiteralPath $azCsv)) { $manifestFiles += $azCsv }
    if ($result.HyperV_TimelineFile -and (Test-Path -LiteralPath $result.HyperV_TimelineFile)) { $manifestFiles += $result.HyperV_TimelineFile }
    if (Test-Path -LiteralPath $ndjsonPath) { $manifestFiles += $ndjsonPath }
    if (Test-Path -LiteralPath $errorLogPath) { $manifestFiles += $errorLogPath }
 
    Export-Manifest -Files $manifestFiles -ManifestPath $manifestFile
    Invoke-Log -Level 'INFO' -EventId 'FILE_CREATED' -Message 'Manifest created' -Details @{ Path = $manifestFile }
 
    Write-Section -Title 'RESULTADO'
    Write-Host 'Analisis completado.' -ForegroundColor Green
    Write-Host "Ruta: $($result.TargetPath)"
    Write-Host "Tipo: $($result.TargetType)"
    Write-Host "Capacidad Forense: $($result.ForensicScore)/100"
    Write-Host "Nivel: $($result.Capability)"
    Write-Host "Reportes generados en: $BasePath" -ForegroundColor Yellow
    Write-Host "Manifest: $manifestFile" -ForegroundColor Yellow
} catch {
    # FIX#2: bloque catch agregado. Antes, cualquier excepcion en el try principal
    # se propagaba sin diagnostico (no habia "catch", solo "finally"), terminando
    # el script de forma abrupta y sin dejar rastro en errors_*.log ni en consola.
    Write-Section -Title 'ERROR'
    Write-Host "El analisis no se completo correctamente." -ForegroundColor Red
    Write-Host "Detalle: $($_.Exception.Message)" -ForegroundColor Red
    try { Write-ErrorLog -Exception $_.Exception -Context 'MAIN' } catch { }
    try { Invoke-Log -Level 'ERROR' -EventId 'RUN_FAILED' -Message $_.Exception.Message -Details @{ TargetPath = $TargetPath } } catch { }
} finally {
    try { Stop-Transcript | Out-Null } catch { }
}
