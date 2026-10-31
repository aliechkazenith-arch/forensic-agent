<#
.SYNOPSIS
    ForensicOps AI - Headless Endpoint Triage & Artifact Collector v4.0
    Standards: RFC 3227 (Order of Volatility), NIST SP 800-86, ISO/IEC 27037
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$CaseId = "CASE-$(Get-Date -Format 'yyyyMMdd-HHmmss')",
    [Parameter(Mandatory = $false)]
    [string]$OutputRoot = "$env:SystemDrive\ForensicOps_Capsule",
    [Parameter(Mandatory = $false)]
    [string[]]$Modules = @("Volatile", "SystemInfo", "EventLogs", "Registry", "Execution", "Persistence", "UsersAndBrowsers", "FileArtifacts"),
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMemoryDump = $false,
    [Parameter(Mandatory = $false)]
    [string]$ToolsBinDir = "$PSScriptRootin"
)

$ErrorActionPreference = "Continue"
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Error "[FATAL] Administrator privileges are required for forensic acquisition."
    exit 1
}

$StartTimeUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$CapsuleDir   = Join-Path $OutputRoot $CaseId
$ArtifactsDir = Join-Path $CapsuleDir "artifacts"
New-Item -Path $ArtifactsDir -ItemType Directory -Force | Out-Null
$LogFile = Join-Path $CapsuleDir "collector_execution.log"
$CollectedArtifacts = [System.Collections.Generic.List[PSObject]]::new()

function Write-ForensicLog {
    param([string]$Message, [string]$Level = "INFO")
    $Stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $Line = "[$Stamp] [$Level] $Message"
    Write-Host $Line
    Add-Content -Path $LogFile -Value $Line -Encoding UTF8
}

function Register-Artifact {
    param([string]$FilePath, [string]$ArtifactType, [string]$OriginalSource, [string]$AcquisitionMethod)
    if (Test-Path $FilePath) {
        $FileInfo = Get-Item $FilePath
        $Sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
        $Sha512 = (Get-FileHash -Path $FilePath -Algorithm SHA512).Hash.ToLower()
        $RelPath = $FilePath.Substring($CapsuleDir.Length).TrimStart('', '/') -replace '\', '/'
        $CollectedArtifacts.Add([PSCustomObject]@{
            artifact_id        = [guid]::NewGuid().ToString()
            type               = $ArtifactType
            original_path      = $OriginalSource
            bundle_path        = $RelPath
            size_bytes         = $FileInfo.Length
            sha256             = $Sha256
            sha512             = $Sha512
            acquired_utc       = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            acquisition_method = $AcquisitionMethod
        })
    }
}
