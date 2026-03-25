# -----------------------------
# CONFIGURE LOGGING
# -----------------------------
$script:DefaultLogDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) 'Logs'
$script:LogFile = Join-Path $script:DefaultLogDirectory 'UserUpdate.log'

function Get-DefaultUserUpdateLogPath {
    param(
        [switch]$PreviewMode,
        [string]$BaseDirectory = '.'
    )

    $fileName = if ($PreviewMode) { 'UserUpdate.preview.log' } else { 'UserUpdate.log' }
    return Join-Path $BaseDirectory (Join-Path 'Logs' $fileName)
}

function Get-DefaultUserUpdatePreflightArtifactPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Timestamp,

        [switch]$PreviewMode,
        [string]$BaseDirectory = '.'
    )

    if ($PreviewMode) {
        $fileName = "Preflight.preview-$Timestamp.json"
        return Join-Path $BaseDirectory (Join-Path 'Reports\UserTypeNullRemediation\Reports_Preflight_Preview' $fileName)
    }
    else {
        $fileName = "Preflight-$Timestamp.json"
        return Join-Path $BaseDirectory (Join-Path 'Reports\UserTypeNullRemediation\Reports_Preflight' $fileName)
    }
}

function Set-LogFilePath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        $script:LogFile = $Path
        return
    }

    # Resolve relative paths from the caller's current location.
    $script:LogFile = Join-Path (Get-Location) $Path
}

function Write-Log {
    param(
        [string]$Message,
        [switch]$NoConsole,
        [switch]$NoFile
    )

    # Timestamped log entry
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "[$timestamp] $Message"

    if (-not $NoConsole) {
        # Write to console
        Write-Host $Message
    }

    if (-not $NoFile) {
        # Write to file
        $logDirectory = Split-Path -Path $script:LogFile -Parent
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -ItemType Directory -Path $logDirectory -Force -WhatIf:$false -Confirm:$false | Out-Null
        }

        Add-Content -Path $script:LogFile -Value $entry -WhatIf:$false -Confirm:$false
    }
}

Export-ModuleMember -Function Get-DefaultUserUpdateLogPath, Get-DefaultUserUpdatePreflightArtifactPath, Write-Log, Set-LogFilePath
