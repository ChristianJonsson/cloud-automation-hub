# -----------------------------
# CONFIGURE LOGGING
# -----------------------------
$script:DefaultLogDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) 'Logs'
$script:LogFile = Join-Path $script:DefaultLogDirectory 'UserUpdate.log'

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
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
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

Export-ModuleMember -Function Write-Log, Set-LogFilePath