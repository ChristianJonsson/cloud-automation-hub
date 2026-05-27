# ==============================================================================
# 01_EntraConnect_Config.ps1
# Purpose : Query Entra Connect server configuration
# Run on  : Entra Connect server (requires ADSync module)
# Output  : Console + <OutputPath>\EntraConnect_Config.txt
# Requires: 00_Config.ps1 (shared configuration)
# ==============================================================================

. "$PSScriptRoot\00_Config.ps1"

$outputFile = Join-Path $OutputPath 'EntraConnect_Config.txt'
$separator  = "`n" + ("=" * 60) + "`n"

$output = @()

# --- Global settings ----------------------------------------------------------
$output += $separator + "GLOBAL SETTINGS"
$output += Get-ADSyncGlobalSettings | Out-String

# --- AAD company features (sync method) ---------------------------------------
$output += $separator + "AAD COMPANY FEATURES (sync method, writeback)"
$output += Get-ADSyncAADCompanyFeature | Out-String

# --- Scheduler (is sync healthy?) ---------------------------------------------
$output += $separator + "SCHEDULER STATUS"
$output += Get-ADSyncScheduler | Out-String

# --- Connectors ---------------------------------------------------------------
$output += $separator + "CONNECTORS"
$output += Get-ADSyncConnector | Select-Object Name, Type, ConnectorTypeName | Out-String

# --- AD connector partition (domain scope) ------------------------------------
$output += $separator + "AD CONNECTOR PARTITIONS"
$connector = Get-ADSyncConnector | Where-Object {$_.ConnectorTypeName -eq $ADConnectorTypeName}
$output += $connector.Partitions | Out-String

# --- Write output -------------------------------------------------------------
$output | Out-File $outputFile -Encoding UTF8
Write-Host "Config written to $outputFile" -ForegroundColor Green

# --- Summary to console -------------------------------------------------------
Write-Host "`nKey findings:" -ForegroundColor Cyan
$features = Get-ADSyncAADCompanyFeature
Write-Host "  PasswordHashSync : $($features.PasswordHashSync)"
Write-Host "  StagingMode      : $((Get-ADSyncScheduler).StagingModeEnabled)"
Write-Host "  SyncEnabled      : $((Get-ADSyncScheduler).SyncCycleEnabled)"
Write-Host "  LastSyncRun      : $((Get-ADSyncScheduler).LastSyncRunTime)"
